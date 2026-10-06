# etc/proteus/bin/ui_logic.py
"""Pure logic for the proteus web UI. No sockets, no root, no side effects.

Mirrors the dispatcher.py / dispatcher_logic.py split: everything the daemon
or broker decides lives here so pytest can reach it.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
from dataclasses import asdict, dataclass

import ledger
import trusted

_log = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 600_000
SESSION_TTL_S = 24 * 3600


def hash_passphrase(passphrase: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations)
    return f"pbkdf2-sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_passphrase(passphrase: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, dk_hex = stored.strip().split("$")
        if scheme != "pbkdf2-sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError, TypeError):
        return False


def mint_session(key: bytes, now: float | None = None) -> str:
    now = time.time() if now is None else now
    payload = f"{int(now) + SESSION_TTL_S}.{os.urandom(8).hex()}"
    sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_session(key: bytes, token: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    try:
        expiry_s, nonce, sig = token.split(".")
        expect = hmac.new(key, f"{expiry_s}.{nonce}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return False
        return int(expiry_s) > now
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Knob:
    key: str
    group: str          # rotation | gates | proton-dns | network | advanced | udm
    kind: str           # int | float | str | iplist
    lo: float | None = None
    hi: float | None = None
    pattern: str | None = None
    applies: str = "next cycle"
    kick: str | None = None      # systemd unit the broker restarts after set
    label: str = ""              # human-readable name shown in the UI
    unit: str = ""               # e.g. "Mbps", "s", "ms"
    default: str = ""            # effective value when not overridden
    help: str = ""               # one-line plain-English explanation
    choices: tuple = ()          # if set, value must be one of these (UI: dropdown)


# group -> human heading, in display order. "udm" is deliberately absent: its one
# knob is drawn by the page's own trusted-egress pane, beside the pairing button
# it affects, rather than in the generic grouped list.
KNOB_GROUPS = [
    ("rotation", "Rotation"),
    ("gates", "Quality gates"),
    ("proton-dns", "Exit & DNS"),
    ("network", "Client network"),
    ("advanced", "Advanced tuning"),
]

KNOBS = {k.key: k for k in [
    Knob("PROTEUS_ROT_THRESHOLD", "rotation", "int", 1, 20, applies="next warmup pass",
         label="Auto-rotate after N failures", unit="fails", default="5",
         help="Consecutive failed health checks before a slot rotates itself to a fresh server."),
    Knob("PROTEUS_ROT_COOLDOWN", "rotation", "int", 60, 86400, applies="next warmup pass",
         label="Min time between auto-rotations", unit="s", default="300",
         help="A slot won't health-rotate again until this many seconds have passed."),
    Knob("PROTEUS_STREAMING_MIN_MBPS", "gates", "int", 1, 500, applies="next rotation",
         label="Minimum throughput to accept a server", unit="Mbps", default="25",
         help="A newly-minted server must sustain at least this speed or it's rejected."),
    Knob("PROTEUS_DEGRADED_AFTER", "gates", "int", 1, 10, applies="next warmup pass",
         label="Mark degraded after N bad passes", unit="fails", default="2",
         help="Failed warmup passes before a slot is flagged degraded."),
    Knob("PROTEUS_REP_MIN_MANDATORY_PASS", "gates", "int", 0, 5, applies="next rotation",
         label="Reputation checks that must pass", unit="", default="4",
         help="A new server must clear at least this many mandatory reputation probes."),
    Knob("PROTEUS_REP_MAX_MANDATORY_ERRORS", "gates", "int", 0, 5, applies="next rotation",
         label="Reputation errors tolerated", unit="", default="1",
         help="Maximum failed mandatory reputation probes before a server is rejected."),
    Knob("PROTEUS_PLAYABILITY_CHECK", "gates", "str", choices=("on", "off"),
         applies="next warmup pass",
         label="Keep checking streaming after go-live", unit="", default="on",
         help="A new server is always tested for video playback before it goes live, "
              "but an exit can get blocked later. With this on, live servers are "
              "re-tested about every 15 minutes and swapped out if video stops "
              "working — otherwise they keep serving until their next daily rotation."),
    Knob("PROTEUS_CF_TIER", "gates", "str", choices=("mandatory", "advisory"),
         applies="next rotation and next live check", kick="proteus-dispatcher.service",
         label="Require cf ok", unit="", default="mandatory",
         help="mandatory (default): a tunnel must be cf ok. A candidate that fails a canary "
              "is never promoted. A flagged tunnel gets no new clients and is replaced. "
              "advisory: the canaries still run and the badges still show, but nothing acts on them."),
    Knob("PROTEUS_LIVECHECK", "gates", "str", choices=("on", "off"), applies="next warmup pass",
         label="Keep checking canaries after go-live", unit="", default="on",
         help="Re-test live exits against the canaries and your mandatory checks about "
              "every 15 minutes. With Require cf ok set to mandatory, a tunnel that fails a canary gets no new "
              "clients at once, is re-checked at the next turn (about 4 minutes) and is rotated "
              "if it fails again."),
    Knob("PROTEUS_LIVECHECK_FAILS", "gates", "int", 1, 10, applies="next warmup pass",
         label="Live-check failures before rotating", unit="fails", default="2",
         help="Consecutive failures of one check before the exit is rotated. In advisory a "
              "canary never rotates an exit. With Require cf ok set to mandatory, a flagged tunnel "
              "is re-checked at the next turn, so two failures take about 4 minutes."),
    Knob("PROTEUS_LIVECHECK_ROT_COOLDOWN", "gates", "int", 300, 86400, applies="next warmup pass",
         label="Min time between live-check rotations", unit="s", default="3600",
         help="Per exit, shared with the streaming re-check."),
    Knob("PROTEUS_PROTON_COUNTRY", "proton-dns", "str", pattern=r"^[A-Z]{2}$", applies="next rotation",
         label="Exit country", unit="", default="US",
         help="Two-letter country code for newly-minted Proton exit servers (e.g. US, CH, NL)."),
    Knob("PROTEUS_DNS_LATENCY_THRESHOLD_MS", "proton-dns", "int", 20, 2000, applies="next DNS check",
         label="Rotate DNS above latency", unit="ms", default="150",
         help="Rotate the dedicated DNS tunnel if resolver latency climbs past this. "
              "The resolver now sits inside the tunnel (~12ms typical, ~70ms on the "
              "worst exit), so this measures tunnel round-trip, not internet quality."),
    Knob("PROTEUS_DNS_ROTATE_COOLDOWN", "proton-dns", "int", 300, 86400, applies="next DNS check",
         label="Min time between DNS rotations", unit="s", default="3600",
         help="The DNS tunnel won't rotate again until this many seconds have passed."),
    Knob("PROTEUS_NETSHIELD_LEVEL", "proton-dns", "int", 0, 2, applies="next fresh DNS mint",
         label="Ad & tracker blocking (NetShield)", unit="", default="2",
         help="Proton NetShield: 0 off, 1 malware only, 2 malware + ads + trackers. "
              "The gateway resolver forwards to Proton's in-tunnel DNS, so this filters "
              "every client lookup network-wide. Baked into the tunnel's certificate at "
              "key registration, so it takes a fresh DNS-tunnel mint to change."),
    Knob("PROTEUS_CLIENT_ISOLATION", "network", "str", choices=("open", "isolated"),
         applies="immediately", kick="proteus-client-isolation.service",
         label="Client network isolation", unit="", default="open",
         help="open: clients can reach other private LAN hosts through this gateway. "
              "isolated: clients reach only the public internet via the VPN tunnels; "
              "traffic to LAN/private IPs is blocked. DNS and this control panel stay "
              "reachable either way."),
    Knob("PROTEUS_CLIENT_ISOLATION_FAILSAFE", "network", "str", choices=("open", "closed"),
         applies="immediately", kick="proteus-client-isolation.service",
         label="If isolation can't be applied", unit="", default="open",
         help="What the firewall does during boot, before the isolation service runs, "
              "and if that service ever fails. open: fall back to allowing LAN access "
              "(the behaviour before isolation existed, no lockout risk). closed: fall "
              "back to blocking it, so a failure can't silently expose your LAN. "
              "Only bites when isolation is on — with isolation off, both behave the same."),
    Knob("PROTEUS_UDM_DNS", "udm", "iplist", applies="the next pairing you generate",
         label="DNS server for trusted hosts", unit="", default="",
         help="The resolver the UDM tunnel hands to hosts routed through it. Use your own "
              "LAN resolver — the ad-blocking one those hosts already use — not a public "
              "or in-tunnel one: trusted hosts send their traffic out through the rotating "
              "exits but must keep resolving internal names and keep their ad-blocking. "
              "One IP address, or several separated by commas. There is no default, and "
              "UniFi will not save a VPN Client without it."),
    Knob("PROTEUS_SCORE_LAT_COEF", "advanced", "float", 0.0, 10.0, applies="next warmup pass",
         label="Latency penalty weight", unit="/ms", default="0.1",
         help="How hard median latency drags a slot's health score down."),
    Knob("PROTEUS_SCORE_JIT_COEF", "advanced", "float", 0.0, 10.0, applies="next warmup pass",
         label="Jitter penalty weight", unit="/ms", default="0.5",
         help="How hard latency jitter drags a slot's health score down."),
    Knob("PROTEUS_SCORE_TP_WEIGHT", "advanced", "float", 0.0, 10.0, applies="next warmup pass",
         label="Throughput bonus weight", unit="", default="0.3",
         help="How much measured throughput lifts a slot's health score."),
    Knob("PROTEUS_SPREAD_BAND", "advanced", "float", 0.0, 500.0,
         applies="immediately", kick="proteus-dispatcher.service",
         label="Load-spread score window", unit="", default="40",
         help="Clients are spread across all slots whose score is within this window of the best."),
    Knob("PROTEUS_PIN_TTL_S", "advanced", "int", 300, 86400,
         applies="immediately", kick="proteus-dispatcher.service",
         label="Client stickiness", unit="s", default="21600",
         help="How long a client stays pinned to the same slot before it can be re-spread."),
    Knob("PROTEUS_CF_QUARANTINE_MIN_EXITS", "advanced", "int", 2, 50, applies="next check",
         label="Exits before a canary is called site-wide", unit="exits", default="8",
         help="A canary that no exit has passed across this many distinct exits in 24h is "
              "quarantined: still probed, but it no longer rejects exits or triggers rotations."),
    Knob("PROTEUS_MINT_EXPLORE", "advanced", "float", 0.0, 1.0, applies="next rotation",
         label="Exploration rate", unit="", default="0.5",
         help="Chance that an odd-numbered rotation attempt tries a server with no history "
              "once the known-good pool is at target. Below target, exploration is certain."),
    Knob("PROTEUS_MINT_POOL_TARGET", "advanced", "int", 1, 200, applies="next rotation",
         label="Known-good exit pool target", unit="exits", default="20",
         help="How many distinct exits meeting the standard the ledger should hold. "
              "Below this, rotations keep exploring new servers."),
    Knob("PROTEUS_MINT_REUSE_MIN_S", "advanced", "int", 0, 2592000, applies="next rotation",
         label="Min time before reusing an exit IP", unit="s", default="604800",
         help="Keeps the fleet from cycling through the same few exits. Relaxed only when "
              "every eligible exit was used within the window."),
]}

# Belt-and-braces: overlay values stay shell-inert. `:` and `,` are here for an
# IPv6 address and for a comma-separated DNS list, and both are inert in an
# unquoted `KEY=value` line. A SPACE is not, and must never be added: proteus.env
# and its overlay are SOURCED by every script on the box, so `KEY=a b` would run
# `b` as a command with `KEY=a` in its environment.
_VALUE_RE = re.compile(r"[A-Za-z0-9._:,-]+")
# Plain decimal forms only — bash `(( ... ))` and awk choke on Python-only
# literals like "5_0" (int with underscore) or "1e1" (float exponent form).
_INT_RE = re.compile(r"\d+")
_FLOAT_RE = re.compile(r"\d+(\.\d+)?")


def validate_knob(key: str, value: str) -> tuple[bool, str]:
    knob = KNOBS.get(key)
    if knob is None:
        return False, f"unknown knob {key!r}"
    if not _VALUE_RE.fullmatch(value):
        return False, "value contains disallowed characters"
    if knob.choices:
        if value not in knob.choices:
            return False, f"must be one of: {', '.join(knob.choices)}"
    elif knob.kind in ("int", "float"):
        literal_re = _INT_RE if knob.kind == "int" else _FLOAT_RE
        if not literal_re.fullmatch(value):
            return False, f"not a plain decimal {knob.kind}"
        n = int(value) if knob.kind == "int" else float(value)
        if not (knob.lo <= n <= knob.hi):
            return False, f"out of range {knob.lo}..{knob.hi}"
    elif knob.kind == "iplist":
        # The same parser the pairing itself uses, so a value the UI accepts can
        # never be one that fails at pairing time. Note _VALUE_RE has already
        # ruled out whitespace, so what is stored is comma-joined with no spaces
        # and stays safe for the shell that sources the overlay.
        try:
            trusted.parse_dns_list(value)
        except ValueError as e:
            return False, f"{key} {e}"
    elif knob.pattern and not re.fullmatch(knob.pattern, value):
        return False, "bad format"
    return True, ""


def knob_schema() -> list[dict]:
    return [asdict(k) for k in KNOBS.values()]


HEALTH_STALE_AFTER_S = 30  # 3x the 10 s warmup interval


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


class Lockout:
    """Login-failure throttle. Sliding window, in-memory only.

    TWO ceilings, because a per-source one alone counts nothing an attacker
    can't choose. The source address IS attacker-controlled: anyone on the
    client VLAN can cycle through the /24 and collect a fresh per-source budget
    for every address, so a per-source-only limit doesn't cap the attack, it
    multiplies by the size of the subnet (5/min becomes ~1270/min on a /24).
    The GLOBAL ceiling is the one that actually bounds a distributed guess.

    The global limit is set far above any plausible human typo rate, because
    tripping it locks *everyone* out of the UI until the window drains — that
    is a deliberate trade (a stranger can deny you the panel) and it is why it
    isn't set low. SSH is unaffected, and `systemctl restart proteus-ui` clears
    it immediately since none of this is persisted.

    Shared across request-handler threads under ThreadingHTTPServer, so every
    read-modify-write is guarded (same pattern as dispatcher.py's _instances).
    """

    def __init__(self, limit: int = 5, window_s: int = 60,
                 global_limit: int = 60, max_sources: int = 4096):
        self.limit, self.window_s = limit, window_s
        self.global_limit, self.max_sources = global_limit, max_sources
        self._fails: dict[str, list[float]] = {}
        self._global: list[float] = []
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        """Caller must hold the lock. Drops aged entries everywhere.

        Without this, one dict key per spoofed source accumulates forever — a
        slow memory exhaustion that costs the attacker nothing.
        """
        cutoff = now - self.window_s
        self._global = [t for t in self._global if t > cutoff]
        stale = [s for s, ts in self._fails.items() if not ts or ts[-1] <= cutoff]
        for s in stale:
            del self._fails[s]
        # Hard bound even if a flood outpaces expiry: evict the least-recently
        # active sources. They lose their individual budget, but the global
        # ceiling still covers them, so this cannot be used to wash out a lock.
        if len(self._fails) > self.max_sources:
            for s, _ in sorted(self._fails.items(), key=lambda kv: kv[1][-1])[
                    :len(self._fails) - self.max_sources]:
                del self._fails[s]

    def record_failure(self, src: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self._fails.setdefault(src, []).append(now)
            self._global.append(now)
            self._prune(now)

    def locked(self, src: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            if len(self._global) >= self.global_limit:
                return True
            return len([t for t in self._fails.get(src, []) if now - t < self.window_s]) >= self.limit

    def clear(self, src: str) -> None:
        """Successful login clears that source. Deliberately does NOT clear the
        global counter — a valid login from one address says nothing about the
        distributed guessing that tripped it."""
        with self._lock:
            self._fails.pop(src, None)


def slot_summary(name: str, state: dict, health: dict,
                 next_rotation: int | None, rotating: bool, now: float,
                 cf: dict | None = None) -> dict:
    try:
        updated = float(health.get("SCORE_UPDATED_AT") or 0)
    except ValueError:
        updated = 0.0
    cf = cf or {}
    cf_clean = {"yes": True, "no": False}.get(cf.get("CF_CLEAN", ""), None)
    try:
        cf_at: int | None = int(cf.get("AT", ""))
    except ValueError:
        cf_at = None
    return {
        "name": name,
        "status": "down" if not state else health.get("STATUS", "unknown"),
        "logical": state.get("LOGICAL_NAME"),
        "exit_country": state.get("EXIT_COUNTRY"),
        "exit_ip": state.get("EXIT_IP"),
        "physical_domain": state.get("PHYSICAL_DOMAIN"),
        "endpoint_ip": state.get("WG_ENDPOINT_IP"),
        "up_since": state.get("UP_TIME"),
        "minted_at": state.get("MINTED_AT"),
        "health": {
            "score": health.get("COMPOSITE_SCORE"),
            "latency_ms": health.get("LATENCY_MEDIAN_MS"),
            "jitter_ms": health.get("LATENCY_MAD_MS"),
            "throughput_mbps": health.get("THROUGHPUT_MBPS"),
            "fail_streak": health.get("FAIL_STREAK"),
            "stale": bool(health) and (now - updated > HEALTH_STALE_AFTER_S),
        },
        "next_rotation": next_rotation,
        "rotating": rotating,
        "cf": {"clean": cf_clean,
               "failing": [h for h in (cf.get("FAILING") or "").split(",") if h],
               "at": cf_at},
    }


# --- egress health checks (custom reputation-probe sites) ----------------------
# BUILTIN_CHECKS mirrors reputation-probe.sh's mandatory/advisory arrays for
# read-only display. Keep in sync with that script if its list changes.
BUILTIN_CHECKS = [
    {"url": "https://api.github.com/zen", "tier": "mandatory"},
    {"url": "https://www.google.com/generate_204", "tier": "mandatory"},
    {"url": "https://duckduckgo.com/?q=test&format=json", "tier": "mandatory"},
    {"url": "https://www.cloudflare.com/", "tier": "mandatory"},
    {"url": "https://www.youtube.com/watch?v=jNQXAC9IVRw", "tier": "mandatory",
     "body": '"playabilityStatus":{"status":"OK"'},
    {"url": "https://www.reddit.com/.json", "tier": "advisory"},
]
MAX_CUSTOM_CHECKS = 15
MAX_CHECK_BODY = 120
CHECK_TIERS = ("mandatory", "advisory")
# http(s) + host/path/query charset only. Deliberately excludes shell
# metacharacters (; & $ ' ( ) space backtick newline ...) so a URL can never be
# reinterpreted by a shell. Absolute length is enforced separately.
_CHECK_URL_RE = re.compile(r"^https?://[A-Za-z0-9._~:/?#@&=%-]+$")
# The body assertion is matched with `grep -F -e`, i.e. as a LITERAL substring
# passed as a single argv element — it is never a regex and never reaches a
# shell, so it can afford a much wider charset than the URL (a useful assertion
# like '"playabilityStatus":{"status":"OK"' needs quotes and braces).
# What it must NOT contain is a tab, newline or carriage return: checks.json is
# handed to reputation-probe.sh as TSV, and any of those would split the record
# and shift the URL/tier columns. Restricted to printable ASCII so a stray
# control byte can't corrupt the file either.
_CHECK_BODY_RE = re.compile(r"^[\x20-\x7e]+$")


def validate_checks(obj) -> tuple[bool, str, list]:
    """Validate a {"checks":[{"url","tier","body"?},...]} object. Whole-list: any
    bad entry rejects the entire list. Returns (ok, reason, normalized_list)."""
    if not isinstance(obj, dict) or not isinstance(obj.get("checks"), list):
        return False, 'expected {"checks": [...]}', []
    checks = obj["checks"]
    if len(checks) > MAX_CUSTOM_CHECKS:
        return False, f"too many checks (max {MAX_CUSTOM_CHECKS})", []
    clean = []
    for c in checks:
        if not isinstance(c, dict):
            return False, "each check must be an object", []
        url, tier = str(c.get("url", "")), str(c.get("tier", ""))
        if len(url) > 200 or url.startswith("-") or not _CHECK_URL_RE.fullmatch(url):
            return False, f"invalid url: {url[:60]!r}", []
        if tier not in CHECK_TIERS:
            return False, f"invalid tier: {tier!r}", []
        entry = {"url": url, "tier": tier}
        # Optional; absent/empty means "status code only", the old behaviour.
        body = c.get("body")
        if body not in (None, ""):
            body = str(body)
            if len(body) > MAX_CHECK_BODY:
                return False, f"body assertion too long (max {MAX_CHECK_BODY})", []
            if not _CHECK_BODY_RE.fullmatch(body):
                return False, "body assertion must be printable ASCII, no tabs/newlines", []
            entry["body"] = body
        clean.append(entry)
    return True, "", clean


def parse_checks(text: str) -> list:
    """Read a checks.json string. Rejects the whole list if any entry is
    malformed (returns []). Never raises."""
    try:
        ok, _, clean = validate_checks(json.loads(text or "{}"))
        return clean if ok else []
    except (ValueError, TypeError):
        return []


# --- Cloudflare canaries ---------------------------------------------------------
MAX_CANARIES = ledger.MAX_CANARIES


def validate_canaries(obj) -> tuple[bool, str, list]:
    """Validate {"canaries":[{"url"},...]}: 1..MAX_CANARIES https URLs matching
    _CHECK_URL_RE, no duplicates. Whole-list: any bad entry rejects the list."""
    if not isinstance(obj, dict) or not isinstance(obj.get("canaries"), list):
        return False, 'expected {"canaries": [...]}', []
    items = obj["canaries"]
    if not items:
        return False, "at least one canary is required", []
    if len(items) > MAX_CANARIES:
        return False, f"too many canaries (max {MAX_CANARIES})", []
    clean, seen = [], set()
    for c in items:
        if not isinstance(c, dict):
            return False, "each canary must be an object", []
        url = str(c.get("url", ""))
        # "@" is inside _CHECK_URL_RE's charset, but userinfo makes the host the
        # UI shows (everything before the @) different from the host curl talks
        # to, so a canary could be listed as one site and probed on another.
        # ledger.canary_urls drops these too; both gates exist because either
        # can be the one an operator edits through.
        if (len(url) > 200 or not url.startswith("https://") or "@" in url
                or url.startswith("-") or not _CHECK_URL_RE.fullmatch(url)):
            return False, f"invalid url: {url[:60]!r}", []
        if url in seen:
            return False, f"duplicate url: {url[:60]!r}", []
        seen.add(url)
        clean.append({"url": url})
    return True, "", clean


def parse_canaries(text: str) -> list[str]:
    """URLs from a canaries.json string, or the shipped basket when the text is
    empty, malformed or fails validation. Never raises.

    All-or-nothing, matching the broker's set-canaries validation: one bad entry
    discards the whole list. The daemon does NOT use this to decide what to
    display — it calls ledger.canary_urls(), which drops bad entries, truncates
    to MAX_CANARIES and dedupes, so the panel shows exactly the basket the
    probes run."""
    try:
        ok, _, clean = validate_canaries(json.loads(text or "{}"))
    except (ValueError, TypeError):
        return list(ledger.DEFAULT_CANARIES)
    return [c["url"] for c in clean] if ok else list(ledger.DEFAULT_CANARIES)


def cf_tier(value: str | None) -> str:
    """The PROTEUS_CF_TIER rule shared with checklib.sh (${PROTEUS_CF_TIER:-mandatory}):
    unset or empty is mandatory, anything but "mandatory" is advisory."""
    return "mandatory" if (value or "mandatory") == "mandatory" else "advisory"


def builtin_checks(cf_tier: str, canary_urls: list[str]) -> list[dict]:
    """BUILTIN_CHECKS plus the canaries at the configured tier, for display."""
    return BUILTIN_CHECKS + [{"url": u, "tier": cf_tier, "canary": True} for u in canary_urls]


def ledger_view(records_path: str, canaries_path: str, now: int, slots: int,
                target: int, min_exits: int, tier: str = "mandatory") -> dict:
    """Ledger rollup for /api/status: {"standard","canaries","pool"}.

    In advisory the canaries gate nothing, so the standard numbers (size,
    attainable, passing exits) and the known-good pool use an empty standard,
    as proteus-cf-report and proton-mint do. Canary stats and quarantine
    still use the full basket.

    The ledger is append-only JSONL written by the probes, not by this daemon,
    so a record that is valid JSON but the wrong shape ({"canaries":"boom"},
    a numeric exit_ip) reaches ledger.status and raises. That must degrade the
    ledger panel, not 500 the whole status endpoint and blank the operator's
    only view of the gateway — every one of these sections is optional in the
    page. Empty sections render as "no data".
    """
    try:
        hosts = [ledger.host_of(u) for u in ledger.canary_urls(canaries_path)]
        records = ledger.load(records_path)
        st = ledger.status(records, hosts, now, slots, target, min_exits)
        if cf_tier(tier) != "mandatory":
            st["standard"].update({
                "size": 0,
                "attainable": ledger.attainable(records, [], now, slots),
                "passing_exits_24h": len(ledger.pool(records, [], now, ttl_s=86400)),
            })
            st["pool"]["known_good"] = len(ledger.pool(records, [], now))
        return st
    except Exception as e:  # noqa: BLE001 — the panel outlives a bad ledger line
        _log.warning("ledger unreadable (%s): %s", records_path, e)
        return {"standard": {}, "canaries": [], "pool": {}}


# --- trusted-VLAN egress ---------------------------------------------------------
def trusted_summary(cidrs: list[str], up: bool, health_dir: str, pins) -> dict:
    """The status block for trusted egress.

    `pinned` counts current pins whose source falls inside a trusted range,
    which is the one number that answers "is any of this actually being used".
    Everything here degrades to a null or a zero rather than raising: a status
    poll must never fail because a status file is being rewritten underneath it.
    The UI daemon is unprivileged and cannot read the peer key or ask WireGuard
    anything, so this is assembled from what it can see — the operator's list,
    the interface's presence, and the age file slot-warmup writes as root.
    """
    age = None
    try:
        with open(f"{health_dir}/.udm-tunnel") as f:
            for line in f:
                if line.startswith("HANDSHAKE_AGE_S="):
                    # An interface that has never completed a handshake gets an
                    # empty value, which int() rejects — that is "up but not yet
                    # heard from", the same null as a missing file.
                    age = int(line.split("=", 1)[1].strip())
                    break
    except (OSError, ValueError):
        age = None
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.IPv4Network(c))
        except ValueError:
            continue
    pinned = 0
    # No trusted ranges is the shipped-dark default, and every pin would then be
    # parsed into an IPv4Address only to be tested against nothing — a quarter of
    # a millisecond of the status poll, every poll, for a guaranteed zero.
    #
    # The pin list comes from the dispatcher's status JSON, which this daemon
    # only reads: anything but a list of objects is a file being rewritten or a
    # file that is wrong, and neither may cost the operator the whole page.
    for p in pins if (nets and isinstance(pins, list)) else []:
        try:
            ip = ipaddress.IPv4Address(str(p.get("ip", "")))
        except (ValueError, AttributeError):
            continue
        if any(ip in n for n in nets):
            pinned += 1
    return {"cidrs": list(cidrs), "tunnel_up": bool(up),
            "handshake_age_s": age, "pinned": pinned}
