# etc/proteus/bin/ui_logic.py
"""Pure logic for the proteus web UI. No sockets, no root, no side effects.

Mirrors the dispatcher.py / dispatcher_logic.py split: everything the daemon
or broker decides lives here so pytest can reach it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass

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
    group: str          # rotation | gates | proton-dns | network | advanced
    kind: str           # int | float | str
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


# group -> human heading, in display order
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
]}

_VALUE_RE = re.compile(r"[A-Za-z0-9._-]+")   # belt-and-braces: overlay values stay shell-inert
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
                 next_rotation: int | None, rotating: bool, now: float) -> dict:
    try:
        updated = float(health.get("SCORE_UPDATED_AT") or 0)
    except ValueError:
        updated = 0.0
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
