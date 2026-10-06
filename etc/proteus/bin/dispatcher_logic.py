"""Pure logic for the multi-VPN dispatcher.

This module has NO netfilter or scapy imports — everything here is
unit-testable with stdlib alone. The integration glue lives in
dispatcher.py, which imports from here.
"""

from __future__ import annotations

import glob
import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from typing import Iterable

log = logging.getLogger("dispatcher")


def is_live_slot(name: str) -> bool:
    """True for a proton-<N> slot, the only kind that takes client traffic.
    Specialized tunnels (e.g. dns-6) carry their own dedicated traffic via
    per-uid routing rules, and a staging copy (proton-N-s) is a rotation's
    candidate, not yet a slot."""
    return re.fullmatch(r"proton-\d+", name) is not None


# What load_state_files last warned about, by path. The dispatcher's janitor
# reads the state dir every pass (once a minute), so a state file that stays
# broken would otherwise repeat its warning every minute for as long as it
# sits there. A path warns again once its problem changes, or after a read
# that found it fine (or gone) in between.
_state_file_warned: dict[str, str] = {}


def load_state_files(state_dir: str) -> list[tuple[str, int]]:
    """(INSTANCE, FWMARK) from every readable state file in state_dir, whatever
    the instance: live slots, staging copies and the DNS tunnel alike.

    load_instances narrows this to the slots that take client traffic. The
    janitor needs the whole list as well, because any instance that is up
    claims its mark, not only the ones the dispatcher hands out.
    """
    global _state_file_warned
    entries: list[tuple[str, int]] = []
    problems: dict[str, str] = {}
    for path in sorted(glob.glob(f"{state_dir}/*.state")):
        kv: dict[str, str] = {}
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        kv[k] = v
        except OSError as e:
            problems[path] = f"could not read {path}: {e}"
            continue
        name = kv.get("INSTANCE")
        mark = kv.get("FWMARK")
        if name and mark:
            try:
                entries.append((name, int(mark, 16)))
            except ValueError:
                problems[path] = f"bad FWMARK in {path}: {mark!r}"
    for path, msg in problems.items():
        if _state_file_warned.get(path) != msg:
            log.warning("%s", msg)
    _state_file_warned = problems
    return entries


def load_instances(state_dir: str) -> list[tuple[str, int]]:
    """Return list of (instance_name, mark_int) from state files in state_dir.

    Only proton-<N> slots participate in client-traffic rotation (see
    is_live_slot).
    """
    return [(n, m) for n, m in load_state_files(state_dir) if is_live_slot(n)]


# The marks the janitor may drain once no state file claims them. vpnns-up.sh
# sets a slot's FWMARK to its index, and live slots are proton-1..proton-99
# (rotate-slot.sh's range), so theirs are 0x1..0x63. Anything else found in the
# maps was not written by the dispatcher and is not its to remove: a staging
# copy runs at 100+N, and a mark outside this range can only have been added by
# hand. The DNS tunnel's index can fall inside it (6 on older boxes, 99 on a
# fresh install), so the caller passes that mark to unclaimed_slot_marks to
# leave out as well.
LIVE_SLOT_MARKS = frozenset(range(0x1, 0x64))


def unclaimed_slot_marks(
    entries: Iterable[tuple[str, int]],
    exclude: Iterable[int] = (),
) -> set[int] | None:
    """Live-slot marks that no state file claims right now, or None when the
    state files list no live slot at all.

    `entries` is load_state_files' (INSTANCE, FWMARK) for EVERY state file:
    a staging copy or the DNS tunnel claims its mark as firmly as a slot does.

    None is the empty-list guard. A read that finds no live slot is more
    likely a state dir caught mid-rewrite, or unreadable, than every slot
    stopping at once; and if they really have all stopped, there is no slot
    left to move the drained clients to.
    """
    entries = list(entries)
    if not any(is_live_slot(n) for n, _ in entries):
        return None
    claimed = {m for _, m in entries}
    return set(LIVE_SLOT_MARKS - claimed - set(exclude))


SCORE_FRESH_SECONDS = 120  # max age of a score for ranking eligibility


@dataclass(frozen=True)
class SlotScore:
    status: str          # "ok" or "degraded"
    score: float
    updated_at: int      # unix ts


def load_slot_score(state_path: str) -> SlotScore | None:
    """Parse a single slot's health-state file. Returns None on missing data."""
    try:
        with open(state_path) as f:
            kv = {}
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    kv[k] = v
    except OSError:
        return None

    status = kv.get("STATUS", "ok")
    score_s = kv.get("COMPOSITE_SCORE")
    ts_s = kv.get("SCORE_UPDATED_AT")
    if score_s is None or ts_s is None:
        return None
    try:
        return SlotScore(status=status, score=float(score_s), updated_at=int(ts_s))
    except ValueError:
        return None


def degraded_marks(
    instances: Iterable[tuple[str, int]],
    health_dir: str,
) -> set[int]:
    """Set of fwmarks belonging to slots currently in STATUS=degraded.

    Missing or unreadable state files are treated as not-degraded — same
    semantics as dispatcher._is_healthy.
    """
    out: set[int] = set()
    for name, mark in instances:
        try:
            with open(f"{health_dir}/{name}.state") as f:
                for line in f:
                    if line.startswith("STATUS=") and \
                       line.split("=", 1)[1].strip() == "degraded":
                        out.add(mark)
                        break
        except OSError:
            continue
    return out


def pick_by_score(
    instances: Iterable[tuple[str, int]],
    health_dir: str,
    *,
    now: int,
    fresh_seconds: int = SCORE_FRESH_SECONDS,
) -> tuple[str, int] | None:
    """Return the (name, mark) tuple with the highest fresh, non-degraded score.

    Returns None if no instance has a fresh, non-degraded score — caller should
    fall back to a random pick.
    """
    best: tuple[str, int] | None = None
    best_score = float("-inf")
    for name, mark in instances:
        s = load_slot_score(f"{health_dir}/{name}.state")
        if s is None:
            continue
        if s.status == "degraded":
            continue
        if now - s.updated_at > fresh_seconds:
            continue
        if s.score > best_score:
            best_score = s.score
            best = (name, mark)
    return best


# A slot whose fresh score is within SPREAD_BAND of the current best counts as
# "good enough" to receive new pins; slots further back (but not degraded) are
# skipped so we distribute over slots that don't suck, not all of them.
# Env-overridable (PROTEUS_SPREAD_BAND) — read at import time, so callers
# that need a fresh value after a config change must reload this module (in
# dispatcher.py, proteus.env / proteus-local.env are loaded into os.environ
# before this module is imported).
SPREAD_BAND = float(os.environ.get("PROTEUS_SPREAD_BAND", "40.0"))

def cf_required(value: str | None) -> bool:
    """One tier rule for every component: unset or empty is mandatory (checklib.sh
    uses ${PROTEUS_CF_TIER:-mandatory}); any other value than "mandatory" is advisory."""
    return (value or "mandatory") == "mandatory"


# Whether "cf ok" is required for new clients. PROTEUS_CF_TIER=mandatory (the
# default) requires it; advisory keeps flagged tunnels eligible. Read at import
# like SPREAD_BAND: dispatcher.py loads proteus.env / proteus-local.env first,
# and the UI knob restarts the dispatcher when it changes.
CF_REQUIRED = cf_required(os.environ.get("PROTEUS_CF_TIER"))

# How long a playability verdict is trusted. Comfortably longer than the
# ~16-minute re-check interval, so a slot isn't treated as "unknown" between
# checks, but short enough that a stale "no" can't outlive its exit forever.
# (rotate-slot.sh also deletes the file on promotion, which is the precise
# invalidation; this is the backstop for the case where that doesn't happen.)
PLAYABILITY_FRESH_SECONDS = 3600


def is_playable(health_dir: str, name: str, now: int,
                fresh_seconds: int = PLAYABILITY_FRESH_SECONDS) -> bool:
    """Last known streaming verdict for a slot. Unknown counts as playable.

    slot-warmup writes this; see playability_check there. Absent, unreadable,
    malformed or stale all resolve to True on purpose — a slot is presumed good
    until something actually observed otherwise, because the alternative
    (presuming bad) would empty the eligible pool on any monitoring hiccup and
    strand every new client.
    """
    try:
        with open(f"{health_dir}/.playability-state.{name}") as f:
            kv = {}
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    kv[k] = v
    except OSError:
        return True
    if kv.get("PLAYABLE", "yes") != "no":
        return True
    try:
        if now - int(kv.get("AT", "0")) > fresh_seconds:
            return True          # verdict too old to act on
    except ValueError:
        return True
    return False


def is_cf_clean(health_dir: str, name: str) -> bool:
    """Last known Cloudflare verdict for a slot: False only for CF_CLEAN=no.

    A flag holds at any age. slot-warmup's live check replaces it on every run
    that observes the canaries. rotate-slot.sh replaces or removes it on
    promotion, so a "no" never outlives the exit it describes. An absent,
    unreadable or malformed file is a slot with no verdict yet (a reboot clears
    /run) and counts as clean: nothing has observed it, and the next live-check
    turn does.
    """
    try:
        with open(f"{health_dir}/.cf-state.{name}") as f:
            kv = {}
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    kv[k] = v
    except OSError:
        return True
    return kv.get("CF_CLEAN", "yes") != "no"


def prefer_cf_clean(candidates, health_dir: str) -> list:
    """The "cf ok" members of `candidates` (tuples that start with the slot
    name), or all of them when none is.

    "cf ok" is mandatory for new clients: a slot whose exit Cloudflare flagged
    takes none while another slot is cf ok. When every slot is flagged, a
    flagged exit beats no exit, so new clients still get one. When cf ok is
    not required (CF_REQUIRED is False), all candidates are returned.
    """
    if not CF_REQUIRED:
        return list(candidates)
    clean = [c for c in candidates if is_cf_clean(health_dir, c[0])]
    return clean or list(candidates)


def pick_distributed(
    instances: Iterable[tuple[str, int]],
    health_dir: str,
    load_counts: dict[int, int],
    *,
    now: int,
    fresh_seconds: int = SCORE_FRESH_SECONDS,
    spread_band: float = SPREAD_BAND,
    prefer_playable: bool = True,
) -> tuple[str, int] | None:
    """Pick a slot for a new assignment, spreading load across the good slots.

    "Good" = fresh, non-degraded, and scoring within `spread_band` of the best
    fresh score (so a healthy-but-weak slot is excluded). Among those, choose
    the least-loaded by `load_counts` (mark -> #entries), tie-breaking toward
    the higher score. This fans new work out across the strong slots —
    spreading bandwidth and handing out distinct exit IPs — instead of piling
    everything onto the single top slot. When cf ok is required, a slot whose
    exit Cloudflare flagged is left out while another scored slot is cf ok.

    `load_counts` must come from a SINGLE source, because the numbers are only
    ever compared with each other. The caller has two candidate maps and they
    are different units: source_pin counts pinned hosts (a handful per slot),
    vpn_dispatch counts pinned destinations (unbounded, one per address any
    trusted host reaches). Mixing them makes a slot carrying trusted traffic
    look permanently most-loaded beside a slot holding four client pins, so it
    stops receiving client pins entirely and the ranking tracks destination
    churn instead of load. dispatcher.pick() therefore passes the counts for
    whichever map the assignment being made will land in.

    Returns None if no slot has a fresh, non-degraded score (caller falls back
    to a random healthy pick).
    """
    scored: list[tuple[str, int, float]] = []
    for name, mark in instances:
        s = load_slot_score(f"{health_dir}/{name}.state")
        if s is None or s.status == "degraded":
            continue
        if now - s.updated_at > fresh_seconds:
            continue
        scored.append((name, mark, s.score))
    if not scored:
        return None

    # "cf ok" first, on every pick: a flagged exit takes no new pins while
    # another scored slot without a flag exists. Then streaming playability
    # inside that set, under the same rule. A flagged or gated exit stays
    # eligible for scoring, routing and rotation, and when every slot is bad
    # the full set stays: a bad exit beats none.
    scored = prefer_cf_clean(scored, health_dir)
    if prefer_playable:
        playable = [t for t in scored if is_playable(health_dir, t[0], now)]
        if playable:
            scored = playable

    best = max(score for _, _, score in scored)
    eligible = [(n, m, sc) for (n, m, sc) in scored if sc >= best - spread_band]
    # Fewest current entries first; among equally-loaded, prefer higher score.
    eligible.sort(key=lambda t: (load_counts.get(t[1], 0), -t[2]))
    name, mark, _ = eligible[0]
    return (name, mark)


def is_pinnable_source(ip_str: str, cidrs="172.16.1.0/24") -> bool:
    """True if `ip_str` is a real host address inside one of `cidrs`.

    `cidrs` is a CIDR string or a sequence of them; a bare string is still
    accepted so existing callers keep working. Rejects 0.0.0.0 and other
    off-range sources — a stray DHCP or broadcast packet that reached the
    dispatcher should not create a junk pin — and each range's own network and
    broadcast addresses.

    That last guard is skipped for ranges with two addresses or fewer, because a
    /32 is how a single infra host is trusted without trusting the subnet around
    it, and its only address is simultaneously the network and the broadcast
    address. A malformed range is skipped rather than failing the whole check,
    so one bad entry cannot stop every other source being pinned.
    """
    if isinstance(cidrs, str):
        cidrs = (cidrs,)
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr)
        except ValueError:
            continue
        if ip not in net:
            continue
        if net.num_addresses > 2 and ip in (net.network_address, net.broadcast_address):
            continue
        return True
    return False


def is_udm_tunnel_source(ip_str: str, tunnel_cidr: str | None) -> bool:
    """True if `ip_str` sits inside the UDM tunnel subnet.

    The UDM masquerades every packet it pushes into `wg-udm`, so all trusted
    hosts arrive at proteus wearing the single tunnel address. This predicate
    therefore means "this packet's source carries no per-host information":
    the dispatcher must record a destination entry for it and no source pin.

    Why the source pin specifically is forbidden: `prerouting_mangle` consults
    `@source_pin` before `@vpn_dispatch`, so one pin on the tunnel address
    would shadow the destination path for every trusted host at once and put
    the whole trusted VLAN back on a single exit — the exact bug the
    per-destination dispatch exists to fix. (The ruleset also scopes its source
    lookup to the client interface; this is the second half of the same rule,
    on the writer's side, so a stale or hand-added pin cannot be recreated.)

    A None or malformed `tunnel_cidr` returns False rather than raising: with
    no usable tunnel subnet there is no tunnel traffic to recognise, and the
    caller falls back to its ordinary pinnable-source check.
    """
    if not tunnel_cidr:
        return False
    try:
        return ipaddress.IPv4Address(ip_str) in ipaddress.IPv4Network(tunnel_cidr)
    except ValueError:
        return False


def parse_source_pin_elements(elems: object) -> list[tuple[str, int]]:
    """Parse the `elem` list from `nft -j list map ...` output for source_pin.

    Handles both shapes nft emits depending on whether the map has element
    timeouts:
      Bare:        [[ip, mark]]
      Wrapped key: [[{"elem": {"val": ip, "expires": N}}, mark]]
      Wrapped val: [[ip, {"val": mark}]]   (less common, but possible)
      Both:        [[{"elem": {...}}, {"val": mark}]]

    Malformed entries are silently skipped — better to surface most pins than
    abort on one weird element.
    """
    out: list[tuple[str, int]] = []
    if not isinstance(elems, list):
        return out
    for entry in elems:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        raw_key, raw_val = entry[0], entry[1]

        # Unwrap the key — string or {"elem": {"val": ...}}.
        if isinstance(raw_key, str):
            key = raw_key
        elif isinstance(raw_key, dict):
            inner = raw_key.get("elem")
            if isinstance(inner, dict) and "val" in inner:
                key = inner["val"]
            elif "val" in raw_key:
                key = raw_key["val"]
            else:
                continue
        else:
            continue

        # Unwrap the value — int or {"val": int}.
        if isinstance(raw_val, dict) and "val" in raw_val:
            mark_raw = raw_val["val"]
        else:
            mark_raw = raw_val

        try:
            out.append((str(key), int(mark_raw)))
        except (TypeError, ValueError):
            continue
    return out


def parse_source_pin_elements_with_ttl(elems: object) -> list[tuple[str, int, int | None]]:
    """Like parse_source_pin_elements, but also extracts the remaining TTL.

    `nft -j list map ...` reports a per-element `expires` field (seconds
    remaining until the element times out — a countdown, NOT an absolute
    epoch timestamp; verified live against nft 1.1.3: insert with `timeout
    30s` reads back `expires: 29` immediately and `expires: 24` five seconds
    later) whenever the map has `flags timeout` and the entry carries a
    timeout, wrapped as `{"elem": {"val": ip, "expires": N}}`. Bare
    `[ip, mark]` entries (e.g. from a map without timeouts) carry no such
    info, so their ttl comes back as None — callers must treat that as
    "unknown" rather than invent an expiry.

    Returns (ip, mark, ttl_remaining_s) tuples. Malformed entries are
    silently skipped, matching parse_source_pin_elements.
    """
    out: list[tuple[str, int, int | None]] = []
    if not isinstance(elems, list):
        return out
    for entry in elems:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        raw_key, raw_val = entry[0], entry[1]

        ttl: int | None = None
        if isinstance(raw_key, str):
            key = raw_key
        elif isinstance(raw_key, dict):
            inner = raw_key.get("elem")
            if isinstance(inner, dict) and "val" in inner:
                key = inner["val"]
                expires = inner.get("expires")
                if isinstance(expires, (int, float)):
                    ttl = int(expires)
            elif "val" in raw_key:
                key = raw_key["val"]
            else:
                continue
        else:
            continue

        if isinstance(raw_val, dict) and "val" in raw_val:
            mark_raw = raw_val["val"]
        else:
            mark_raw = raw_val

        try:
            out.append((str(key), int(mark_raw), ttl))
        except (TypeError, ValueError):
            continue
    return out


def parse_get_element_mark(text: str, key: str) -> int | None:
    """The mark in `nft get element <family> <table> <map> { key }` output.

    nft 1.1.3 ignores -j for `get element` and prints the ruleset form, with
    the one element on a line such as
        elements = { 172.16.1.50 timeout 6h expires 5h59m58s : 0x00000002 }
    (no timeout/expires on a map without them). Returns None unless that line
    names exactly `key` (172.16.1.5 must not match 172.16.1.50) and ends in a
    mark nft printed in hex or decimal.
    """
    m = re.search(
        r"elements\s*=\s*\{\s*" + re.escape(key)
        + r"(?=[\s:])[^:{}\n]*:\s*(0x[0-9a-fA-F]+|[0-9]+)\s*\}",
        text or "")
    if m is None:
        return None
    raw = m.group(1)
    return int(raw, 16) if raw.startswith("0x") else int(raw)


def build_status_snapshot(pins: dict, counters: dict, now: float) -> dict:
    """Build the JSON-serializable status snapshot published for the web UI.

    `pins` is {ip: (slot, expiry_epoch_s)}; already-expired entries (expiry
    <= now) are dropped rather than surfaced with a negative/zero ttl_s.
    `counters` is {slot: flow_count}, published verbatim.
    """
    return {
        "generated_at": int(now),
        "pins": [
            {"ip": ip, "slot": slot, "ttl_s": int(exp - now)}
            for ip, (slot, exp) in sorted(pins.items()) if exp > now
        ],
        "flow_counts": dict(counters),
    }
