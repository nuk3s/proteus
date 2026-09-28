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


def load_instances(state_dir: str) -> list[tuple[str, int]]:
    """Return list of (instance_name, mark_int) from state files in state_dir.

    Only proton-<N> slots participate in client-traffic rotation.
    Specialized tunnels (e.g. dns-6) are excluded; they carry their own
    dedicated traffic via per-uid routing rules.
    """
    instances: list[tuple[str, int]] = []
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
            log.warning("could not read %s: %s", path, e)
            continue
        name = kv.get("INSTANCE")
        mark = kv.get("FWMARK")
        if name and not re.fullmatch(r"proton-\d+", name):
            continue
        if name and mark:
            try:
                instances.append((name, int(mark, 16)))
            except ValueError:
                log.warning("bad FWMARK in %s: %r", path, mark)
    return instances


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

# Shadow mode: with PROTEUS_CF_TIER=advisory the Cloudflare verdict is recorded
# and displayed but never acts, including on new-pin placement. Read at import
# like SPREAD_BAND (dispatcher.py loads proteus.env / proteus-local.env into the
# environment first); the UI knob restarts the dispatcher when it changes.
CF_BIAS = os.environ.get("PROTEUS_CF_TIER", "mandatory") == "mandatory"


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


def is_cf_clean(health_dir: str, name: str, now: int,
                fresh_seconds: int = PLAYABILITY_FRESH_SECONDS) -> bool:
    """Last known Cloudflare verdict for a slot. Unknown counts as clean.

    slot-warmup's live_check writes .cf-state.<slot> on every run and
    rotate-slot.sh writes it on a step-down promotion. Absent, unreadable,
    malformed or stale all resolve to True for the same reason is_playable
    does: presuming bad would empty the eligible pool on a monitoring hiccup.
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
    if kv.get("CF_CLEAN", "yes") != "no":
        return True
    try:
        if now - int(kv.get("AT", "0")) > fresh_seconds:
            return True
    except ValueError:
        return True
    return False


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
    everything onto the single top slot.

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

    # Preference cascade, each step applied only if it leaves at least one slot:
    # clean of Cloudflare challenges AND playable, then clean, then playable,
    # then everybody. A challenged or gated exit stays eligible for scoring,
    # routing and rotation; it is only moved to the back of the queue for NEW
    # pins. If every slot is bad, keep the full set: a bad exit beats none.
    if prefer_playable:
        clean = [t for t in scored if is_cf_clean(health_dir, t[0], now)] if CF_BIAS else list(scored)
        playable = [t for t in scored if is_playable(health_dir, t[0], now)]
        both = [t for t in clean if t in playable]
        if both:
            scored = both
        elif clean:
            scored = clean
        elif playable:
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
