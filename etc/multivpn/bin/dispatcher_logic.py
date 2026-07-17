"""Pure logic for the multi-VPN dispatcher.

This module has NO netfilter or scapy imports — everything here is
unit-testable with stdlib alone. The integration glue lives in
dispatcher.py, which imports from here.
"""

from __future__ import annotations

import glob
import ipaddress
import logging
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
SPREAD_BAND = 40.0


def pick_distributed(
    instances: Iterable[tuple[str, int]],
    health_dir: str,
    pin_counts: dict[int, int],
    *,
    now: int,
    fresh_seconds: int = SCORE_FRESH_SECONDS,
    spread_band: float = SPREAD_BAND,
) -> tuple[str, int] | None:
    """Pick a slot for a new pin, spreading load across the good slots.

    "Good" = fresh, non-degraded, and scoring within `spread_band` of the best
    fresh score (so a healthy-but-weak slot is excluded). Among those, choose
    the least-loaded by current pin count (`pin_counts`: mark -> #pins),
    tie-breaking toward the higher score. This fans new clients out across the
    strong slots — spreading bandwidth and handing out distinct exit IPs —
    instead of piling every client onto the single top slot.

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

    best = max(score for _, _, score in scored)
    eligible = [(n, m, sc) for (n, m, sc) in scored if sc >= best - spread_band]
    # Fewest current pins first; among equally-loaded, prefer the higher score.
    eligible.sort(key=lambda t: (pin_counts.get(t[1], 0), -t[2]))
    name, mark, _ = eligible[0]
    return (name, mark)


def is_pinnable_source(ip_str: str, client_cidr: str = "172.16.1.0/24") -> bool:
    """True if `ip_str` is a real client-VLAN host address worth pinning.

    Rejects 0.0.0.0 and other off-VLAN sources (e.g. a stray DHCP/broadcast
    packet that reached the dispatcher), and the network/broadcast addresses of
    the client subnet, so they don't pollute source_pin with junk entries.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        net = ipaddress.IPv4Network(client_cidr)
    except ValueError:
        return False
    if ip not in net:
        return False
    return ip not in (net.network_address, net.broadcast_address)


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
