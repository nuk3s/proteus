#!/usr/bin/env python3
"""
Proteus dispatch daemon.

Reads packets on NFQUEUE 0. For each first-seen destination IP, picks a
currently-up VPN instance at random, inserts (dest_ip -> mark) into the
nftables map `inet filter vpn_dispatch`, then sets the packet's fwmark
and accepts it so policy routing can steer it to the chosen namespace.

Follow-up packets to the same destination hit the map directly in
prerouting_mangle and never reach us — so we are only invoked on brand-
new destinations.

The list of active instances is read from /etc/proteus/state/*.state.
Send SIGHUP to reload (e.g. after rotation).
"""

import grp
import json
import logging
import logging.handlers
import os
import random
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

STATE_DIR = "/etc/proteus/state"
HEALTH_DIR = "/run/proteus-slot-health"


def _load_env_file(path: str, *, protected: frozenset[str]) -> None:
    """Parse KEY=VALUE lines from an env file into os.environ.

    Keys already present in `protected` (the real process environment at
    startup, e.g. set by systemd or an explicit export) are left alone —
    an operator's actual environment always wins over file-based config.
    Otherwise a later call overrides an earlier one, matching the shell
    `source proteus.env; . proteus-local.env` convention used by the other
    proteus scripts (proteus-local.env carries UI-driven overrides).
    """
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"')
                if key in protected:
                    continue
                os.environ[key] = val
    except OSError:
        pass


# Load proteus.env then proteus-local.env (UI overrides) into os.environ
# BEFORE importing dispatcher_logic or computing our own env-derived module
# constants (CLIENT_VLAN, PIN_TTL_S) below — dispatcher_logic.SPREAD_BAND is
# computed at import time from os.environ, so the env files must land first.
_PROTECTED_ENV = frozenset(os.environ)
_load_env_file("/etc/proteus/proteus.env", protected=_PROTECTED_ENV)
_load_env_file("/etc/proteus/proteus-local.env", protected=_PROTECTED_ENV)

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP

from dispatcher_logic import (
    load_instances, degraded_marks, parse_source_pin_elements,
    parse_source_pin_elements_with_ttl, pick_distributed, is_pinnable_source,
    build_status_snapshot,
)

CLIENT_VLAN = os.environ.get("PROTEUS_CLIENT_VLAN_CIDR", "172.16.1.0/24")
# Source-pin TTL: was hard-coded only in etc/nftables.conf's `timeout 6h` on
# the source_pin map; now set explicitly per-element on insert (see
# _nft_source_pin_insert) so PROTEUS_PIN_TTL_S actually takes effect without
# an nftables.conf reload. Default matches the prior hard-coded 6h.
PIN_TTL_S = int(os.environ.get("PROTEUS_PIN_TTL_S", "21600"))
NFT_TABLE_FAMILY = "inet"
NFT_TABLE = "filter"
NFT_MAP = "vpn_dispatch"
NFT_SOURCE_PIN_MAP = "source_pin"
LOG_PATH = "/var/log/proteus/dispatcher.log"
QUEUE_NUM = 0
SNAPSHOT = "/run/proteus/dispatcher-status.json"


def write_snapshot(snap: dict) -> None:
    """Atomically publish the status snapshot, group-readable by proteus-ui."""
    os.makedirs("/run/proteus", exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir="/run/proteus")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(snap, f)
        os.chmod(tmp, 0o640)
        # /run/proteus is setgid root:proteus-ui (tmpfiles.d), so files created
        # here inherit the proteus-ui group. Attempt an explicit chown too, but
        # the dispatcher has no CAP_CHOWN (see CapabilityBoundingSet in the
        # unit), so treat failure as non-fatal — setgid inheritance covers
        # group-readability for the UI.
        try:
            os.chown(tmp, 0, grp.getgrnam("proteus-ui").gr_gid)
        except (KeyError, OSError):
            pass
        os.rename(tmp, SNAPSHOT)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


log = logging.getLogger("dispatcher")


def _setup_logging() -> None:
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=2 * 1024 * 1024, backupCount=3
    )
    fh.setFormatter(fmt)
    log.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)


def _is_healthy(instance_name: str) -> bool:
    """Return True if the slot is OK to receive new flows.

    Reads /run/proteus-slot-health/<inst>.state which slot-warmup updates
    after each pass. A missing file (e.g. just-booted, warmup hasn't run yet)
    is treated as healthy — better to send traffic and let it ride than to
    falsely DEGRADE everything at boot.
    """
    path = f"{HEALTH_DIR}/{instance_name}.state"
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("STATUS="):
                    return line.split("=", 1)[1].strip() != "degraded"
    except OSError:
        return True
    return True


class Dispatcher:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._instances: list[tuple[str, int]] = []
        # Per-slot count of flows dispatched since start, for the UI status
        # snapshot. Separate lock: handle() (NFQUEUE callback, effectively
        # single-threaded) increments it; the janitor thread reads it.
        self._counts_lock = threading.Lock()
        self._flow_counts: Counter[str] = Counter()
        self.reload()

    def reload(self) -> None:
        new = load_instances(STATE_DIR)
        with self._lock:
            self._instances = new
        log.info(
            "loaded %d VPN instance(s): %s",
            len(new),
            ", ".join(f"{n}=0x{m:x}" for n, m in new) or "(none)",
        )

    def _pin_counts(self) -> dict[int, int]:
        """Current pin count per mark, read from the source_pin map. Empty on
        error — pick_distributed then degrades gracefully to pure best-score."""
        counts: dict[int, int] = {}
        pins = _nft_list_source_pin()
        if pins:
            for _src, mark in pins:
                counts[mark] = counts.get(mark, 0) + 1
        return counts

    def pick(self) -> tuple[str, int] | None:
        with self._lock:
            if not self._instances:
                return None

            # 1. Distribute new clients across the good slots (fresh, non-
            #    degraded, within SPREAD_BAND of the best), least-loaded first.
            #    Spreads bandwidth and hands out distinct exit IPs instead of
            #    piling every client onto the single top-scored slot.
            chosen = pick_distributed(
                self._instances, HEALTH_DIR, self._pin_counts(), now=int(time.time())
            )
            if chosen is not None:
                return chosen

            # 2. No fresh scores yet — fall back to today's healthy random.
            healthy = [(n, m) for (n, m) in self._instances if _is_healthy(n)]
            if healthy:
                return random.choice(healthy)

            # 3. Everything degraded — log loudly, ride a known-bad slot.
            log.warning(
                "all %d instance(s) DEGRADED; falling back to full pool",
                len(self._instances),
            )
            return random.choice(self._instances)

    def handle(self, pkt) -> None:
        try:
            payload = pkt.get_payload()
            ip = IP(payload)
            src = ip.src
            dest = ip.dst
        except Exception:
            log.exception("parse failure; dropping packet")
            pkt.drop()
            return

        choice = self.pick()
        if choice is None:
            # Genuinely important (we're dropping traffic) — keep the event at
            # WARNING, but the client/dest addresses are privacy-sensitive so
            # they only go to DEBUG.
            log.warning("no active VPN instance; dropping packet")
            log.debug("no active VPN instance; dropping packet from %s to %s",
                       src, dest)
            pkt.drop()
            return

        name, mark = choice

        # New flow dispatched to `name` — count it for the UI status snapshot.
        with self._counts_lock:
            self._flow_counts[name] += 1

        # Pin the source (per-client stickiness) AND record the dest (per-dest
        # fallback). Only pin real client-VLAN hosts — a stray 0.0.0.0/off-VLAN
        # packet shouldn't create a junk pin. On insert failure we still
        # mark+accept; subsequent packets just re-enter NFQUEUE (a perf hit, not
        # a correctness issue — vpn_dispatch is the fallback either way).
        if is_pinnable_source(src, CLIENT_VLAN):
            if not _nft_source_pin_insert(src, mark):
                log.error("source_pin insert failed (0x%x)", mark)
                log.debug("source_pin insert failed for %s -> %s (0x%x)", src, name, mark)
        else:
            log.debug("not pinning off-VLAN source %s (dst=%s -> %s)", src, dest, name)
        if not _nft_map_insert(dest, mark):
            log.error("vpn_dispatch insert failed (0x%x)", mark)
            log.debug("vpn_dispatch insert failed for %s -> %s (0x%x)", dest, name, mark)

        pkt.set_mark(mark)
        pkt.accept()
        # Per-flow client activity — DEBUG only, this is the browsing-trail
        # line; the default (INFO) level must not record per-client addresses.
        log.debug("dispatch src=%s dst=%s -> %s (mark 0x%x)", src, dest, name, mark)

    def flow_counts_snapshot(self) -> dict[str, int]:
        with self._counts_lock:
            return dict(self._flow_counts)

    def janitor_once(self) -> None:
        """One pass: evict source_pin entries whose mark belongs to a degraded
        slot, then publish a status snapshot for the web UI."""
        with self._lock:
            instances = list(self._instances)
        self._evict_degraded_pins(instances)
        self._publish_snapshot(instances)

    def _evict_degraded_pins(self, instances: list[tuple[str, int]]) -> None:
        bad_marks = degraded_marks(instances, HEALTH_DIR)
        if not bad_marks:
            return
        pins = _nft_list_source_pin()
        if pins is None:
            return
        # Reverse-lookup mark -> name for log messages.
        name_by_mark = {m: n for n, m in instances}
        evicted = 0
        for src, mark in pins:
            if mark in bad_marks:
                if _nft_source_pin_remove(src):
                    evicted += 1
                    # Client IP -> DEBUG only.
                    log.debug("evicted pin %s -> %s (degraded)",
                              src, name_by_mark.get(mark, f"0x{mark:x}"))
        if evicted:
            log.info("janitor: evicted %d pin(s) to degraded slots", evicted)

    def _publish_snapshot(self, instances: list[tuple[str, int]]) -> None:
        """Build and atomically write /run/proteus/dispatcher-status.json.

        Pins come from the source_pin nft map, whose elements always carry a
        timeout (the map itself is `flags timeout`), so nft -j reports a
        remaining-seconds `expires` per element; we convert that to an
        absolute epoch expiry (now + expires) for build_status_snapshot.
        Entries we can't resolve to a known slot name, or that carry no ttl
        info at all (defensive — shouldn't happen for a timeout-flagged map),
        are dropped rather than guessed at.
        """
        now = time.time()
        raw = _nft_list_source_pin_with_ttl()
        pins: dict[str, tuple[str, float]] = {}
        if raw is not None:
            name_by_mark = {m: n for n, m in instances}
            for src, mark, ttl_remaining in raw:
                name = name_by_mark.get(mark)
                if name is None or ttl_remaining is None:
                    continue
                pins[src] = (name, now + ttl_remaining)
        snap = build_status_snapshot(pins, self.flow_counts_snapshot(), now)
        try:
            write_snapshot(snap)
        except OSError:
            log.exception("failed to write status snapshot")

    def janitor_loop(self) -> None:
        log.info("janitor thread started (interval=%ds)", JANITOR_INTERVAL)
        while True:
            try:
                self.janitor_once()
            except Exception:
                log.exception("janitor pass failed; will retry")
            time.sleep(JANITOR_INTERVAL)


def _nft_map_insert(dest_ip: str, mark: int) -> bool:
    """Insert (dest_ip -> mark) into the dispatch map."""
    elem = "{ %s : 0x%x }" % (dest_ip, mark)
    try:
        r = subprocess.run(
            ["nft", "add", "element", NFT_TABLE_FAMILY, NFT_TABLE, NFT_MAP, elem],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft add element (vpn_dispatch) timed out")
        log.debug("nft add element timed out for %s", dest_ip)
        return False
    if r.returncode != 0:
        # An existing entry for this key errors out with "File exists" — treat as benign.
        if "File exists" in (r.stderr or ""):
            return True
        log.error("nft add element (vpn_dispatch) failed (rc=%s)", r.returncode)
        log.debug("nft add element failed (%s): %s", r.returncode, r.stderr.strip())
        return False
    return True


def _nft_source_pin_insert(src_ip: str, mark: int) -> bool:
    """Insert (src_ip -> mark) into the source_pin map.

    Sets an explicit per-element timeout (PIN_TTL_S) rather than relying on
    the map's own default (`timeout 6h` in etc/nftables.conf), so
    PROTEUS_PIN_TTL_S actually controls pin lifetime without an nftables.conf
    reload. Verified live (nft 1.1.3): `add element ... { ip timeout 30s :
    mark }` is accepted and the element reads back with `timeout: 30`.
    """
    elem = "{ %s timeout %ds : 0x%x }" % (src_ip, PIN_TTL_S, mark)
    try:
        r = subprocess.run(
            ["nft", "add", "element", NFT_TABLE_FAMILY, NFT_TABLE,
             NFT_SOURCE_PIN_MAP, elem],
            capture_output=True, text=True, timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft add element (source_pin) timed out")
        log.debug("nft add element (source_pin) timed out for %s", src_ip)
        return False
    if r.returncode != 0:
        if "File exists" in (r.stderr or ""):
            return True
        log.error("nft add element (source_pin) failed (rc=%s)", r.returncode)
        log.debug("nft add element (source_pin) failed (%s): %s",
                  r.returncode, r.stderr.strip())
        return False
    return True


JANITOR_INTERVAL = 60  # seconds between degradation eviction passes


def _nft_source_pin_elem_list() -> object | None:
    """Return the raw `elem` list from `nft -j list map ... source_pin`, or
    None on error (timeout, nonzero exit, unparseable JSON). Shared by
    _nft_list_source_pin and _nft_list_source_pin_with_ttl so there's one
    place that talks to nft."""
    try:
        r = subprocess.run(
            ["nft", "-j", "list", "map", NFT_TABLE_FAMILY, NFT_TABLE,
             NFT_SOURCE_PIN_MAP],
            capture_output=True, text=True, timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft list source_pin timed out")
        return None
    if r.returncode != 0:
        log.error("nft list source_pin failed (rc=%s)", r.returncode)
        log.debug("nft list source_pin failed: %s", r.stderr.strip())
        return None

    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.error("nft -j output not parseable: %s", e)
        return None

    for obj in doc.get("nftables", []):
        m = obj.get("map")
        if not m or m.get("name") != NFT_SOURCE_PIN_MAP:
            continue
        return m.get("elem")
    return []


def _nft_list_source_pin() -> list[tuple[str, int]] | None:
    """Return list of (src_ip, mark) currently in source_pin, or None on error."""
    elems = _nft_source_pin_elem_list()
    if elems is None:
        return None
    return parse_source_pin_elements(elems)


def _nft_list_source_pin_with_ttl() -> list[tuple[str, int, int | None]] | None:
    """Return list of (src_ip, mark, ttl_remaining_s) currently in
    source_pin, or None on error. ttl_remaining_s is nft's per-element
    `expires` (seconds remaining, a countdown — not an absolute time)."""
    elems = _nft_source_pin_elem_list()
    if elems is None:
        return None
    return parse_source_pin_elements_with_ttl(elems)


def _nft_source_pin_remove(src_ip: str) -> bool:
    elem = "{ %s }" % src_ip
    try:
        r = subprocess.run(
            ["nft", "delete", "element", NFT_TABLE_FAMILY, NFT_TABLE,
             NFT_SOURCE_PIN_MAP, elem],
            capture_output=True, text=True, timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft delete element (source_pin) timed out")
        log.debug("nft delete element (source_pin) timed out for %s", src_ip)
        return False
    if r.returncode != 0:
        # Not an error if the element is already gone (raced with TTL eviction).
        if "No such file or directory" in (r.stderr or "") or \
           "does not exist" in (r.stderr or ""):
            return True
        log.error("nft delete element (source_pin) failed (rc=%s)", r.returncode)
        log.debug("nft delete element (source_pin) failed (%s): %s",
                  r.returncode, r.stderr.strip())
        return False
    return True


def main() -> int:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    _setup_logging()

    d = Dispatcher()
    if not d._instances:
        log.error("no active VPN instances in %s; exiting", STATE_DIR)
        return 1

    # SIGHUP reloads the instance list (called after rotation).
    signal.signal(signal.SIGHUP, lambda *_: d.reload())

    # Start the pin janitor in the background.
    janitor = threading.Thread(target=d.janitor_loop, name="janitor", daemon=True)
    janitor.start()

    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, d.handle)
    log.info("bound to NFQUEUE %d", QUEUE_NUM)

    try:
        nfq.run()
    except KeyboardInterrupt:
        log.info("interrupted; shutting down")
    finally:
        nfq.unbind()
    return 0


if __name__ == "__main__":
    sys.exit(main())
