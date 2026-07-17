#!/usr/bin/env python3
"""
Multi-VPN dispatch daemon.

Reads packets on NFQUEUE 0. For each first-seen destination IP, picks a
currently-up VPN instance at random, inserts (dest_ip -> mark) into the
nftables map `inet filter vpn_dispatch`, then sets the packet's fwmark
and accepts it so policy routing can steer it to the chosen namespace.

Follow-up packets to the same destination hit the map directly in
prerouting_mangle and never reach us — so we are only invoked on brand-
new destinations.

The list of active instances is read from /etc/multivpn/state/*.state.
Send SIGHUP to reload (e.g. after rotation).
"""

import json
import logging
import logging.handlers
import os
import random
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP

from dispatcher_logic import (
    load_instances, degraded_marks, parse_source_pin_elements,
    pick_distributed, is_pinnable_source,
)

STATE_DIR = "/etc/multivpn/state"
HEALTH_DIR = "/run/multivpn-slot-health"
def _env(key, default):
    try:
        with open("/etc/multivpn/multivpn.env") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return default

CLIENT_VLAN = _env("MULTIVPN_CLIENT_VLAN_CIDR", "172.16.1.0/24")
NFT_TABLE_FAMILY = "inet"
NFT_TABLE = "filter"
NFT_MAP = "vpn_dispatch"
NFT_SOURCE_PIN_MAP = "source_pin"
LOG_PATH = "/var/log/multivpn/dispatcher.log"
QUEUE_NUM = 0

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

    Reads /run/multivpn-slot-health/<inst>.state which slot-warmup updates
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
            log.warning("no active VPN instance; dropping packet from %s to %s",
                        src, dest)
            pkt.drop()
            return

        name, mark = choice

        # Pin the source (per-client stickiness) AND record the dest (per-dest
        # fallback). Only pin real client-VLAN hosts — a stray 0.0.0.0/off-VLAN
        # packet shouldn't create a junk pin. On insert failure we still
        # mark+accept; subsequent packets just re-enter NFQUEUE (a perf hit, not
        # a correctness issue — vpn_dispatch is the fallback either way).
        if is_pinnable_source(src, CLIENT_VLAN):
            if not _nft_source_pin_insert(src, mark):
                log.error("source_pin insert failed for %s -> %s (0x%x)", src, name, mark)
        else:
            log.info("not pinning off-VLAN source %s (dst=%s -> %s)", src, dest, name)
        if not _nft_map_insert(dest, mark):
            log.error("vpn_dispatch insert failed for %s -> %s (0x%x)", dest, name, mark)

        pkt.set_mark(mark)
        pkt.accept()
        log.info("dispatch src=%s dst=%s -> %s (mark 0x%x)", src, dest, name, mark)

    def janitor_once(self) -> None:
        """One pass: evict source_pin entries whose mark belongs to a degraded slot."""
        with self._lock:
            instances = list(self._instances)
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
                    log.info("evicted pin %s -> %s (degraded)",
                             src, name_by_mark.get(mark, f"0x{mark:x}"))
        if evicted:
            log.info("janitor: evicted %d pin(s) to degraded slots", evicted)

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
        log.error("nft add element timed out for %s", dest_ip)
        return False
    if r.returncode != 0:
        # An existing entry for this key errors out with "File exists" — treat as benign.
        if "File exists" in (r.stderr or ""):
            return True
        log.error("nft add element failed (%s): %s", r.returncode, r.stderr.strip())
        return False
    return True


def _nft_source_pin_insert(src_ip: str, mark: int) -> bool:
    """Insert (src_ip -> mark) into the source_pin map."""
    elem = "{ %s : 0x%x }" % (src_ip, mark)
    try:
        r = subprocess.run(
            ["nft", "add", "element", NFT_TABLE_FAMILY, NFT_TABLE,
             NFT_SOURCE_PIN_MAP, elem],
            capture_output=True, text=True, timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft add element (source_pin) timed out for %s", src_ip)
        return False
    if r.returncode != 0:
        if "File exists" in (r.stderr or ""):
            return True
        log.error("nft add element (source_pin) failed (%s): %s",
                  r.returncode, r.stderr.strip())
        return False
    return True


JANITOR_INTERVAL = 60  # seconds between degradation eviction passes


def _nft_list_source_pin() -> list[tuple[str, int]] | None:
    """Return list of (src_ip, mark) currently in source_pin, or None on error."""
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
        log.error("nft list source_pin failed: %s", r.stderr.strip())
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
        return parse_source_pin_elements(m.get("elem"))
    return []


def _nft_source_pin_remove(src_ip: str) -> bool:
    elem = "{ %s }" % src_ip
    try:
        r = subprocess.run(
            ["nft", "delete", "element", NFT_TABLE_FAMILY, NFT_TABLE,
             NFT_SOURCE_PIN_MAP, elem],
            capture_output=True, text=True, timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft delete element (source_pin) timed out for %s", src_ip)
        return False
    if r.returncode != 0:
        # Not an error if the element is already gone (raced with TTL eviction).
        if "No such file or directory" in (r.stderr or "") or \
           "does not exist" in (r.stderr or ""):
            return True
        log.error("nft delete element (source_pin) failed (%s): %s",
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
