#!/usr/bin/env python3
"""
Proteus dispatch daemon.

Reads packets on NFQUEUE 0: the first packet of a new flow that nothing in
prerouting_mangle (etc/nftables.conf) has already mapped. There are two
dispatchable origins and they are mapped differently:

- Client VLAN (ens19) hosts arrive with their real addresses. A packet gets
  here when its source has no pin and its destination no entry. We pick a
  slot, pin the SOURCE in `inet filter source_pin` for PIN_TTL_S, so every
  later flow from that client rides the same exit, and record the
  destination in `inet filter vpn_dispatch` as a fallback.
- Trusted traffic out of the UDM tunnel (wg-udm) arrives masqueraded as the
  one tunnel address, so a source pin would carry no per-host information.
  The ruleset skips @source_pin for it and we write only the destination
  entry: trusted traffic is dispatched per destination.

Each decision is balanced by pick_distributed (fresh score, not degraded,
within SPREAD_BAND of the best, least-loaded, playable preferred) against
the one map it lands in. We then set the packet's fwmark and accept it, and
policy routing steers it to the slot's namespace. Later packets that hit a
map entry are marked in the kernel and never reach us.

The list of active instances is read from /etc/proteus/state/*.state.
Send SIGHUP to reload it (rotate-slot.sh does, after every promotion). The
reload is deferred to the next pick()/janitor pass — see
_install_signal_handlers for why the handler itself must do nothing else.
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
    is_udm_tunnel_source, build_status_snapshot,
)
import ipaddress
import trusted

log = logging.getLogger("dispatcher")


def _validated_cidr(value: str, varname: str) -> str | None:
    """Strictly parse and privacy-check a boundary CIDR from the environment.

    CLIENT_VLAN and UDM_TUNNEL_CIDR are unconditionally included in every
    call to _pinnable_cidrs() — unlike a bad trusted.json entry, a bad value
    here is not inert, it changes what the whole box treats as "pin this
    source" on every single new flow. `strict=True` catches a host-bits typo
    such as 172.16.1.1/24: syntactically invalid, and without this check it
    would be silently swallowed by is_pinnable_source's own per-range
    try/except, pinning nothing with no signal that anything is wrong. The
    RFC1918 floor (the same one trusted.py applies to operator-supplied
    trusted ranges) catches the opposite mistake: 0.0.0.0/0 parses just fine
    under strict=True, and without this check would make every address on
    the internet pinnable.

    Logs one ERROR naming the variable and its value, and returns None so the
    caller drops the entry rather than pass through something that matches
    either nothing or everything.
    """
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except ValueError as e:
        log.error("%s=%r is not a valid CIDR (%s); excluding it from pinning",
                  varname, value, e)
        return None
    if not trusted.is_private(net):
        log.error("%s=%r is not a private (RFC1918) range; excluding it "
                  "from pinning", varname, value)
        return None
    return value


CLIENT_VLAN = _validated_cidr(
    os.environ.get("PROTEUS_CLIENT_VLAN_CIDR", "172.16.1.0/24"),
    "PROTEUS_CLIENT_VLAN_CIDR",
)
TRUSTED_FILE = os.environ.get("PROTEUS_TRUSTED_FILE", "/etc/proteus/trusted.json")
UDM_TUNNEL_CIDR = _validated_cidr(
    os.environ.get("PROTEUS_UDM_TUNNEL_CIDR", "10.99.99.0/30"),
    "PROTEUS_UDM_TUNNEL_CIDR",
)
MGMT_CIDR = os.environ.get("PROTEUS_MGMT_CIDR", "")


def _mgmt_cidr_is_valid(value: str) -> bool:
    """Whether PROTEUS_MGMT_CIDR is usable as trusted.load's validation
    boundary. Parsed permissively (host bits allowed) — the same way
    trusted.py itself treats this value: "172.20.0.119/24" is a normal way to
    write "the subnet this address is in", not a typo. Empty counts as
    invalid rather than "fall back to a default"; see the check below for why.
    """
    if not value:
        return False
    try:
        ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return False
    return True


# Three consumers of PROTEUS_MGMT_CIDR exist now (proteus-trusted-egress.sh,
# vpnns-up.sh, here) and they do not agree on what an unset value means: the
# reconcile script assumes 10.0.0.0/24, vpnns-up.sh passes the empty string
# straight through to trusted.py's weaker floor. Guessing a management
# subnet here would recreate exactly the silent-widening failure mode the
# mgmt/client overlap guards in trusted.py exist to close, so this fails
# closed instead and says so: an unset or unparseable value disables
# trusted-source pinning outright, loudly, rather than picking a default that
# might not match this box's actual network.
_MGMT_CIDR_VALID = _mgmt_cidr_is_valid(MGMT_CIDR)

# trusted.load(path, mgmt_cidr, client_cidr) only runs its full validate() —
# the client-VLAN-overlap and management-overlap guards — when BOTH guard
# args are not None; give it either one alone and it silently drops to the
# weaker shape-and-RFC1918-only floor. CLIENT_VLAN can be None here (an
# invalid PROTEUS_CLIENT_VLAN_CIDR, logged by _validated_cidr above), and
# passing that None straight through would hit exactly that floor — the same
# silent-widening failure mode the MGMT_CIDR gate above exists to close,
# just from the other guard. So both boundaries gate trusted-range loading,
# not just the management one: an unusable boundary must disable the
# feature, never quietly weaken what it checks.
_TRUSTED_LOAD_ENABLED = _MGMT_CIDR_VALID and CLIENT_VLAN is not None
if not _MGMT_CIDR_VALID:
    log.error(
        "trusted-source pinning disabled: PROTEUS_MGMT_CIDR=%r is unset or "
        "invalid, and the management subnet cannot be guessed", MGMT_CIDR)
elif CLIENT_VLAN is None:
    # PROTEUS_CLIENT_VLAN_CIDR's own parse/privacy failure was already logged
    # by _validated_cidr; this spells out the consequence for trusted-range
    # loading specifically, since without a valid client boundary
    # trusted.load cannot run the client-VLAN-overlap or management-overlap
    # guards at all.
    log.error(
        "trusted-source pinning disabled: PROTEUS_CLIENT_VLAN_CIDR is "
        "invalid, so trusted.load has no client-VLAN boundary to validate "
        "against")

_trusted_cache: tuple[tuple[int, int, int] | None, list[str]] = (None, [])


def _trusted_file_key() -> tuple[int, int, int] | None:
    """Identity of TRUSTED_FILE's current contents, for the reload cache.

    (inode, size, mtime_ns) rather than mtime alone: a mtime-preserving
    overwrite such as `cp -p` or `tar -xp` can replace the file's contents
    while leaving its mtime untouched, which would otherwise pin a stale
    trusted list until some later, unrelated edit finally moved the
    timestamp. Inode alone already catches an atomic replace (the
    write-then-rename the broker uses); size and mtime_ns are free to add
    alongside it and catch a same-inode, same-mtime overwrite too. None
    means the file cannot be stat'd (e.g. it does not exist).
    """
    try:
        st = os.stat(TRUSTED_FILE)
    except OSError:
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def _pinnable_cidrs() -> list[str]:
    """Client VLAN, the UDM tunnel, and whatever trusted.json lists right now.

    Re-read on file-identity change rather than at startup, so editing the
    list in the web UI takes effect on the next new flow instead of needing a
    dispatcher restart — a restart would be a far bigger disruption than the
    one stat call per new flow this costs. The tunnel subnet is always
    included (when it validated at import): if the UDM masquerades, every
    trusted host arrives as the tunnel address.

    Trusted-range loading is skipped entirely, with no stat call at all, when
    either guard boundary failed validation at import (logged once there,
    above) — this then returns only the boundaries below, exactly the
    pre-trusted-egress behaviour. Both boundaries gate this, not just
    PROTEUS_MGMT_CIDR: trusted.load only runs its full validate() when
    neither guard arg is None, so a None CLIENT_VLAN would otherwise make it
    silently fall back to the weaker floor instead of being disabled.

    This runs on the NFQUEUE callback path, once per new flow, so a failure
    here must degrade rather than propagate: an uncaught exception would abort
    handle() before the packet is verdicted, and trusted.load is documented to
    never raise but is still someone else's code reached through a file that an
    operator can hand-edit. If it does raise, keep serving the last good list
    (or the empty one, on a first-ever failure) instead of taking the whole
    dispatcher down over a bad or unreadable trusted.json.
    """
    global _trusted_cache
    boundaries = [c for c in (CLIENT_VLAN, UDM_TUNNEL_CIDR) if c is not None]
    if not _TRUSTED_LOAD_ENABLED:
        return boundaries
    key = _trusted_file_key()
    if key != _trusted_cache[0]:
        try:
            # Pass the guard subnets so a hand-edited trusted.json faces the
            # same rules the web UI enforces. Without them trusted.load drops
            # to a weaker floor, and the dispatcher is exactly the consumer
            # that must not.
            trusted_list = trusted.load(TRUSTED_FILE, MGMT_CIDR, CLIENT_VLAN)
        except Exception:
            log.exception("trusted.load failed; keeping previous trusted list")
            trusted_list = _trusted_cache[1]
        # `key` is cached even on the exception path above, not just on
        # success: otherwise a persistent failure (e.g. a permissions
        # problem) would retry trusted.load — and log.exception — on every
        # single new flow until the file's identity happens to change again.
        # One logged exception per distinct file state is enough; the
        # operator does not need it repeated at packet rate.
        _trusted_cache = (key, trusted_list)
    return boundaries + _trusted_cache[1]


# Source-pin TTL: was hard-coded only in etc/nftables.conf's `timeout 6h` on
# the source_pin map; now set explicitly per-element on insert (see
# _nft_source_pin_insert) so PROTEUS_PIN_TTL_S actually takes effect without
# an nftables.conf reload. Default matches the prior hard-coded 6h.
PIN_TTL_S = int(os.environ.get("PROTEUS_PIN_TTL_S", "21600"))
NFT_TABLE_FAMILY = "inet"
NFT_TABLE = "filter"
NFT_MAP = "vpn_dispatch"
NFT_SOURCE_PIN_MAP = "source_pin"

# How long a per-slot load snapshot may be reused before it is re-read from
# nft. pick() runs on the NFQUEUE callback path, once per NEW FLOW, and
# vpn_dispatch is unbounded — one entry per destination address, held for 12h.
# Listing it per flow would put a subprocess and a large JSON parse in front of
# every new connection the live client VLAN makes, with the 2s nft timeout as
# the only ceiling. pick() needs relative load, not an exact census, and
# inserts and evictions adjust the cached numbers as they happen, so a couple
# of seconds of staleness cannot meaningfully misplace an assignment.
LOAD_CACHE_TTL_S = 2.0
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
        # Cached per-map, per-mark entry counts and the monotonic time they
        # were last read from nft. Its own lock again: the NFQUEUE callback
        # refreshes it and the janitor thread adjusts it, and neither may have
        # to wait on the instance-list lock — nor hold any lock across an nft
        # subprocess — to do so.
        self._load_lock = threading.Lock()
        self._load: dict[str, dict[int, int]] = {
            NFT_SOURCE_PIN_MAP: {},
            NFT_MAP: {},
        }
        self._load_at = float("-inf")
        # Set by the SIGHUP handler, consumed at the top of pick() and
        # janitor_once(). The handler runs on the main thread between two
        # bytecodes of whatever that thread is doing, which includes pick()'s
        # short `with self._lock` block. A handler that called reload()
        # directly would then block on that same (non-reentrant) lock and hang
        # the daemon: every new client flow stuck in NFQUEUE, forever. The
        # window is a few bytecodes now that no nft call runs under the lock,
        # but it is not zero. Reproduced in tests/dispatcher_daemon_test.py.
        #
        # A plain bool, deliberately not a threading.Event: Event.set() and
        # Event.clear() both take the Event's internal lock, so a handler
        # calling set() while the main thread sat inside clear() would hang
        # in exactly the same way. A single attribute store needs no lock
        # under the GIL.
        self._reload_pending = False
        # Serialises _apply_pending_reload between the janitor thread and the
        # NFQUEUE callback. Only ever taken there: the signal handler must
        # never touch it (it runs on the main thread, which may be holding it).
        self._reload_lock = threading.Lock()
        self.reload()

    def request_reload(self) -> None:
        """Signal-handler-safe: one attribute store. No I/O, no locks."""
        self._reload_pending = True

    def _apply_pending_reload(self) -> None:
        # The janitor thread and the NFQUEUE callback both get here, and two
        # reloads running at once were last-writer-wins: the one that read the
        # state files first could store its list second, putting an older
        # list back over a newer one until the next SIGHUP. So the check, the
        # clear and the reload happen as one step under _reload_lock.
        # Clear before reloading: a SIGHUP that lands after the clear sets the
        # flag again and costs one redundant reload, never a missed one.
        # The unlocked read first keeps the lock off the per-flow path when
        # nothing is pending. The price: a pick() that arrives while the
        # janitor is mid-reload (flag already cleared) does not wait for it,
        # and uses the previous list for that one decision.
        if not self._reload_pending:
            return
        with self._reload_lock:
            if self._reload_pending:
                self._reload_pending = False
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

    def _load_counts(self, map_name: str) -> dict[int, int]:
        """Per-slot entry count for ONE dispatch map, from a short-lived cache.

        The two maps are never mixed, because their entries are not the same
        unit: source_pin counts pinned HOSTS (a handful per slot, one per
        client), vpn_dispatch counts pinned DESTINATIONS (unbounded — one per
        address anything behind the tunnel talks to). Summing them would let a
        slot carrying trusted traffic accumulate thousands of destination
        entries, look permanently most-loaded next to a slot holding four
        client pins, and stop receiving client pins altogether; the ordering
        would track destination churn rather than load. So each decision is
        balanced against the map it will land in — see pick().

        A map nft could not list counts as `{}`, which pick_distributed reads
        as "no load information" and answers with pure best-score: the same
        graceful degradation as before this cache existed.

        Every nft call here happens with no lock held. This runs on the NFQUEUE
        callback path, and holding a lock across a subprocess (bounded at 2s,
        but 2s is already a bad outcome for new-flow dispatch) would stall the
        janitor thread behind it as well.
        """
        now = time.monotonic()
        with self._load_lock:
            if now - self._load_at < LOAD_CACHE_TTL_S:
                return dict(self._load[map_name])
            # Claim the refresh before dropping the lock, so a burst of new
            # flows costs one nft read rather than one per packet. Concurrent
            # callers meanwhile keep the previous counts, which is the point of
            # the cache.
            self._load_at = now

        fresh = {
            NFT_SOURCE_PIN_MAP: _count_marks(_nft_list_source_pin()),
            NFT_MAP: _count_marks(_nft_list_vpn_dispatch()),
        }
        with self._load_lock:
            # Wholesale replacement: any adjustment made during the read above
            # is discarded, which is correct — nft is the authority, and that
            # is also what stops _load_adjust's drift accumulating.
            self._load = fresh
            return dict(fresh[map_name])

    def _load_adjust(self, map_name: str, mark: int, delta: int) -> None:
        """Fold a map change we just made into the cached counts.

        Without this, every new flow inside one cache window would read the
        same numbers and pile onto the same slot — exactly the behaviour
        pick_distributed exists to avoid. Small drift is possible (an insert
        that silently hit an existing key still counts as one) and is bounded
        by the next refresh, which replaces the counts wholesale from nft.
        """
        with self._load_lock:
            counts = self._load[map_name]
            updated = counts.get(mark, 0) + delta
            if updated > 0:
                counts[mark] = updated
            else:
                counts.pop(mark, None)

    def pick(self, load_map: str = NFT_SOURCE_PIN_MAP) -> tuple[str, int] | None:
        """Choose a slot for a new assignment, balanced within one map.

        `load_map` names the map the assignment is about to land in —
        source_pin for a client-VLAN host, vpn_dispatch for a trusted
        destination — and only that map's counts decide the balance, because
        the two count different things (see _load_counts). The default keeps
        the client-VLAN path reading exactly the numbers it always has.
        """
        self._apply_pending_reload()
        with self._lock:
            instances = list(self._instances)
        if not instances:
            return None

        # 1. Distribute new assignments across the good slots (fresh, non-
        #    degraded, within SPREAD_BAND of the best), least-loaded first.
        #    Spreads bandwidth and hands out distinct exit IPs instead of
        #    piling everything onto the single top-scored slot.
        chosen = pick_distributed(
            instances, HEALTH_DIR, self._load_counts(load_map),
            now=int(time.time()),
        )
        if chosen is not None:
            return chosen

        # 2. No fresh scores yet — fall back to today's healthy random.
        healthy = [(n, m) for (n, m) in instances if _is_healthy(n)]
        if healthy:
            return random.choice(healthy)

        # 3. Everything degraded — log loudly, ride a known-bad slot.
        log.warning(
            "all %d instance(s) DEGRADED; falling back to full pool",
            len(instances),
        )
        return random.choice(instances)

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

        # Which map this assignment lands in decides which map's load balances
        # it. A tunnel source gets a destination entry only (the UDM
        # masquerades — see below), so it is balanced against the other
        # destinations; a client host gets a source pin, so it is balanced
        # against the other pinned hosts, exactly as it always was.
        tunnel_src = is_udm_tunnel_source(src, UDM_TUNNEL_CIDR)
        choice = self.pick(NFT_MAP if tunnel_src else NFT_SOURCE_PIN_MAP)
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

        # Record the destination always; pin the source only when the source
        # actually identifies a host. Only real client-VLAN/trusted hosts get a
        # pin — a stray 0.0.0.0/off-range packet shouldn't create a junk one,
        # and neither should the UDM tunnel's NATed address (below). On insert
        # failure we still mark+accept. The verdict's mark is what carries the
        # rest of THIS flow: chain prerouting_ctsave copies it into conntrack
        # and prerouting_mangle restores it on every later packet. Do not rely
        # on later packets re-entering NFQUEUE: the queue rule is `ct state
        # new`, so an established TCP flow never comes back here. A failed
        # insert only costs the NEXT flow to that source or destination a
        # fresh pick.
        if tunnel_src:
            # Trusted traffic out of the UDM tunnel: the router masquerades, so
            # `src` is the tunnel address for every trusted host alike. The
            # ruleset deliberately skips @source_pin for wg-udm so these flows
            # dispatch per destination; writing a pin here anyway would shadow
            # that destination rule for the whole trusted VLAN at once and
            # silently restore the single-shared-exit bug. Destination only.
            log.debug("tunnel source %s: destination-only dispatch "
                      "(dst=%s -> %s)", src, dest, name)
        elif is_pinnable_source(src, _pinnable_cidrs()):
            if _nft_source_pin_insert(src, mark):
                self._load_adjust(NFT_SOURCE_PIN_MAP, mark, 1)
            else:
                log.error("source_pin insert failed (0x%x)", mark)
                log.debug("source_pin insert failed for %s -> %s (0x%x)", src, name, mark)
        else:
            log.debug("not pinning untrusted source %s (dst=%s -> %s)", src, dest, name)
        if _nft_map_insert(dest, mark):
            self._load_adjust(NFT_MAP, mark, 1)
        else:
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
        """One pass: evict map entries whose mark belongs to a degraded slot,
        then publish a status snapshot for the web UI."""
        self._apply_pending_reload()
        with self._lock:
            instances = list(self._instances)
        self._evict_degraded_pins(instances)
        self._publish_snapshot(instances)

    def _evict_degraded_pins(self, instances: list[tuple[str, int]]) -> None:
        """Drop entries pointing at a degraded slot from BOTH dispatch maps.

        source_pin is the client VLAN's path. vpn_dispatch is the trusted
        VLAN's PRIMARY path — the UDM masquerades, so tunnel traffic dispatches
        on destination (see prerouting_mangle rule 2) — and nothing else ever
        rewrites those entries, so evicting only source pins would strand every
        trusted destination on a dead exit for the map's full 12h timeout.
        Removing the entry sends the next packet for that key back through the
        NFQUEUE, where pick() chooses a healthy slot.

        Rotation deliberately needs none of this: rotate-slot.sh replaces the
        WireGuard endpoint inside a slot's namespace and never touches the
        slot's fwmark or routing table (vpnns-up.sh derives FWMARK from the
        slot index, so it is stable across a rotation), which is why an
        existing mark keeps routing correctly into the same, now-rotated
        namespace. Only degradation makes a mark worth dropping.
        """
        bad_marks = degraded_marks(instances, HEALTH_DIR)
        if not bad_marks:
            return
        # Reverse-lookup mark -> name for log messages.
        name_by_mark = {m: n for n, m in instances}
        evicted = 0
        for kind, map_name, entries, remove in (
            ("pin", NFT_SOURCE_PIN_MAP, _nft_list_source_pin, _nft_source_pin_remove),
            ("dest", NFT_MAP, _nft_list_vpn_dispatch, _nft_vpn_dispatch_remove),
        ):
            listed = entries()
            if listed is None:
                # This map couldn't be read (nft error, already logged); the
                # other one is still worth sweeping.
                continue
            for key, mark in listed:
                if mark in bad_marks and remove(key):
                    evicted += 1
                    # Keep the cached load in step, so picks made before the
                    # next refresh see the freed capacity.
                    self._load_adjust(map_name, mark, -1)
                    # Client/destination IPs -> DEBUG only.
                    log.debug("evicted %s %s -> %s (degraded)", kind, key,
                              name_by_mark.get(mark, f"0x{mark:x}"))
        if evicted:
            log.info("janitor: evicted %d map entries to degraded slots", evicted)

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


def _count_marks(entries: list[tuple[str, int]] | None) -> dict[int, int]:
    """Per-mark entry count from one map listing. None (an nft error, already
    logged by the lister) becomes `{}` — "no load information" — rather than
    zeros, which would falsely read as "every slot idle"."""
    counts: dict[int, int] = {}
    for _key, mark in entries or ():
        counts[mark] = counts.get(mark, 0) + 1
    return counts


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


def _nft_map_elem_list(map_name: str) -> object | None:
    """Return the raw `elem` list from `nft -j list map ... <map_name>`, or
    None on error (timeout, nonzero exit, unparseable JSON).

    Both dispatch maps are ipv4_addr : mark, so one reader serves them.
    Shared by _nft_list_source_pin, _nft_list_source_pin_with_ttl and
    _nft_list_vpn_dispatch so there's one place that talks to nft."""
    try:
        r = subprocess.run(
            ["nft", "-j", "list", "map", NFT_TABLE_FAMILY, NFT_TABLE, map_name],
            capture_output=True, text=True, timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft list %s timed out", map_name)
        return None
    if r.returncode != 0:
        log.error("nft list %s failed (rc=%s)", map_name, r.returncode)
        log.debug("nft list %s failed: %s", map_name, r.stderr.strip())
        return None

    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.error("nft -j output not parseable: %s", e)
        return None

    for obj in doc.get("nftables", []):
        m = obj.get("map")
        if not m or m.get("name") != map_name:
            continue
        return m.get("elem")
    return []


def _nft_source_pin_elem_list() -> object | None:
    return _nft_map_elem_list(NFT_SOURCE_PIN_MAP)


def _nft_list_source_pin() -> list[tuple[str, int]] | None:
    """Return list of (src_ip, mark) currently in source_pin, or None on error."""
    elems = _nft_source_pin_elem_list()
    if elems is None:
        return None
    return parse_source_pin_elements(elems)


def _nft_list_vpn_dispatch() -> list[tuple[str, int]] | None:
    """Return list of (dest_ip, mark) currently in vpn_dispatch, or None on
    error. Same element shape as source_pin, so the same parser applies."""
    elems = _nft_map_elem_list(NFT_MAP)
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


def _nft_map_elem_remove(map_name: str, key: str) -> bool:
    elem = "{ %s }" % key
    try:
        r = subprocess.run(
            ["nft", "delete", "element", NFT_TABLE_FAMILY, NFT_TABLE,
             map_name, elem],
            capture_output=True, text=True, timeout=2,
        )
    except subprocess.TimeoutExpired:
        log.error("nft delete element (%s) timed out", map_name)
        log.debug("nft delete element (%s) timed out for %s", map_name, key)
        return False
    if r.returncode != 0:
        # Not an error if the element is already gone (raced with TTL eviction).
        if "No such file or directory" in (r.stderr or "") or \
           "does not exist" in (r.stderr or ""):
            return True
        log.error("nft delete element (%s) failed (rc=%s)", map_name, r.returncode)
        log.debug("nft delete element (%s) failed (%s): %s",
                  map_name, r.returncode, r.stderr.strip())
        return False
    return True


def _nft_source_pin_remove(src_ip: str) -> bool:
    return _nft_map_elem_remove(NFT_SOURCE_PIN_MAP, src_ip)


def _nft_vpn_dispatch_remove(dest_ip: str) -> bool:
    return _nft_map_elem_remove(NFT_MAP, dest_ip)


def _install_signal_handlers(d: Dispatcher) -> None:
    """SIGHUP = re-read the instance list (rotate-slot.sh sends it after
    every promotion).

    Two rules, both load-bearing:

    1. The handler only sets a flag. Python runs it on the main thread at
       the next bytecode boundary, which can be inside pick() while
       self._lock is held. That window is short now (pick() copies the
       instance list under the lock and does its nft reads outside it), but
       a handler that takes the lock can still land in it, and then the
       daemon deadlocks against itself. A flag cannot.

    2. No SA_RESTART. The main thread spends its life in the netfilterqueue
       extension's C recv() loop, and Python installs handlers without
       SA_RESTART, so a SIGHUP makes that recv() fail with EINTR.
       netfilterqueue 1.0 and later (Debian 13 ships 1.1.0) then run the
       Python handler at once and resume the loop: the flag is set straight
       away, and the janitor applies the reload within JANITOR_INTERVAL even
       when no client opens a new flow. Releases before 1.0 leave the loop on
       EINTR instead; nfq.run() returns, main() returns 1 and Restart=
       on-failure brings the daemon back with the new list. Do not add
       siginterrupt(SIGHUP, False): with SA_RESTART the kernel resumes the
       recv(), the handler cannot run until the next queued packet, and on a
       quiet VLAN the reload (and its log line) waits for traffic.
    """
    signal.signal(signal.SIGHUP, lambda *_: d.request_reload())


def main() -> int:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    _setup_logging()

    d = Dispatcher()
    if not d._instances:
        log.error("no active VPN instances in %s; exiting", STATE_DIR)
        return 1

    _install_signal_handlers(d)

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
        return 0
    finally:
        nfq.unbind()
    # run() only returns on a recv() error (see _install_signal_handlers).
    # That is a failure, not a clean stop: exit non-zero so systemd's
    # Restart=on-failure actually restarts us instead of leaving every new
    # client flow to fall through the NFQUEUE bypass into the forward drop.
    log.error("NFQUEUE receive loop exited unexpectedly; exiting for restart")
    return 1


if __name__ == "__main__":
    sys.exit(main())
