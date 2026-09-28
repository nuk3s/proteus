"""Tests for dispatcher.py's trusted-source pinning wiring.

dispatcher.py imports netfilterqueue and scapy.layers.inet at module load
time for their real NFQUEUE/packet-parsing classes. Neither package is
installed on a dev box, so both are stubbed out in sys.modules before
dispatcher.py is imported. The handle() tests at the bottom need a working
packet parse, so they rebind `dispatcher.IP` to a two-line fake over a
"src>dst" payload — enough for code that only reads `.src` and `.dst`, and it
keeps the stub in sys.modules doing what it does for every other test here.

CLIENT_VLAN / UDM_TUNNEL_CIDR / MGMT_CIDR are validated once, at dispatcher.py
import time — so exercising different values means importing a fresh copy of
the module per test (via `import_dispatcher`), not monkeypatching its
already-computed globals afterward.
"""
from __future__ import annotations

import logging
import os
import sys
import time
import types
from pathlib import Path

import pytest

BIN = Path(__file__).resolve().parent.parent / "etc" / "proteus" / "bin"


def _install_stub_modules() -> None:
    if "netfilterqueue" not in sys.modules:
        stub = types.ModuleType("netfilterqueue")
        stub.NetfilterQueue = object
        sys.modules["netfilterqueue"] = stub
    if "scapy.layers.inet" not in sys.modules:
        scapy = types.ModuleType("scapy")
        scapy_layers = types.ModuleType("scapy.layers")
        scapy_inet = types.ModuleType("scapy.layers.inet")
        scapy_inet.IP = object
        sys.modules["scapy"] = scapy
        sys.modules["scapy.layers"] = scapy_layers
        sys.modules["scapy.layers.inet"] = scapy_inet


@pytest.fixture
def import_dispatcher(monkeypatch):
    """Returns a function that (re)imports dispatcher.py with a given env.

    Clears the four PROTEUS_* variables dispatcher.py reads at import time
    before setting the ones passed in, so a leftover value from a prior test
    (or the real environment) can't leak in. `monkeypatch` restores the real
    os.environ automatically at teardown.
    """
    def _import(**env):
        for key in ("PROTEUS_MGMT_CIDR", "PROTEUS_CLIENT_VLAN_CIDR",
                    "PROTEUS_UDM_TUNNEL_CIDR", "PROTEUS_TRUSTED_FILE"):
            monkeypatch.delenv(key, raising=False)
        for key, val in env.items():
            monkeypatch.setenv(key, val)
        _install_stub_modules()
        sys.modules.pop("dispatcher", None)
        import dispatcher
        return dispatcher

    yield _import
    sys.modules.pop("dispatcher", None)


def test_trusted_load_failure_keeps_previous_list_and_boundaries(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    trusted_file = tmp_path / "trusted.json"
    trusted_file.write_text('{"trusted": [{"cidr": "192.168.7.0/24"}]}')
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
        PROTEUS_TRUSTED_FILE=str(trusted_file),
    )
    first = dispatcher._pinnable_cidrs()
    assert set(first) == {"172.16.1.0/24", "10.99.99.0/30", "192.168.7.0/24"}

    # Change the file's identity so a reload is attempted, but make
    # trusted.load explode this time.
    trusted_file.write_text(
        '{"trusted": [{"cidr": "192.168.7.0/24"}, {"cidr": "10.44.0.0/24"}]}'
    )

    def _boom(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(dispatcher.trusted, "load", _boom)
    second = dispatcher._pinnable_cidrs()

    # Boundaries are always present; the trusted list falls back to the last
    # good one rather than the new (unreachable) content or an empty list.
    assert "172.16.1.0/24" in second
    assert "10.99.99.0/30" in second
    assert "192.168.7.0/24" in second
    assert "10.44.0.0/24" not in second


def test_empty_mgmt_cidr_disables_trusted_pinning_and_logs(
    tmp_path, import_dispatcher, caplog
) -> None:
    trusted_file = tmp_path / "trusted.json"
    trusted_file.write_text('{"trusted": [{"cidr": "192.168.7.0/24"}]}')
    caplog.set_level(logging.ERROR, logger="dispatcher")
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
        PROTEUS_TRUSTED_FILE=str(trusted_file),
    )
    assert dispatcher._pinnable_cidrs() == ["172.16.1.0/24", "10.99.99.0/30"]
    assert any("PROTEUS_MGMT_CIDR" in r.message for r in caplog.records), \
        "expected an ERROR naming PROTEUS_MGMT_CIDR when it is unset"


def test_unparseable_mgmt_cidr_disables_trusted_pinning_and_logs(
    tmp_path, import_dispatcher, caplog
) -> None:
    trusted_file = tmp_path / "trusted.json"
    trusted_file.write_text('{"trusted": [{"cidr": "192.168.7.0/24"}]}')
    caplog.set_level(logging.ERROR, logger="dispatcher")
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="not-a-cidr",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
        PROTEUS_TRUSTED_FILE=str(trusted_file),
    )
    assert dispatcher._pinnable_cidrs() == ["172.16.1.0/24", "10.99.99.0/30"]
    assert any("PROTEUS_MGMT_CIDR" in r.message for r in caplog.records)


def test_wide_open_client_vlan_does_not_pin_public_addresses(
    import_dispatcher, caplog
) -> None:
    """A 0.0.0.0/0 CLIENT_VLAN is syntactically a valid CIDR — strict parsing
    alone would accept it — so this must be caught by the RFC1918 floor, the
    same one trusted.py applies to operator-supplied trusted ranges."""
    caplog.set_level(logging.ERROR, logger="dispatcher")
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="0.0.0.0/0",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    assert dispatcher.CLIENT_VLAN is None
    assert not dispatcher.is_pinnable_source("8.8.8.8", dispatcher._pinnable_cidrs())
    assert any("PROTEUS_CLIENT_VLAN_CIDR" in r.message for r in caplog.records)


def test_host_bits_typo_in_client_vlan_excluded_and_logged(
    import_dispatcher, caplog
) -> None:
    caplog.set_level(logging.ERROR, logger="dispatcher")
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.1/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    assert dispatcher.CLIENT_VLAN is None
    assert dispatcher._pinnable_cidrs() == ["10.99.99.0/30"]
    assert any("PROTEUS_CLIENT_VLAN_CIDR" in r.message for r in caplog.records)


def test_invalid_client_vlan_disables_trusted_loading_rather_than_weakening_it(
    tmp_path, import_dispatcher, caplog
) -> None:
    """Reviewer's repro: an invalid CLIENT_VLAN (host bits, so rejected) must
    not make trusted.load fall back to its weaker shape-and-RFC1918-only
    floor. That floor skips the management-overlap guard, so a trusted.json
    naming the management subnet — something full validate() would reject
    outright — would otherwise sail through and become pinnable, handing a
    tunnel-side host a route to the box's own management address."""
    trusted_file = tmp_path / "trusted.json"
    trusted_file.write_text('{"trusted": [{"cidr": "10.0.0.0/24"}]}')
    caplog.set_level(logging.ERROR, logger="dispatcher")
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.1/24",  # host bits -> rejected
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
        PROTEUS_TRUSTED_FILE=str(trusted_file),
    )
    assert dispatcher.CLIENT_VLAN is None
    cidrs = dispatcher._pinnable_cidrs()
    assert "10.0.0.0/24" not in cidrs
    assert cidrs == ["10.99.99.0/30"]
    assert not dispatcher.is_pinnable_source("172.20.0.50", cidrs)
    assert any("PROTEUS_CLIENT_VLAN_CIDR" in r.message for r in caplog.records)


def test_trusted_cache_reloads_on_replace_not_on_touch(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    trusted_file = tmp_path / "trusted.json"
    trusted_file.write_text('{"trusted": [{"cidr": "192.168.7.0/24"}]}')
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
        PROTEUS_TRUSTED_FILE=str(trusted_file),
    )
    real_load = dispatcher.trusted.load
    calls = []

    def _counting_load(*a, **k):
        calls.append(1)
        return real_load(*a, **k)

    monkeypatch.setattr(dispatcher.trusted, "load", _counting_load)

    first = dispatcher._pinnable_cidrs()
    assert len(calls) == 1
    assert "192.168.7.0/24" in first

    # Untouched: identical (inode, size, mtime_ns) -> no reload.
    dispatcher._pinnable_cidrs()
    assert len(calls) == 1

    # A mtime-preserving overwrite, as `cp -p` or `tar -xp` would produce:
    # written in place (same inode), content and size change, and the mtime
    # is pinned back to its old value. A cache keyed on st_mtime alone would
    # miss this; (inode, size, mtime_ns) does not, because size differs.
    before = os.stat(trusted_file)
    trusted_file.write_text(
        '{"trusted": [{"cidr": "192.168.7.0/24"}, {"cidr": "10.44.0.0/24"}]}'
    )
    os.utime(trusted_file, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert os.stat(trusted_file).st_mtime_ns == before.st_mtime_ns  # sanity
    assert os.stat(trusted_file).st_ino == before.st_ino            # sanity

    second = dispatcher._pinnable_cidrs()
    assert len(calls) == 2
    assert "10.44.0.0/24" in second


# --- trusted traffic dispatches per destination, not per NATed source --------
#
# The UDM masquerades, so every trusted host arrives as the single tunnel
# address. The ruleset skips @source_pin for wg-udm and dispatches those flows
# on destination; the dispatcher has to hold up the writer's half of that deal.
# A source pin on the tunnel address is consulted BEFORE @vpn_dispatch, so one
# stray pin puts the whole trusted VLAN back on one exit — silently, since
# traffic keeps flowing.


class _FakeIP:
    """Stands in for scapy's IP(): parses the fake "src>dst" payload below."""

    def __init__(self, payload: bytes) -> None:
        self.src, _, self.dst = payload.decode().partition(">")


class _FakePacket:
    """Minimal stand-in for netfilterqueue's packet object."""

    def __init__(self, src: str, dst: str) -> None:
        self._payload = f"{src}>{dst}".encode()
        self.mark: int | None = None
        self.verdict: str | None = None

    def get_payload(self) -> bytes:
        return self._payload

    def set_mark(self, mark: int) -> None:
        self.mark = mark

    def accept(self) -> None:
        self.verdict = "accept"

    def drop(self) -> None:
        self.verdict = "drop"


def _dispatch_one(dispatcher, monkeypatch, tmp_path, src: str, dst: str):
    """Run one packet through Dispatcher.handle().

    Both nft maps are stubbed to record instead of shelling out, and STATE_DIR
    / HEALTH_DIR are pointed at empty temp directories so the pick is the
    single instance we install rather than whatever this machine is running.

    Returns (pins, dests, pkt, dispatcher_instance, nft_list_calls) — the last
    two so the caching tests can see what the run cost.
    """
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(tmp_path / "health"))
    monkeypatch.setattr(dispatcher, "IP", _FakeIP)
    d, calls = _make_dispatcher(dispatcher, monkeypatch, tmp_path)

    pins: list[tuple[str, int]] = []
    dests: list[tuple[str, int]] = []
    monkeypatch.setattr(dispatcher, "_nft_source_pin_insert",
                        lambda ip, mark: pins.append((ip, mark)) or dispatcher.INSERT_ADDED)
    monkeypatch.setattr(dispatcher, "_nft_map_insert",
                        lambda ip, mark: dests.append((ip, mark)) or dispatcher.INSERT_ADDED)

    d._instances = [("proton-1", 0x1)]
    pkt = _FakePacket(src, dst)
    d.handle(pkt)
    return pins, dests, pkt, d, calls


def test_tunnel_source_writes_only_the_destination_entry(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    pins, dests, pkt, _d, _calls = _dispatch_one(
        dispatcher, monkeypatch, tmp_path, "10.99.99.2", "203.0.113.10")

    assert pins == [], "a pin on the NATed tunnel address would shadow @vpn_dispatch"
    assert dests == [("203.0.113.10", 0x1)]
    assert (pkt.mark, pkt.verdict) == (0x1, "accept")


def test_tunnel_source_is_not_pinned_even_when_listed_as_trusted(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """The tunnel subnet is always a pinnable CIDR (it is a boundary, and an
    operator can also name it in trusted.json), so "is it pinnable" is the
    wrong question and cannot be the guard. The tunnel check has to win."""
    trusted_file = tmp_path / "trusted.json"
    trusted_file.write_text('{"trusted": [{"cidr": "10.99.99.0/30"}]}')
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
        PROTEUS_TRUSTED_FILE=str(trusted_file),
    )
    assert dispatcher.is_pinnable_source("10.99.99.2", dispatcher._pinnable_cidrs())
    pins, dests, _pkt, _d, _calls = _dispatch_one(
        dispatcher, monkeypatch, tmp_path, "10.99.99.2", "203.0.113.10")
    assert pins == []
    assert dests == [("203.0.113.10", 0x1)]


def test_client_vlan_source_still_gets_a_source_pin(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """No regression for the 16 live client-VLAN hosts: they arrive with real
    per-host addresses and must keep per-source pinning."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    pins, dests, pkt, _d, _calls = _dispatch_one(
        dispatcher, monkeypatch, tmp_path, "172.16.1.50", "203.0.113.10")

    assert pins == [("172.16.1.50", 0x1)]
    assert dests == [("203.0.113.10", 0x1)]
    assert (pkt.mark, pkt.verdict) == (0x1, "accept")


# --- load accounting: one map per decision, and off the hot path ------------
#
# The two maps count different things. source_pin holds pinned HOSTS — 16 on
# this box. vpn_dispatch holds pinned DESTINATIONS — unbounded, one per address
# anything behind the tunnel talks to, held for 12h. Comparing one against the
# other makes any slot touched by trusted traffic look permanently most-loaded,
# so it stops receiving client pins and the ranking follows destination churn
# instead of load.


def _make_dispatcher(dispatcher, monkeypatch, tmp_path, *, pins=(), dests=()):
    """A Dispatcher with both nft listers stubbed, counting calls.

    Returns (dispatcher_instance, calls) where `calls` counts nft list calls
    per map — that is how the hot-path caching is asserted.
    """
    calls = {"source_pin": 0, "vpn_dispatch": 0}

    def _list_pins():
        calls["source_pin"] += 1
        return None if pins is None else list(pins)

    def _list_dests():
        calls["vpn_dispatch"] += 1
        return None if dests is None else list(dests)

    monkeypatch.setattr(dispatcher, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(dispatcher, "_nft_list_source_pin", _list_pins)
    monkeypatch.setattr(dispatcher, "_nft_list_vpn_dispatch", _list_dests)
    return dispatcher.Dispatcher(), calls


def test_load_counts_are_per_map_and_never_summed(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    d, _calls = _make_dispatcher(
        dispatcher, monkeypatch, tmp_path,
        pins=[("172.16.1.50", 0x1), ("172.16.1.51", 0x2)],
        dests=[("203.0.113.10", 0x2), ("203.0.113.11", 0x2), ("198.51.100.5", 0x3)],
    )
    assert d._load_counts("source_pin") == {0x1: 1, 0x2: 1}
    assert d._load_counts("vpn_dispatch") == {0x2: 2, 0x3: 1}


def test_load_counts_are_empty_for_a_map_nft_cannot_list(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """A lister returns None on an nft error. That map must read as "no load
    information" — pick_distributed then falls back to pure best-score, the
    behaviour that predates any of this — and the other map must still work."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    d, _calls = _make_dispatcher(
        dispatcher, monkeypatch, tmp_path,
        pins=None, dests=[("203.0.113.10", 0x2)],
    )
    assert d._load_counts("source_pin") == {}
    assert d._load_counts("vpn_dispatch") == {0x2: 1}


def test_client_picks_ignore_destination_load(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """A slot buried under trusted destination entries must NOT thereby repel
    new client pins. proton-1 holds 200 destinations and zero pins; the client
    decision balances on source_pin, where proton-2 is the loaded one."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    health = tmp_path / "health"
    health.mkdir()
    now = int(time.time())
    for slot in ("proton-1", "proton-2"):
        (health / f"{slot}.state").write_text(
            f"STATUS=ok\nCOMPOSITE_SCORE=100.0\nSCORE_UPDATED_AT={now}\n")
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(health))
    d, _calls = _make_dispatcher(
        dispatcher, monkeypatch, tmp_path,
        pins=[("172.16.1.50", 0x2)],
        dests=[(f"203.0.113.{i}", 0x1) for i in range(200)],
    )
    d._instances = [("proton-1", 0x1), ("proton-2", 0x2)]
    assert d.pick(dispatcher.NFT_SOURCE_PIN_MAP) == ("proton-1", 0x1)


def test_client_picks_balance_exactly_as_they_did_on_source_pin_alone(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """The pre-existing client-VLAN path must be untouched: same instances,
    same scores, same source pins -> same choice, whatever vpn_dispatch holds.
    Asserted against pick_distributed called directly with source_pin counts,
    which is literally what the code did before trusted egress existed."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    health = tmp_path / "health"
    health.mkdir()
    now = int(time.time())
    for slot, score in (("proton-1", 120.0), ("proton-2", 100.0), ("proton-3", 95.0)):
        (health / f"{slot}.state").write_text(
            f"STATUS=ok\nCOMPOSITE_SCORE={score}\nSCORE_UPDATED_AT={now}\n")
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(health))
    instances = [("proton-1", 0x1), ("proton-2", 0x2), ("proton-3", 0x3)]
    source_pins = [("172.16.1.50", 0x1), ("172.16.1.51", 0x1), ("172.16.1.52", 0x2)]
    d, _calls = _make_dispatcher(
        dispatcher, monkeypatch, tmp_path,
        pins=source_pins,
        dests=[(f"198.51.100.{i}", 0x3) for i in range(50)],
    )
    d._instances = list(instances)

    legacy = dispatcher.pick_distributed(
        instances, str(health), {0x1: 2, 0x2: 1}, now=now)
    assert d.pick(dispatcher.NFT_SOURCE_PIN_MAP) == legacy == ("proton-3", 0x3)


def test_trusted_picks_balance_on_destination_load(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """The mirror image: a trusted decision ignores source pins and spreads
    across the slots holding fewest destinations."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    health = tmp_path / "health"
    health.mkdir()
    now = int(time.time())
    for slot in ("proton-1", "proton-2"):
        (health / f"{slot}.state").write_text(
            f"STATUS=ok\nCOMPOSITE_SCORE=100.0\nSCORE_UPDATED_AT={now}\n")
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(health))
    d, _calls = _make_dispatcher(
        dispatcher, monkeypatch, tmp_path,
        pins=[("172.16.1.50", 0x2), ("172.16.1.51", 0x2)],
        dests=[("203.0.113.10", 0x1)],
    )
    d._instances = [("proton-1", 0x1), ("proton-2", 0x2)]
    assert d.pick(dispatcher.NFT_MAP) == ("proton-2", 0x2)


def test_load_counts_are_cached_off_the_new_flow_path(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """pick() runs per new flow and vpn_dispatch is unbounded, so a burst of
    flows must not mean a subprocess and a large JSON parse each."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    d, calls = _make_dispatcher(dispatcher, monkeypatch, tmp_path,
                                pins=[("172.16.1.50", 0x1)])
    for _ in range(50):
        d._load_counts("source_pin")
        d._load_counts("vpn_dispatch")
    assert calls == {"source_pin": 1, "vpn_dispatch": 1}

    # ...and the cache does expire, so a slot freed by something outside this
    # process is picked up rather than trusted forever.
    monkeypatch.setattr(dispatcher, "LOAD_CACHE_TTL_S", 0.0)
    d._load_counts("source_pin")
    assert calls == {"source_pin": 2, "vpn_dispatch": 2}


def test_insert_adjusts_the_cached_counts_within_one_window(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """Inside a cache window a burst of new flows would otherwise all read the
    same numbers and pile onto one slot."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    pins, dests, _pkt, d, calls = _dispatch_one(
        dispatcher, monkeypatch, tmp_path, "172.16.1.50", "203.0.113.10")
    assert pins and dests  # sanity: this packet did write both entries
    assert d._load_counts("source_pin") == {0x1: 1}
    assert d._load_counts("vpn_dispatch") == {0x1: 1}
    assert calls == {"source_pin": 1, "vpn_dispatch": 1}, \
        "the counts came from the insert, not from a second nft read"


def test_eviction_adjusts_the_cached_counts(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """A slot freed by the janitor must look free to the next pick, not stay
    loaded until the cache happens to expire."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    health = tmp_path / "health"
    health.mkdir()
    (health / "proton-1.state").write_text("STATUS=degraded\n")
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(health))
    d, calls = _make_dispatcher(
        dispatcher, monkeypatch, tmp_path,
        pins=[("172.16.1.50", 0x1)],
        dests=[("203.0.113.10", 0x1), ("198.51.100.5", 0x2)],
    )
    monkeypatch.setattr(dispatcher, "_nft_source_pin_remove", lambda ip: True)
    monkeypatch.setattr(dispatcher, "_nft_vpn_dispatch_remove", lambda ip: True)

    assert d._load_counts("vpn_dispatch") == {0x1: 1, 0x2: 1}
    d._evict_pins([("proton-1", 0x1), ("proton-2", 0x2)])
    assert d._load_counts("source_pin") == {}
    assert d._load_counts("vpn_dispatch") == {0x2: 1}


def test_evict_degraded_clears_both_maps(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """vpn_dispatch is now the trusted VLAN's PRIMARY path, and nothing else
    rewrites it — evicting only source pins would strand trusted destinations
    on a dead exit for the map's full 12h timeout."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    health = tmp_path / "health"
    health.mkdir()
    (health / "proton-1.state").write_text("STATUS=degraded\n")
    (health / "proton-2.state").write_text("STATUS=ok\n")
    monkeypatch.setattr(dispatcher, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(health))
    monkeypatch.setattr(dispatcher, "_nft_list_source_pin",
                        lambda: [("172.16.1.50", 0x1), ("172.16.1.51", 0x2)])
    monkeypatch.setattr(dispatcher, "_nft_list_vpn_dispatch",
                        lambda: [("203.0.113.10", 0x1), ("203.0.113.11", 0x2)])

    dropped_pins: list[str] = []
    dropped_dests: list[str] = []
    monkeypatch.setattr(dispatcher, "_nft_source_pin_remove",
                        lambda ip: bool(dropped_pins.append(ip)) or True)
    monkeypatch.setattr(dispatcher, "_nft_vpn_dispatch_remove",
                        lambda ip: bool(dropped_dests.append(ip)) or True)

    d = dispatcher.Dispatcher()
    d._evict_pins([("proton-1", 0x1), ("proton-2", 0x2)])

    assert dropped_pins == ["172.16.1.50"]
    assert dropped_dests == ["203.0.113.10"], \
        "the degraded slot's destination entries must go too"


def test_evict_leaves_everything_alone_when_no_slot_is_degraded(
    tmp_path, import_dispatcher, monkeypatch
) -> None:
    """A rotation is NOT a degradation: rotate-slot.sh swaps the endpoint
    inside the namespace and leaves the slot's fwmark and routing table
    untouched, so existing entries still route correctly and must survive."""
    dispatcher = import_dispatcher(
        PROTEUS_MGMT_CIDR="10.0.0.0/24",
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24",
        PROTEUS_UDM_TUNNEL_CIDR="10.99.99.0/30",
    )
    health = tmp_path / "health"
    health.mkdir()
    (health / "proton-1.state").write_text("STATUS=ok\n")
    monkeypatch.setattr(dispatcher, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(health))
    monkeypatch.setattr(dispatcher, "_nft_list_source_pin",
                        lambda: [("172.16.1.50", 0x1)])
    monkeypatch.setattr(dispatcher, "_nft_list_vpn_dispatch",
                        lambda: [("203.0.113.10", 0x1)])

    removed: list[str] = []
    monkeypatch.setattr(dispatcher, "_nft_source_pin_remove",
                        lambda ip: bool(removed.append(ip)) or True)
    monkeypatch.setattr(dispatcher, "_nft_vpn_dispatch_remove",
                        lambda ip: bool(removed.append(ip)) or True)

    d = dispatcher.Dispatcher()
    d._evict_pins([("proton-1", 0x1)])
    assert removed == []
