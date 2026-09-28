"""Tests for the dispatcher's map upkeep in etc/proteus/bin/dispatcher.py:

- the janitor drains the pins of a slot that has stopped or been removed,
  and nothing else;
- a new entry that clashes with one already in a map (nft keeps the old mark)
  is verdicted with the mark the map holds, not the one just picked.

nft itself is replaced by FakeNft below, a stand-in for the four commands the
dispatcher runs, answering the way nft 1.1.3 does (checked in a scratch
netns). That keeps the dispatcher's own subprocess and parsing code in the
test. The one test that needs the real nft runs it in `unshare -rn`.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

_BIN = Path(__file__).resolve().parent.parent / "etc" / "proteus" / "bin"
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))


def _stub_native_modules() -> None:
    try:
        import netfilterqueue  # noqa: F401
    except ImportError:
        sys.modules["netfilterqueue"] = types.SimpleNamespace(NetfilterQueue=object)
    try:
        from scapy.layers.inet import IP  # noqa: F401
    except ImportError:
        scapy = types.ModuleType("scapy")
        layers = types.ModuleType("scapy.layers")
        inet = types.ModuleType("scapy.layers.inet")
        inet.IP = object
        sys.modules["scapy"], sys.modules["scapy.layers"] = scapy, layers
        sys.modules["scapy.layers.inet"] = inet


_stub_native_modules()
import dispatcher  # noqa: E402


class FakeNft:
    """nft add/get/delete element and -j list map, for the two dispatch maps.

    A key already present with a different mark fails `add` with "File
    exists" and keeps the old mark; the same mark again succeeds. The clash
    tests depend on exactly that, so the fake models it."""

    def __init__(self, source_pin=(), vpn_dispatch=()) -> None:
        self.maps = {"source_pin": dict(source_pin),
                     "vpn_dispatch": dict(vpn_dispatch)}
        self.calls: list[list[str]] = []

    def run(self, argv, capture_output=True, text=True, timeout=None):
        self.calls.append(list(argv))
        ok = lambda out="": subprocess.CompletedProcess(argv, 0, out, "")  # noqa: E731
        err = lambda msg: subprocess.CompletedProcess(  # noqa: E731
            argv, 1, "", f"Error: Could not process rule: {msg}\n")
        if argv[:3] == ["nft", "-j", "list"]:
            name = argv[-1]
            elem = [[{"elem": {"val": k, "expires": 3600}}, m]
                    for k, m in self.maps[name].items()]
            return ok(json.dumps({"nftables": [
                {"metainfo": {"version": "1.1.3"}},
                {"map": {"family": "inet", "name": name, "table": "filter",
                         "type": "ipv4_addr", "map": "mark", "elem": elem}}]}))
        verb, name, spec = argv[1], argv[5], argv[6]
        m = re.fullmatch(r"\{ (\S+)(?: timeout \d+s)?(?: : 0x([0-9a-f]+))? \}", spec)
        assert m, f"unexpected element spec {spec!r}"
        key, mark = m.group(1), m.group(2)
        entries = self.maps[name]
        if verb == "add":
            mark = int(mark, 16)
            if key in entries and entries[key] != mark:
                return err("File exists")
            entries[key] = mark
            return ok()
        if key not in entries:
            return err("No such file or directory")
        if verb == "get":
            return ok(f"table inet filter {{\n\tmap {name} {{\n\t\ttype ipv4_addr : mark\n"
                      f"\t\telements = {{ {key} expires 59m59s : 0x{entries[key]:08x} }}\n"
                      f"\t}}\n}}\n")
        if verb == "delete":
            del entries[key]
            return ok()
        raise AssertionError(f"unexpected nft call {argv}")

    def verbs(self, verb: str) -> list[list[str]]:
        return [c for c in self.calls if c[1] == verb]


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A state dir, a health dir and a FakeNft wired into the dispatcher."""
    state = tmp_path / "state"
    health = tmp_path / "health"
    state.mkdir()
    health.mkdir()
    monkeypatch.setattr(dispatcher, "STATE_DIR", str(state))
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(health))
    monkeypatch.setattr(dispatcher, "write_snapshot", lambda snap: None)
    nft = FakeNft()
    monkeypatch.setattr(dispatcher, "subprocess", types.SimpleNamespace(
        run=nft.run, TimeoutExpired=subprocess.TimeoutExpired))
    b = types.SimpleNamespace(state=state, health=health, nft=nft)

    def up(name: str, mark: int) -> None:
        (state / f"{name}.state").write_text(f"INSTANCE={name}\nFWMARK=0x{mark:x}\n")

    def down(name: str) -> None:
        (state / f"{name}.state").unlink()

    b.up, b.down = up, down
    return b


# --- draining the pins of a stopped or removed slot --------------------------

def test_a_stopped_slot_is_drained_on_the_second_pass_not_the_first(box) -> None:
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    box.nft.maps["source_pin"].update({"172.16.1.50": 0x1, "172.16.1.51": 0x2})
    box.nft.maps["vpn_dispatch"].update({"203.0.113.10": 0x1, "203.0.113.11": 0x2})
    d = dispatcher.Dispatcher()
    d.janitor_once()                            # both slots up: the baseline pass

    box.down("proton-1")                        # vpnns-down.sh deleted its state file
    d.request_reload()                          # ... and sent the SIGHUP
    d.janitor_once()
    assert d._instances == [("proton-2", 0x2)], "stops picking the slot at once"
    assert box.nft.maps["source_pin"] == {"172.16.1.50": 0x1, "172.16.1.51": 0x2}, \
        "one pass without a state file proves nothing (a restart looks the same)"

    d.janitor_once()
    assert box.nft.maps["source_pin"] == {"172.16.1.51": 0x2}
    assert box.nft.maps["vpn_dispatch"] == {"203.0.113.11": 0x2}, \
        "trusted destinations on the stopped slot go too"


def test_a_restart_between_passes_drains_nothing(box) -> None:
    """`systemctl restart proteus-proton@proton-1`: a pass may catch the slot
    with no state file, but the next one finds it back."""
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    box.nft.maps["source_pin"]["172.16.1.50"] = 0x1
    d = dispatcher.Dispatcher()
    d.janitor_once()
    box.down("proton-1")
    d.janitor_once()                            # landed mid-restart
    box.up("proton-1", 0x1)
    d.janitor_once()
    d.janitor_once()
    assert box.nft.maps["source_pin"] == {"172.16.1.50": 0x1}
    assert box.nft.verbs("delete") == []


def test_a_slot_that_comes_back_without_a_sighup_is_picked_up(box) -> None:
    """vpnns-up.sh's SIGHUP went missing. The list (reloaded mid-restart)
    would lack the slot until some later rotation; the janitor's own re-read
    puts it back."""
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    d = dispatcher.Dispatcher()
    box.down("proton-1")
    d.request_reload()
    d.pick()                                    # a new flow applies the SIGHUP mid-restart
    assert d._instances == [("proton-2", 0x2)]
    box.up("proton-1", 0x1)                     # back, and nobody signals
    d.janitor_once()
    assert d._instances == [("proton-1", 0x1), ("proton-2", 0x2)]


def test_a_one_slot_restart_is_picked_up_by_the_next_flow(box, monkeypatch) -> None:
    """`systemctl restart proteus-proton@proton-1` on a one-slot box, with
    vpnns-up.sh's SIGHUP lost. vpnns-down.sh's SIGHUP empties the list, and
    every new flow is dropped until something reloads it. The next flow after
    the slot is back must find it, not wait up to JANITOR_INTERVAL for the
    janitor. (EMPTY_REREAD_S stands in for the seconds vpnns-up.sh takes.)"""
    monkeypatch.setattr(dispatcher, "EMPTY_REREAD_S", 0.0)
    box.up("proton-1", 0x1)
    d = dispatcher.Dispatcher()
    d.janitor_once()
    box.down("proton-1")                        # ExecStop: vpnns-down.sh ...
    d.request_reload()                          # ... and its SIGHUP
    assert d.pick() is None                     # a flow while the slot is down
    box.up("proton-1", 0x1)                     # ExecStart, no SIGHUP arrives
    assert d.pick() == ("proton-1", 0x1)


def test_restarting_every_slot_is_picked_up_by_the_next_flow(box, monkeypatch) -> None:
    monkeypatch.setattr(dispatcher, "EMPTY_REREAD_S", 0.0)
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    d = dispatcher.Dispatcher()
    box.down("proton-1")
    d.request_reload()
    box.down("proton-2")
    d.request_reload()
    assert d.pick() is None
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    assert d.pick() is not None
    assert d._instances == [("proton-1", 0x1), ("proton-2", 0x2)]


def test_an_empty_list_is_re_read_at_most_once_per_interval(box, monkeypatch) -> None:
    """Every new flow reaches pick() while the list is empty, so the re-read
    is rate-limited, and only happens when the list is empty."""
    reads = []
    real = dispatcher.load_state_files
    monkeypatch.setattr(dispatcher, "load_state_files",
                        lambda path: reads.append(path) or real(path))
    monkeypatch.setattr(dispatcher, "EMPTY_REREAD_S", 3600.0)
    d = dispatcher.Dispatcher()                 # no slot yet: an empty list
    box.up("proton-1", 0x1)
    for _ in range(5):
        assert d.pick() is None, "read at start-up, not again within the interval"
    assert reads == []

    monkeypatch.setattr(dispatcher, "EMPTY_REREAD_S", 0.0)
    assert d.pick() == ("proton-1", 0x1)
    assert len(reads) == 1, "one re-read, once the interval has passed"
    for _ in range(5):
        d.pick()
    assert len(reads) == 1, "a list with a slot in it is not re-read per flow"


def test_an_empty_read_drains_nothing_and_restarts_the_count(box) -> None:
    """The empty-list guard. Two empty reads in a row are still not two
    passes of evidence against any one slot, and a pass after an empty read
    starts the count again."""
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    box.nft.maps["source_pin"].update({"172.16.1.50": 0x1, "172.16.1.51": 0x2})
    d = dispatcher.Dispatcher()
    d.janitor_once()
    box.down("proton-1")
    box.down("proton-2")
    d.janitor_once()
    d.janitor_once()
    assert len(box.nft.maps["source_pin"]) == 2
    assert d._instances == [("proton-1", 0x1), ("proton-2", 0x2)], \
        "the janitor's own re-read does not adopt an empty list"

    box.up("proton-2", 0x2)                     # proton-1 stays gone
    d.janitor_once()                            # first pass with a usable read
    assert len(box.nft.maps["source_pin"]) == 2
    d.janitor_once()
    assert box.nft.maps["source_pin"] == {"172.16.1.51": 0x2}


def test_an_explicit_sighup_still_adopts_an_empty_list(box) -> None:
    """Unchanged: with every slot stopped, a SIGHUP empties the list and new
    flows are dropped rather than sent into a sentinel."""
    box.up("proton-1", 0x1)
    d = dispatcher.Dispatcher()
    box.down("proton-1")
    d.request_reload()
    d.janitor_once()
    assert d._instances == []


def test_marks_that_are_not_live_slot_marks_are_never_drained(box, monkeypatch) -> None:
    """Only the live slots' own marks can be drained. Everything else in the
    maps was not written by the dispatcher: the DNS tunnel's mark (claimed by
    its state file, or excluded by value when it is down), a staging copy's,
    another tunnel's that has a state file, zero, or a value added by hand."""
    monkeypatch.setattr(dispatcher, "_NOT_SLOT_MARKS", frozenset({0x6}))
    box.up("proton-1", 0x1)
    box.up("dns-6", 0x6)
    box.up("custom-7", 0x7)
    box.up("proton-1-s", 0x65)
    keep = {"172.16.1.60": 0x6, "172.16.1.61": 0x7, "172.16.1.62": 0x65,
            "172.16.1.63": 0x0, "172.16.1.64": 0x1234, "172.16.1.65": 0x1}
    box.nft.maps["source_pin"].update(keep)
    box.nft.maps["vpn_dispatch"].update(keep)
    d = dispatcher.Dispatcher()
    for _ in range(3):
        d.janitor_once()
    assert box.nft.maps["source_pin"] == keep
    box.down("dns-6")                           # a rotate-dns.sh swap that failed
    box.down("proton-1-s")                      # the rotation finished
    for _ in range(3):
        d.janitor_once()
    assert box.nft.maps["source_pin"] == keep
    assert box.nft.maps["vpn_dispatch"] == keep


def test_a_removed_slot_is_drained_after_a_dispatcher_restart(box) -> None:
    """The maps outlive the dispatcher. A slot removed while it was down
    (or just before it restarted) is not in anything the new process ever
    loaded, and its pins must still go."""
    box.up("proton-2", 0x2)
    box.nft.maps["source_pin"].update({"172.16.1.50": 0x5, "172.16.1.51": 0x2})
    d = dispatcher.Dispatcher()
    d.janitor_once()
    d.janitor_once()
    assert box.nft.maps["source_pin"] == {"172.16.1.51": 0x2}


def test_the_drain_frees_the_cached_load(box, monkeypatch) -> None:
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    box.nft.maps["source_pin"].update({"172.16.1.50": 0x1, "172.16.1.51": 0x2})
    d = dispatcher.Dispatcher()
    assert d._load_counts("source_pin") == {0x1: 1, 0x2: 1}
    d.janitor_once()
    box.down("proton-1")
    d.janitor_once()
    d.janitor_once()
    assert d._load_counts("source_pin") == {0x2: 1}


def test_the_drain_is_logged_with_the_marks(box, caplog) -> None:
    import logging
    caplog.set_level(logging.INFO, logger="dispatcher")
    box.up("proton-2", 0x2)
    box.nft.maps["source_pin"]["172.16.1.50"] = 0x3
    d = dispatcher.Dispatcher()
    d.janitor_once()
    d.janitor_once()
    msgs = [r.getMessage() for r in caplog.records]
    assert any("stopped or removed" in m and "0x3" in m for m in msgs), msgs
    assert not any("172.16.1.50" in m for m in msgs if "evicted" in m), \
        "client addresses stay at DEBUG"


# --- a map-key clash follows the entry already there --------------------------

class _FakeIP:
    def __init__(self, payload: bytes) -> None:
        self.src, _, self.dst = payload.decode().partition(">")


class _FakePacket:
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


@pytest.fixture
def one_slot(box, monkeypatch):
    """Two slots, but only proton-2 has a fresh score, so every pick is 0x2;
    the maps may already hold 0x1 for a key (another flow won the race)."""
    import time
    monkeypatch.setattr(dispatcher, "IP", _FakeIP)
    monkeypatch.setattr(dispatcher, "CLIENT_VLAN", "172.16.1.0/24")
    monkeypatch.setattr(dispatcher, "UDM_TUNNEL_CIDR", "10.99.99.0/30")
    monkeypatch.setattr(dispatcher, "_TRUSTED_LOAD_ENABLED", False)
    box.up("proton-1", 0x1)
    box.up("proton-2", 0x2)
    (box.health / "proton-2.state").write_text(
        f"STATUS=ok\nCOMPOSITE_SCORE=100\nSCORE_UPDATED_AT={int(time.time())}\n")
    d = dispatcher.Dispatcher()
    assert d.pick() == ("proton-2", 0x2)
    box.d = d

    def dispatch(src: str, dst: str) -> _FakePacket:
        pkt = _FakePacket(src, dst)
        d.handle(pkt)
        assert pkt.verdict == "accept"
        return pkt
    box.dispatch = dispatch
    return box


def test_a_pin_clash_verdicts_the_pinned_mark(one_slot) -> None:
    """A new client's second connection, queued before its first one's pin
    landed: the host keeps the exit it already has."""
    b = one_slot
    b.nft.maps["source_pin"]["172.16.1.50"] = 0x1
    before = b.d._load_counts("source_pin")
    pkt = b.dispatch("172.16.1.50", "203.0.113.10")
    assert pkt.mark == 0x1, "verdicted the picked 0x2 while the pin says 0x1"
    assert b.nft.maps["source_pin"]["172.16.1.50"] == 0x1
    assert b.nft.maps["vpn_dispatch"]["203.0.113.10"] == 0x1, \
        "the destination entry is written with the mark the flow really takes"
    assert b.d._load_counts("source_pin") == before, "a clash adds no entry"
    assert b.d._load_counts("vpn_dispatch") == {0x1: 1}
    assert b.d.flow_counts_snapshot() == {"proton-1": 1}


def test_a_destination_clash_verdicts_the_mapped_mark_for_a_tunnel_source(one_slot) -> None:
    """Trusted traffic dispatches per destination, so that entry decides."""
    b = one_slot
    b.nft.maps["vpn_dispatch"]["203.0.113.10"] = 0x1
    before = b.d._load_counts("vpn_dispatch")
    pkt = b.dispatch("10.99.99.2", "203.0.113.10")
    assert pkt.mark == 0x1
    assert b.nft.maps["vpn_dispatch"] == {"203.0.113.10": 0x1}
    assert b.nft.maps["source_pin"] == {}
    assert b.d._load_counts("vpn_dispatch") == before, "a clash adds no entry"


def test_a_destination_clash_does_not_override_a_new_pin(one_slot) -> None:
    """For a pinned host the pin decides: the ruleset reads @source_pin first,
    so the host's later flows to this destination follow the pin, not the
    destination entry some other source left."""
    b = one_slot
    b.nft.maps["vpn_dispatch"]["203.0.113.10"] = 0x1
    pkt = b.dispatch("172.16.1.50", "203.0.113.10")
    assert pkt.mark == 0x2
    assert b.nft.maps["source_pin"] == {"172.16.1.50": 0x2}


def test_an_unpinnable_source_follows_the_destination_entry(one_slot) -> None:
    b = one_slot
    b.nft.maps["vpn_dispatch"]["203.0.113.10"] = 0x1
    pkt = b.dispatch("192.0.2.9", "203.0.113.10")
    assert pkt.mark == 0x1


def test_an_unreadable_clash_falls_back_to_the_pick(one_slot, monkeypatch) -> None:
    """If the entry vanished (TTL, eviction) between the add and the read, or
    nft's output cannot be parsed, the flow still goes somewhere live."""
    b = one_slot
    b.nft.maps["source_pin"]["172.16.1.50"] = 0x1
    monkeypatch.setattr(dispatcher, "parse_get_element_mark", lambda text, key: None)
    pkt = b.dispatch("172.16.1.50", "203.0.113.10")
    assert pkt.mark == 0x2
    assert b.d.flow_counts_snapshot() == {"proton-2": 1}


def test_no_clash_no_extra_nft_call(one_slot) -> None:
    """The read is on the clash path only; a plain new flow costs what it did."""
    b = one_slot
    pkt = b.dispatch("172.16.1.50", "203.0.113.10")
    assert pkt.mark == 0x2
    assert b.nft.verbs("get") == []
    assert b.d._load_counts("source_pin") == {0x2: 1}


def test_elem_add_reports_a_clash_and_elem_get_reads_it(box) -> None:
    box.nft.maps["source_pin"]["172.16.1.50"] = 0x1
    assert dispatcher._nft_source_pin_insert("172.16.1.50", 0x1) == dispatcher.INSERT_ADDED
    assert dispatcher._nft_source_pin_insert("172.16.1.50", 0x2) == dispatcher.INSERT_CLASH
    assert dispatcher._nft_map_elem_get("source_pin", "172.16.1.50") == 0x1
    assert dispatcher._nft_map_elem_get("source_pin", "172.16.1.99") is None
    assert dispatcher._nft_map_insert("203.0.113.10", 0x2) == dispatcher.INSERT_ADDED
    assert dispatcher._nft_map_insert("203.0.113.10", 0x3) == dispatcher.INSERT_CLASH


# --- the same clash against the real nft, in a throwaway network namespace ---

_REAL_NFT = textwrap.dedent("""
    import subprocess, sys, types
    sys.path.insert(0, sys.argv[1])
    sys.modules.setdefault("netfilterqueue", types.SimpleNamespace(NetfilterQueue=object))
    for name in ("scapy", "scapy.layers", "scapy.layers.inet"):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["scapy.layers.inet"].IP = object
    import dispatcher as D

    def nft(*a):
        subprocess.run(["nft", *a], check=True)
    nft("add", "table", "inet", "filter")
    nft("add", "map", "inet", "filter", "vpn_dispatch",
        "{ type ipv4_addr : mark; flags timeout; timeout 12h; }")
    nft("add", "map", "inet", "filter", "source_pin",
        "{ type ipv4_addr : mark; flags timeout; timeout 6h; size 256; }")
    print("add1", D._nft_source_pin_insert("172.16.1.50", 0x1))
    print("add2", D._nft_source_pin_insert("172.16.1.50", 0x2))
    print("get", D._nft_map_elem_get("source_pin", "172.16.1.50"))
    print("dadd1", D._nft_map_insert("203.0.113.10", 0x1))
    print("dsame", D._nft_map_insert("203.0.113.10", 0x1))
    print("dadd2", D._nft_map_insert("203.0.113.10", 0x2))
    print("dget", D._nft_map_elem_get("vpn_dispatch", "203.0.113.10"))
    print("missing", D._nft_map_elem_get("vpn_dispatch", "203.0.113.11"))
""")


def test_clash_against_the_real_nft():
    if shutil.which("nft") is None or shutil.which("unshare") is None:
        pytest.skip("needs nft and unshare")
    if subprocess.run(["unshare", "-rn", "nft", "list", "ruleset"],
                      capture_output=True).returncode != 0:
        pytest.skip("unprivileged user+net namespaces (unshare -rn) not available")
    r = subprocess.run(["unshare", "-rn", sys.executable, "-c", _REAL_NFT, str(_BIN)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    got = dict(line.split(" ", 1) for line in r.stdout.splitlines() if " " in line)
    assert got == {"add1": "added", "add2": "clash", "get": "1",
                   "dadd1": "added", "dsame": "added", "dadd2": "clash",
                   "dget": "1", "missing": "None"}, r.stdout + r.stderr
