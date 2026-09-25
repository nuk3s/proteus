"""Tests for the daemon glue in etc/proteus/bin/dispatcher.py.

dispatcher_logic.py is pure and covered by dispatcher_logic_test.py; this file
covers the part that talks to signals, locks and the NFQUEUE loop. The two
native modules dispatcher.py imports (netfilterqueue, scapy) are stubbed when
absent so the module can be imported on a box that isn't the gateway.

The signal tests run in a SUBPROCESS: a deadlock on the main thread cannot be
recovered from inside pytest, and Python only delivers signal handlers to the
main thread, so the scenario has to own one.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import types
from pathlib import Path

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


def _state_dir(*slots: str) -> str:
    d = tempfile.mkdtemp()
    for i, name in enumerate(slots, start=1):
        Path(d, f"{name}.state").write_text(f"INSTANCE={name}\nFWMARK=0x{i:x}\n")
    return d


def _quiet(monkeypatch=None):
    """Keep the daemon's nft/snapshot side effects out of the test box."""
    targets = {"_nft_source_pin_elem_list": lambda: [], "write_snapshot": lambda snap: None}
    if monkeypatch:
        for k, v in targets.items():
            monkeypatch.setattr(dispatcher, k, v)
    else:
        for k, v in targets.items():
            setattr(dispatcher, k, v)


# --- in-process: the deferred reload -----------------------------------------

def test_request_reload_is_applied_by_next_pick(monkeypatch):
    sd = _state_dir("proton-1")
    monkeypatch.setattr(dispatcher, "STATE_DIR", sd)
    _quiet(monkeypatch)
    d = dispatcher.Dispatcher()
    assert [n for n, _ in d._instances] == ["proton-1"]

    Path(sd, "proton-2.state").write_text("INSTANCE=proton-2\nFWMARK=0x2\n")
    d.request_reload()
    assert [n for n, _ in d._instances] == ["proton-1"], "flag alone must not reload"
    d.pick()
    assert [n for n, _ in d._instances] == ["proton-1", "proton-2"]
    assert not d._reload_pending.is_set(), "flag is consumed"


def test_request_reload_is_applied_by_janitor(monkeypatch):
    sd = _state_dir("proton-1")
    monkeypatch.setattr(dispatcher, "STATE_DIR", sd)
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", tempfile.mkdtemp())
    _quiet(monkeypatch)
    d = dispatcher.Dispatcher()
    Path(sd, "proton-1.state").unlink()
    d.request_reload()
    d.janitor_once()
    assert d._instances == []


def test_main_exits_nonzero_when_receive_loop_returns(monkeypatch, tmp_path):
    """nfq.run() returning means recv() failed; exit 1 so Restart=on-failure
    fires. (It used to return 0, which systemd treats as a clean stop.)"""
    monkeypatch.setattr(dispatcher, "STATE_DIR", _state_dir("proton-1"))
    monkeypatch.setattr(dispatcher, "LOG_PATH", str(tmp_path / "d.log"))
    monkeypatch.setattr(dispatcher, "JANITOR_INTERVAL", 3600)
    _quiet(monkeypatch)

    class FakeNFQ:
        def bind(self, num, cb): pass
        def run(self): return None          # loop ended, no exception
        def unbind(self): pass

    monkeypatch.setattr(dispatcher, "NetfilterQueue", FakeNFQ)
    old = signal.getsignal(signal.SIGHUP)
    try:
        assert dispatcher.main() == 1
    finally:
        signal.signal(signal.SIGHUP, old)
        signal.siginterrupt(signal.SIGHUP, True)


# --- subprocess scenarios: real signals on a real main thread -----------------

def scenario_sighup_during_pick() -> None:
    """A SIGHUP arriving while pick() holds the lock must not deadlock, and the
    reload it asked for must land on the following pick()."""
    _quiet()
    sd = _state_dir("proton-1")
    dispatcher.STATE_DIR = sd
    d = dispatcher.Dispatcher()
    dispatcher._install_signal_handlers(d)          # what main() installs
    Path(sd, "proton-2.state").write_text("INSTANCE=proton-2\nFWMARK=0x2\n")

    def list_and_get_hupped():
        # Simulates rotate-slot.sh's SIGHUP landing during the nft call that
        # pick() makes under self._lock.
        os.kill(os.getpid(), signal.SIGHUP)
        return []
    dispatcher._nft_source_pin_elem_list = list_and_get_hupped
    d.pick()                                        # deadlocked before the fix
    dispatcher._nft_source_pin_elem_list = lambda: []
    d.pick()                                        # applies the deferred reload
    names = sorted(n for n, _ in d._instances)
    assert names == ["proton-1", "proton-2"], names
    print("OK no-deadlock reload-applied")


def scenario_sighup_restarts_blocking_recv() -> None:
    """What the netfilterqueue extension does all day: a C recv() with the GIL
    released. With the daemon's signal setup a SIGHUP must NOT make that recv()
    fail with EINTR (netfilterqueue < 1.1 left its loop on that, ending
    nfq.run(); 1.1.0 copes, but the daemon should not depend on it); the
    syscall must be restarted and the Python-level handler must still run
    afterwards."""
    import ctypes
    import socket
    import threading

    _quiet()
    dispatcher.STATE_DIR = _state_dir("proton-1")
    d = dispatcher.Dispatcher()
    dispatcher._install_signal_handlers(d)

    a, b = socket.socketpair()
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(8)

    def poke():
        import time
        time.sleep(0.3)
        os.kill(os.getpid(), signal.SIGHUP)         # lands while recv() blocks
        time.sleep(0.3)
        b.send(b"x")
    threading.Thread(target=poke, daemon=True).start()

    rv = libc.recv(a.fileno(), buf, 8, 0)           # releases the GIL, like Cython's `with nogil`
    err = ctypes.get_errno()
    assert rv == 1, f"recv returned {rv} errno={err} (4=EINTR: SIGHUP interrupted the receive loop)"
    assert d._reload_pending.is_set(), "Python-level SIGHUP handler did not run"
    print("OK recv-restarted handler-ran")


def _run_scenario(name: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, __file__, name],
        capture_output=True, text=True, timeout=15,
    )


def test_sighup_during_pick_does_not_deadlock():
    r = _run_scenario("scenario_sighup_during_pick")
    assert r.returncode == 0 and "OK no-deadlock" in r.stdout, r.stdout + r.stderr


def test_sighup_does_not_end_the_receive_loop():
    r = _run_scenario("scenario_sighup_restarts_blocking_recv")
    assert r.returncode == 0 and "OK recv-restarted" in r.stdout, r.stdout + r.stderr


if __name__ == "__main__":
    globals()[sys.argv[1]]()
