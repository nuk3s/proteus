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
    """Keep the daemon's nft/snapshot side effects out of the test box.

    _nft_map_elem_list is the one place the daemon lists a map (source_pin and
    vpn_dispatch both go through it), so stubbing it keeps pick()'s load read,
    the janitor's eviction sweep and the snapshot's pin read off the host."""
    targets = {"_nft_map_elem_list": lambda map_name: [],
               "write_snapshot": lambda snap: None}
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
    assert d._reload_pending is False, "flag is consumed"


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


def test_pending_reloads_run_one_at_a_time(monkeypatch):
    """The janitor and the NFQUEUE callback can both apply a pending reload.
    Two at once were last-writer-wins: the one that read the state files first
    could store its list last, over a newer one, until the next SIGHUP."""
    import threading

    monkeypatch.setattr(dispatcher, "STATE_DIR", _state_dir("proton-1"))
    _quiet(monkeypatch)
    d = dispatcher.Dispatcher()
    first_reading = threading.Event()
    let_first_finish = threading.Event()
    reads: list[int] = []

    def slow_then_fast(_state_dir):
        n = len(reads)
        reads.append(n)
        if n == 0:                      # the first reload reads the OLD files, slowly
            first_reading.set()
            let_first_finish.wait(5)
            return [("proton-1", 0x1)]
        return [("proton-1", 0x1), ("proton-2", 0x2)]
    monkeypatch.setattr(dispatcher, "load_instances", slow_then_fast)

    d.request_reload()
    a = threading.Thread(target=d._apply_pending_reload)
    a.start()
    assert first_reading.wait(5)
    d.request_reload()                  # a second SIGHUP, after the files changed
    b = threading.Thread(target=d._apply_pending_reload)
    b.start()
    b.join(0.3)
    assert reads == [0], "a second reload ran while the first was still in progress"
    let_first_finish.set()
    a.join(5)
    b.join(5)
    assert reads == [0, 1]
    assert [n for n, _ in d._instances] == ["proton-1", "proton-2"], \
        "the older read was stored last"


_WITH_OPS = {"SETUP_WITH", "BEFORE_WITH", "SETUP_ASYNC_WITH", "BEFORE_ASYNC_WITH"}


def _has_with(code) -> bool:
    """True if the code object contains a with-statement (any Python version:
    3.11-3.13 compile one to BEFORE_WITH, 3.14 to LOAD_SPECIAL __enter__)."""
    import dis
    return any(i.opname in _WITH_OPS
               or (i.opname == "LOAD_SPECIAL" and "enter" in str(i.argrepr))
               for i in dis.get_instructions(code))


def _locks_taken(fn, *args) -> list[str]:
    """Run fn under sys.setprofile and list every lock it can acquire:
    - a C-level acquire()/__enter__() on a Lock or RLock;
    - any Python-level call into threading.Condition or threading.Event, both
      of which wrap one;
    - any with-statement in a Python function it runs. Python 3.12 and later
      report `with lock:` as a c_call of __enter__, but 3.11 calls __enter__
      straight from the bytecode and the profiler never sees it, so the code
      is read as well. Deliberately broad: a with-block on anything counts,
      taken or not."""
    import inspect
    import threading

    lock_types = (type(threading.Lock()), type(threading.RLock()))
    wrapped = {f.__code__: f"{cls.__name__}.{name}"
               for cls in (threading.Condition, threading.Event)
               for name, f in vars(cls).items() if inspect.isfunction(f)}
    taken: list[str] = []

    def prof(frame, event, arg):
        if event == "c_call":
            owner = getattr(arg, "__self__", None)
            if isinstance(owner, lock_types) and arg.__name__ in ("acquire", "acquire_lock", "__enter__"):
                taken.append(f"{type(owner).__name__}.{arg.__name__}")
        elif event == "call":
            if frame.f_code in wrapped:
                taken.append(wrapped[frame.f_code])
            elif _has_with(frame.f_code):
                taken.append(f"with-statement in {frame.f_code.co_name}")

    sys.setprofile(prof)
    try:
        fn(*args)
    finally:
        sys.setprofile(None)
    return taken


def test_sighup_handler_acquires_no_lock(monkeypatch):
    """The handler runs on the main thread at an arbitrary bytecode, and the
    main thread may already hold any lock the dispatcher has. So the handler
    may take none, not even briefly. Deterministic, unlike the storm scenario
    below: it inspects the exact handler main() installs."""
    import threading

    monkeypatch.setattr(dispatcher, "STATE_DIR", _state_dir("proton-1"))
    _quiet(monkeypatch)
    d = dispatcher.Dispatcher()
    old = signal.getsignal(signal.SIGHUP)
    try:
        dispatcher._install_signal_handlers(d)
        handler = signal.getsignal(signal.SIGHUP)
    finally:
        signal.signal(signal.SIGHUP, old)
    assert callable(handler)

    # The checker has to see a lock when there is one, or a pass means nothing.
    lock, rlock, event = threading.Lock(), threading.RLock(), threading.Event()

    def with_lock():
        with lock:
            pass

    def with_rlock():
        with rlock:
            pass
    assert _locks_taken(threading.Lock().acquire) == ["lock.acquire"]
    assert _locks_taken(with_lock), "blind to `with lock:`"
    assert _locks_taken(with_rlock), "blind to `with rlock:`"
    assert "Event.set" in _locks_taken(event.set)

    taken = _locks_taken(handler, signal.SIGHUP, None)
    assert taken == [], f"the SIGHUP handler acquired {taken}"
    assert d._reload_pending is True, "the handler did not request a reload"


def test_unit_restarts_a_dispatcher_killed_by_sighup():
    """A SIGHUP before the handler is installed, or during interpreter
    shutdown, kills the daemon, and systemd counts that as a clean exit:
    Restart=on-failure alone would not bring it back."""
    root = Path(__file__).resolve().parent.parent
    for unit in (root / "etc/systemd/system/proteus-dispatcher.service",
                 root / "install/templates/proteus-dispatcher.service.tmpl"):
        lines = unit.read_text().splitlines()
        assert "Restart=on-failure" in lines, unit
        assert "RestartForceExitStatus=SIGHUP" in lines, unit


def test_unit_comment_names_every_sighup_sender():
    """The comment on RestartForceExitStatus says who sends the SIGHUP. It
    named rotate-slot.sh alone after vpnns-down.sh started sending one too;
    a sender left out is one an operator reading the unit will not think of
    when the dispatcher reloads or restarts."""
    root = Path(__file__).resolve().parent.parent
    senders = {p.name for p in (root / "etc/proteus/bin").iterdir()
               if p.is_file() and "--signal=HUP proteus-dispatcher.service"
               in p.read_text(errors="replace")}
    assert senders >= {"rotate-slot.sh", "vpnns-up.sh", "vpnns-down.sh"}, senders
    for unit in (root / "etc/systemd/system/proteus-dispatcher.service",
                 root / "install/templates/proteus-dispatcher.service.tmpl"):
        lines = unit.read_text().splitlines()
        i = lines.index("RestartForceExitStatus=SIGHUP")
        j = i
        while j > 0 and lines[j - 1].startswith("#"):
            j -= 1
        comment = " ".join(lines[j:i])
        for s in sorted(senders):
            assert s in comment, f"{unit.name}: {s} is not named above line {i + 1}"


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


# --- a SIGHUP during startup ---------------------------------------------------

# Stands in for netfilterqueue when dispatcher.py runs as the daemon: the
# import is where startup spends its time (with scapy right after it), so a
# rotate-slot.sh or vpnns-down.sh SIGHUP is most likely to land here. It then
# stops the run: going on into main() would read and write the real box's
# paths.
_HUP_ON_IMPORT = """\
import os, signal
os.kill(os.getpid(), signal.SIGHUP)
print("OK survived a SIGHUP during the imports", flush=True)
raise SystemExit(0)
"""


def test_sighup_during_the_startup_imports_does_not_kill_the_daemon(tmp_path):
    """Before the handler is installed the default action kills the process,
    and systemd restarts it only thanks to RestartForceExitStatus=SIGHUP: a
    restart for what should have been a reload. dispatcher.py ignores SIGHUP
    from its first lines, before the heavy imports. Run exactly as systemd
    does (the script itself, as __main__)."""
    (tmp_path / "netfilterqueue.py").write_text(_HUP_ON_IMPORT)
    env = dict(os.environ, PYTHONPATH=str(tmp_path))
    r = subprocess.run([sys.executable, str(_BIN / "dispatcher.py")],
                       capture_output=True, text=True, timeout=30, env=env)
    assert r.returncode == 0 and "OK survived" in r.stdout, \
        f"rc={r.returncode} (-{int(signal.SIGHUP)} is death by SIGHUP)\n{r.stdout}{r.stderr}"


def test_importing_the_module_leaves_sighup_alone():
    """The ignore is for the daemon only; an importer (these tests) keeps its
    own signal handling."""
    code = ("import signal, sys, types\n"
            f"sys.path.insert(0, {str(_BIN)!r})\n"
            "sys.modules['netfilterqueue'] = types.SimpleNamespace(NetfilterQueue=object)\n"
            "for n in ('scapy', 'scapy.layers', 'scapy.layers.inet'):\n"
            "    sys.modules[n] = types.ModuleType(n)\n"
            "sys.modules['scapy.layers.inet'].IP = object\n"
            "import dispatcher\n"
            "print(signal.getsignal(signal.SIGHUP) is signal.SIG_DFL)\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True, timeout=30)
    assert r.stdout.strip() == "True", r.stdout + r.stderr


def test_a_sighup_ignored_during_startup_is_not_lost(monkeypatch, tmp_path):
    """rotate-slot.sh promotes a slot and signals just after Dispatcher() has
    read the state files, while SIGHUP is still ignored. The first flow after
    startup must see the new slot anyway: main() requests one reload once the
    real handler is in."""
    sd = _state_dir("proton-1")
    monkeypatch.setattr(dispatcher, "STATE_DIR", sd)
    monkeypatch.setattr(dispatcher, "HEALTH_DIR", str(tmp_path / "health"))
    monkeypatch.setattr(dispatcher, "LOG_PATH", str(tmp_path / "d.log"))
    _quiet(monkeypatch)
    # The janitor's own re-read would find the slot too; this is about the
    # pick path, which must not wait for it.
    monkeypatch.setattr(dispatcher.Dispatcher, "janitor_loop", lambda self: None)

    real_load = dispatcher.load_instances
    reads: list[int] = []

    def read_then_promote(state_dir):
        out = real_load(state_dir)
        if not reads:
            Path(sd, "proton-2.state").write_text("INSTANCE=proton-2\nFWMARK=0x2\n")
            os.kill(os.getpid(), signal.SIGHUP)     # ignored: no handler yet
        reads.append(1)
        return out
    monkeypatch.setattr(dispatcher, "load_instances", read_then_promote)

    seen: dict = {}

    class FakeNFQ:
        def bind(self, num, cb):
            self.d = cb.__self__

        def run(self):
            seen["handler"] = signal.getsignal(signal.SIGHUP)
            self.d.pick()                           # the first new flow
            seen["names"] = [n for n, _ in self.d._instances]

        def unbind(self):
            pass

    monkeypatch.setattr(dispatcher, "NetfilterQueue", FakeNFQ)
    # What the top of dispatcher.py does when it runs as the daemon.
    old = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        assert dispatcher.main() == 1
    finally:
        signal.signal(signal.SIGHUP, old)
        signal.siginterrupt(signal.SIGHUP, True)
    assert callable(seen["handler"]), "main() did not replace the startup SIG_IGN"
    assert seen["names"] == ["proton-1", "proton-2"], \
        "the SIGHUP that arrived during startup was lost"


# --- subprocess scenarios: real signals on a real main thread -----------------

def scenario_sighup_during_pick() -> None:
    """A SIGHUP arriving during pick()'s nft load read must not deadlock, and
    the reload it asked for must land on the following pick().

    The read runs outside self._lock since the load cache moved it off the
    lock, so this one no longer reaches the deadlock by itself (see
    scenario_sighup_while_lock_held for the window that remains); it pins
    the deferred reload across the read, and would catch the read moving
    back under the lock."""
    _quiet()
    sd = _state_dir("proton-1")
    dispatcher.STATE_DIR = sd
    d = dispatcher.Dispatcher()
    dispatcher._install_signal_handlers(d)          # what main() installs
    Path(sd, "proton-2.state").write_text("INSTANCE=proton-2\nFWMARK=0x2\n")

    def list_and_get_hupped():
        # Simulates rotate-slot.sh's SIGHUP landing during the nft call that
        # pick() makes to refresh its load counts.
        os.kill(os.getpid(), signal.SIGHUP)
        return []
    dispatcher._nft_source_pin_elem_list = list_and_get_hupped
    d.pick()                                        # deadlocked before the fix
    dispatcher._nft_source_pin_elem_list = lambda: []
    d.pick()                                        # applies the deferred reload
    names = sorted(n for n, _ in d._instances)
    assert names == ["proton-1", "proton-2"], names
    print("OK no-deadlock reload-applied")


class _HupWhileHeld:
    """Stands in for Dispatcher._lock. The first acquisition after `armed` is
    set raises SIGHUP at this process while the real lock is held; Python runs
    the handler as os.kill() returns, still inside the `with`. That is the
    window a rotate-slot.sh SIGHUP can land in on any new flow: pick() holds
    self._lock while it copies the instance list, and a signal that arrives
    just before that copy is handled at the call boundary inside the block.
    The real window is a few bytecodes wide; this makes it certain."""

    def __init__(self, real) -> None:
        self._real = real
        self.armed = False

    def __enter__(self):
        self._real.acquire()
        if self.armed:
            self.armed = False
            os.kill(os.getpid(), signal.SIGHUP)
        return self

    def __exit__(self, *exc) -> bool:
        self._real.release()
        return False


def scenario_sighup_while_lock_held() -> None:
    """A SIGHUP handled while pick() holds self._lock must not deadlock. A
    handler that reloads in place takes that same non-reentrant lock and
    hangs the daemon here; the flag-only handler does not."""
    _quiet()
    sd = _state_dir("proton-1")
    dispatcher.STATE_DIR = sd
    d = dispatcher.Dispatcher()
    dispatcher._install_signal_handlers(d)          # what main() installs
    Path(sd, "proton-2.state").write_text("INSTANCE=proton-2\nFWMARK=0x2\n")

    d._lock = _HupWhileHeld(d._lock)
    d._lock.armed = True
    d.pick()                                        # deadlocks with an in-place reload
    d.pick()                                        # applies the deferred reload
    names = sorted(n for n, _ in d._instances)
    assert names == ["proton-1", "proton-2"], names
    print("OK lock-held no-deadlock reload-applied")


STORM_S = 3.0


def scenario_sighup_storm() -> None:
    """No injection: another process SIGHUPs us as fast as it can while the
    main thread runs pick() in a loop, so the handler lands at arbitrary
    points, the way systemctl's signal does. Any lock the handler path takes
    that the main thread can already be holding shows up as a hang (the
    watchdog exits 3) or, when later signals keep re-entering a handler that
    is stuck on the lock, a RecursionError. The in-place reload() handler
    fails here within milliseconds (pick()'s lock), and so did a
    threading.Event flag (its set() takes the lock clear() holds). A pass is
    evidence, not proof; a failure is always real."""
    import threading
    import time

    _quiet()
    dispatcher.STATE_DIR = _state_dir("proton-1", "proton-2")
    d = dispatcher.Dispatcher()
    dispatcher._install_signal_handlers(d)

    sender = subprocess.Popen([sys.executable, "-c", (
        "import os, signal, time\n"
        f"end = time.monotonic() + {STORM_S}\n"
        "while time.monotonic() < end:\n"
        f"    os.kill({os.getpid()}, signal.SIGHUP)\n"
        "    time.sleep(0.0002)\n")])
    picks = [0]

    def watchdog() -> None:
        last = -1
        while True:
            time.sleep(1.0)
            if picks[0] == last:
                sender.kill()
                print(f"HUNG after {picks[0]} picks", flush=True)
                os._exit(3)
            last = picks[0]
    threading.Thread(target=watchdog, daemon=True).start()

    try:
        while sender.poll() is None:
            d.pick()
            picks[0] += 1
    finally:
        # Pass or fail, stop the sender before this process exits. A SIGHUP
        # that lands during interpreter shutdown, after the handler is gone,
        # kills the process, and a pick() that raised would then show up as
        # a death by signal instead of its traceback.
        sender.kill()
        sender.wait()
    print(f"OK storm survived picks={picks[0]}")


def scenario_sighup_runs_handler_while_recv_blocks() -> None:
    """What the netfilterqueue extension does all day: a C recv() with the GIL
    released. A SIGHUP that lands there must run the Python handler straight
    away, with no packet arriving, so the janitor can apply the reload on a
    quiet VLAN. That needs recv() to be interrupted (EINTR), which is what
    netfilterqueue 1.0+ handles by running the handler and looping. With
    SA_RESTART (siginterrupt(SIGHUP, False)) the recv() below would resume and
    block for good, and the scenario would time out."""
    import ctypes
    import errno
    import socket
    import threading

    _quiet()
    dispatcher.STATE_DIR = _state_dir("proton-1")
    d = dispatcher.Dispatcher()
    dispatcher._install_signal_handlers(d)

    a, _b = socket.socketpair()
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(8)

    def poke():
        import time
        time.sleep(0.3)
        os.kill(os.getpid(), signal.SIGHUP)         # lands while recv() blocks; nothing is ever sent
    threading.Thread(target=poke, daemon=True).start()

    rv = libc.recv(a.fileno(), buf, 8, 0)           # releases the GIL, like Cython's `with nogil`
    err = ctypes.get_errno()
    assert rv == -1 and err == errno.EINTR, f"recv returned {rv} errno={err}; expected EINTR"
    assert d._reload_pending is True, "Python-level SIGHUP handler did not run"
    print("OK handler-ran-without-traffic")


def _run_scenario(name: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [sys.executable, __file__, name],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired as e:
        # A deadlocked main thread never exits; report it as what it is.
        out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return subprocess.CompletedProcess(e.cmd, -1, out, "TIMEOUT: scenario hung (deadlock)")


def test_sighup_during_pick_does_not_deadlock():
    r = _run_scenario("scenario_sighup_during_pick")
    assert r.returncode == 0 and "OK no-deadlock" in r.stdout, r.stdout + r.stderr


def test_sighup_while_pick_holds_the_lock_does_not_deadlock():
    r = _run_scenario("scenario_sighup_while_lock_held")
    assert r.returncode == 0 and "OK lock-held" in r.stdout, r.stdout + r.stderr


def test_sighup_storm_never_hangs_pick():
    r = _run_scenario("scenario_sighup_storm")
    assert r.returncode == 0 and "OK storm" in r.stdout, r.stdout + r.stderr


def test_sighup_is_handled_while_the_receive_loop_idles():
    r = _run_scenario("scenario_sighup_runs_handler_while_recv_blocks")
    assert r.returncode == 0 and "OK handler-ran-without-traffic" in r.stdout, r.stdout + r.stderr


if __name__ == "__main__":
    globals()[sys.argv[1]]()
