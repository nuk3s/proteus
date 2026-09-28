"""Tests for etc/proteus/bin/dispatcher_logic.py — pure logic only."""
from pathlib import Path
import pytest

import dispatcher_logic
from dispatcher_logic import load_instances


def test_load_instances_filters_to_proton_slots(tmp_path: Path) -> None:
    """Only proton-N slots participate; dns-6 etc. are excluded."""
    (tmp_path / "proton-1.state").write_text("INSTANCE=proton-1\nFWMARK=0x1\n")
    (tmp_path / "proton-2.state").write_text("INSTANCE=proton-2\nFWMARK=0x2\n")
    (tmp_path / "dns-6.state").write_text("INSTANCE=dns-6\nFWMARK=0x6\n")

    out = load_instances(str(tmp_path))
    names = sorted(n for n, _ in out)
    assert names == ["proton-1", "proton-2"]


def test_load_instances_skips_files_missing_keys(tmp_path: Path) -> None:
    (tmp_path / "proton-1.state").write_text("INSTANCE=proton-1\n")  # no FWMARK
    (tmp_path / "proton-2.state").write_text("INSTANCE=proton-2\nFWMARK=0x2\n")
    out = load_instances(str(tmp_path))
    assert out == [("proton-2", 0x2)]


def test_load_instances_handles_empty_dir(tmp_path: Path) -> None:
    assert load_instances(str(tmp_path)) == []


import time
from dispatcher_logic import load_slot_score, pick_by_score, SCORE_FRESH_SECONDS


def _write_state(p: Path, status: str, score: float, updated_at: int) -> None:
    p.write_text(
        f"STATUS={status}\nCOMPOSITE_SCORE={score}\nSCORE_UPDATED_AT={updated_at}\n"
    )


def test_load_slot_score_parses_state_file(tmp_path: Path) -> None:
    p = tmp_path / "proton-1.state"
    _write_state(p, "ok", 92.3, 1746810000)
    s = load_slot_score(str(p))
    assert s.status == "ok"
    assert s.score == pytest.approx(92.3)
    assert s.updated_at == 1746810000


def test_load_slot_score_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_slot_score(str(tmp_path / "nope.state")) is None


def test_load_slot_score_missing_keys_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "proton-1.state"
    p.write_text("STATUS=ok\n")  # no SCORE_UPDATED_AT
    assert load_slot_score(str(p)) is None


def test_pick_by_score_chooses_highest_fresh(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "ok",  60.0, now)
    _write_state(tmp_path / "proton-2.state", "ok",  90.0, now)
    _write_state(tmp_path / "proton-3.state", "ok",  75.0, now)

    instances = [("proton-1", 0x1), ("proton-2", 0x2), ("proton-3", 0x3)]
    chosen = pick_by_score(instances, str(tmp_path), now=now)
    assert chosen == ("proton-2", 0x2)


def test_pick_by_score_excludes_degraded(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "degraded", -940.0, now)
    _write_state(tmp_path / "proton-2.state", "ok",         50.0, now)
    instances = [("proton-1", 0x1), ("proton-2", 0x2)]
    assert pick_by_score(instances, str(tmp_path), now=now) == ("proton-2", 0x2)


def test_pick_by_score_excludes_stale(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "ok", 100.0, now - SCORE_FRESH_SECONDS - 5)
    _write_state(tmp_path / "proton-2.state", "ok",  50.0, now)
    instances = [("proton-1", 0x1), ("proton-2", 0x2)]
    # proton-1 is stale -> proton-2 wins despite lower score
    assert pick_by_score(instances, str(tmp_path), now=now) == ("proton-2", 0x2)


def test_pick_by_score_returns_none_when_no_fresh_scores(tmp_path: Path) -> None:
    """Caller should fall back to random when this returns None."""
    instances = [("proton-1", 0x1), ("proton-2", 0x2)]
    # No state files written.
    assert pick_by_score(instances, str(tmp_path), now=int(time.time())) is None


def test_pick_by_score_empty_instances_returns_none(tmp_path: Path) -> None:
    assert pick_by_score([], str(tmp_path), now=int(time.time())) is None


from dispatcher_logic import degraded_marks


def test_degraded_marks_collects_only_degraded(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "degraded", -940.0, now)
    _write_state(tmp_path / "proton-2.state", "ok",         50.0, now)
    _write_state(tmp_path / "proton-3.state", "degraded", -960.0, now)

    instances = [("proton-1", 0x1), ("proton-2", 0x2), ("proton-3", 0x3)]
    assert degraded_marks(instances, str(tmp_path)) == {0x1, 0x3}


def test_degraded_marks_missing_state_treated_as_ok(tmp_path: Path) -> None:
    """A slot whose state file doesn't exist is treated as not-degraded
    (consistent with _is_healthy in dispatcher.py)."""
    instances = [("proton-1", 0x1)]
    assert degraded_marks(instances, str(tmp_path)) == set()


def test_degraded_marks_empty_instances(tmp_path: Path) -> None:
    assert degraded_marks([], str(tmp_path)) == set()


from dispatcher_logic import parse_source_pin_elements


def test_parse_source_pin_elements_empty() -> None:
    assert parse_source_pin_elements([]) == []
    assert parse_source_pin_elements(None) == []


def test_parse_source_pin_elements_bare_types() -> None:
    """nft -j without timeout produces [[ip, mark]] elements."""
    elems = [["172.16.1.10", 1], ["172.16.1.20", 2]]
    assert parse_source_pin_elements(elems) == [
        ("172.16.1.10", 1), ("172.16.1.20", 2)
    ]


def test_parse_source_pin_elements_wrapped_key() -> None:
    """nft -j WITH 'flags timeout' wraps the key in {'elem': {'val':..., 'expires':...}}."""
    elems = [[{"elem": {"val": "172.16.1.254", "expires": 21202}}, 1]]
    assert parse_source_pin_elements(elems) == [("172.16.1.254", 1)]


def test_parse_source_pin_elements_wrapped_value() -> None:
    """A wrapped value (rare but possible if the value-side has an attribute)."""
    elems = [["172.16.1.30", {"val": 3}]]
    assert parse_source_pin_elements(elems) == [("172.16.1.30", 3)]


def test_parse_source_pin_elements_both_wrapped() -> None:
    elems = [[
        {"elem": {"val": "172.16.1.40", "expires": 5000}},
        {"val": 5}
    ]]
    assert parse_source_pin_elements(elems) == [("172.16.1.40", 5)]


def test_parse_source_pin_elements_mixed() -> None:
    elems = [
        ["172.16.1.10", 1],
        [{"elem": {"val": "172.16.1.20", "expires": 100}}, 2],
    ]
    assert parse_source_pin_elements(elems) == [
        ("172.16.1.10", 1), ("172.16.1.20", 2)
    ]


def test_parse_source_pin_elements_skips_malformed() -> None:
    """Bad entries are skipped, not raised."""
    elems = [
        [],                                        # too short
        ["172.16.1.10"],                           # missing value
        ["172.16.1.10", 1],                        # ok
        ["not-an-ip", "not-a-mark"],               # int() raises -> skip
        [{"weird": "shape"}, 2],                   # unrecognised dict -> skip
        [["nested", "list"], 3],                   # non-str/non-dict key -> skip
    ]
    assert parse_source_pin_elements(elems) == [("172.16.1.10", 1)]


from dispatcher_logic import pick_distributed, is_pinnable_source


def test_pick_distributed_first_client_gets_best(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "ok", 121.0, now)
    _write_state(tmp_path / "proton-2.state", "ok", 85.0, now)
    _write_state(tmp_path / "proton-3.state", "ok", 81.0, now)
    insts = [("proton-1", 0x1), ("proton-2", 0x2), ("proton-3", 0x3)]
    # No pins yet -> all equally loaded -> highest score wins.
    assert pick_distributed(insts, str(tmp_path), {}, now=now) == ("proton-1", 0x1)


def test_pick_distributed_spreads_to_least_loaded(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "ok", 121.0, now)
    _write_state(tmp_path / "proton-2.state", "ok", 85.0, now)
    _write_state(tmp_path / "proton-3.state", "ok", 81.0, now)
    insts = [("proton-1", 0x1), ("proton-2", 0x2), ("proton-3", 0x3)]
    # proton-1 already has a client -> next goes to least-loaded eligible,
    # tie-broken by higher score -> proton-2, then proton-3.
    assert pick_distributed(insts, str(tmp_path), {0x1: 1}, now=now) == ("proton-2", 0x2)
    assert pick_distributed(insts, str(tmp_path), {0x1: 1, 0x2: 1}, now=now) == ("proton-3", 0x3)


def test_pick_distributed_excludes_weak_slot_outside_band(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "ok", 121.0, now)
    _write_state(tmp_path / "proton-2.state", "ok", 70.0, now)  # 121-70 = 51 > 40 band
    insts = [("proton-1", 0x1), ("proton-2", 0x2)]
    # Even with proton-1 loaded and proton-2 idle, proton-2 "sucks" (outside the
    # band) so it's not used -> stays on proton-1.
    assert pick_distributed(insts, str(tmp_path), {0x1: 5}, now=now) == ("proton-1", 0x1)


def test_pick_distributed_excludes_degraded_and_stale(tmp_path: Path) -> None:
    now = int(time.time())
    _write_state(tmp_path / "proton-1.state", "degraded", -940.0, now)
    _write_state(tmp_path / "proton-2.state", "ok", 100.0, now - SCORE_FRESH_SECONDS - 5)
    _write_state(tmp_path / "proton-3.state", "ok", 90.0, now)
    insts = [("proton-1", 0x1), ("proton-2", 0x2), ("proton-3", 0x3)]
    assert pick_distributed(insts, str(tmp_path), {}, now=now) == ("proton-3", 0x3)


def test_pick_distributed_none_when_no_fresh(tmp_path: Path) -> None:
    assert pick_distributed([("proton-1", 0x1)], str(tmp_path), {}, now=int(time.time())) is None


def test_is_pinnable_source() -> None:
    assert is_pinnable_source("172.16.1.132") is True
    assert is_pinnable_source("172.16.1.1") is True
    assert is_pinnable_source("0.0.0.0") is False
    assert is_pinnable_source("255.255.255.255") is False
    assert is_pinnable_source("172.16.1.0") is False     # network address
    assert is_pinnable_source("172.16.1.255") is False   # broadcast address
    assert is_pinnable_source("10.0.0.5") is False        # off-VLAN (mgmt)
    assert is_pinnable_source("not-an-ip") is False


def test_status_snapshot():
    from dispatcher_logic import build_status_snapshot
    pins = {"10.0.0.23": ("proton-1", 1754300100.0)}   # src -> (slot, expiry)
    counters = {"proton-1": 41, "proton-2": 7}
    snap = build_status_snapshot(pins, counters, now=1754300000.0)
    assert snap["pins"] == [{"ip": "10.0.0.23", "slot": "proton-1", "ttl_s": 100}]
    assert snap["flow_counts"] == {"proton-1": 41, "proton-2": 7}
    expired = build_status_snapshot({"10.0.0.9": ("proton-1", 100.0)}, {}, now=200.0)
    assert expired["pins"] == []


from dispatcher_logic import parse_source_pin_elements_with_ttl


def test_parse_source_pin_elements_with_ttl_wrapped_key() -> None:
    """nft -j on a timeout-flagged map wraps the key with a remaining-seconds
    'expires' field (verified live: insert with timeout 30s -> expires: 29,
    5s later -> expires: 24 — it counts down, it is not an absolute epoch)."""
    elems = [[{"elem": {"val": "172.16.1.254", "expires": 21202}}, 1]]
    assert parse_source_pin_elements_with_ttl(elems) == [("172.16.1.254", 1, 21202)]


def test_parse_source_pin_elements_with_ttl_bare_has_no_ttl() -> None:
    """Bare [ip, mark] entries (no timeout info in the JSON) yield ttl=None —
    caller must treat this as 'unknown', not guess an expiry."""
    elems = [["172.16.1.10", 1]]
    assert parse_source_pin_elements_with_ttl(elems) == [("172.16.1.10", 1, None)]


def test_parse_source_pin_elements_with_ttl_empty() -> None:
    assert parse_source_pin_elements_with_ttl([]) == []
    assert parse_source_pin_elements_with_ttl(None) == []


def test_parse_source_pin_elements_with_ttl_skips_malformed() -> None:
    elems = [
        [],
        ["172.16.1.10"],
        ["172.16.1.10", 1],
        ["not-an-ip", "not-a-mark"],
    ]
    assert parse_source_pin_elements_with_ttl(elems) == [("172.16.1.10", 1, None)]


# --- playability-biased pinning ------------------------------------------------
def _mk_slot(tmp_path, name, score, *, playable=None, at=None, now=1000):
    (tmp_path / f"{name}.state").write_text(
        f"STATUS=ok\nCOMPOSITE_SCORE={score}\nSCORE_UPDATED_AT={now}\n")
    if playable is not None:
        (tmp_path / f".playability-state.{name}").write_text(
            f"PLAYABLE={playable}\nAT={at if at is not None else now}\n")


def test_new_pins_avoid_a_known_unplayable_slot(tmp_path):
    # Equal scores and equal load: the only thing separating them is streaming.
    _mk_slot(tmp_path, "proton-1", 100, playable="no")
    _mk_slot(tmp_path, "proton-2", 100, playable="yes")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1), ("proton-2", 2)], str(tmp_path), {}, now=1000)
    assert got == ("proton-2", 2)


def test_unplayable_slot_still_wins_if_it_is_the_only_one(tmp_path):
    # Stranding a client is worse than handing it a slot that can't stream.
    _mk_slot(tmp_path, "proton-1", 100, playable="no")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1)], str(tmp_path), {}, now=1000)
    assert got == ("proton-1", 1)


def test_all_unplayable_falls_back_to_the_full_set(tmp_path):
    # Every slot gated: keep normal least-loaded behaviour rather than None.
    _mk_slot(tmp_path, "proton-1", 100, playable="no")
    _mk_slot(tmp_path, "proton-2", 100, playable="no")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1), ("proton-2", 2)], str(tmp_path), {2: 5}, now=1000)
    assert got == ("proton-1", 1)          # least-loaded still decides


def test_playability_does_not_override_load_spreading_among_playable(tmp_path):
    _mk_slot(tmp_path, "proton-1", 100, playable="yes")
    _mk_slot(tmp_path, "proton-2", 100, playable="yes")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1), ("proton-2", 2)], str(tmp_path), {1: 9}, now=1000)
    assert got == ("proton-2", 2)


def test_stale_unplayable_verdict_is_ignored(tmp_path):
    # A verdict older than the freshness window says nothing about the exit now.
    _mk_slot(tmp_path, "proton-1", 100, playable="no",
             at=1000 - dispatcher_logic.PLAYABILITY_FRESH_SECONDS - 1)
    _mk_slot(tmp_path, "proton-2", 100, playable="yes")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1), ("proton-2", 2)], str(tmp_path), {2: 9}, now=1000)
    assert got == ("proton-1", 1)          # stale "no" ignored -> least-loaded wins


def test_unknown_playability_is_treated_as_playable(tmp_path):
    # No file at all (never checked, or just rotated) must not exclude a slot.
    _mk_slot(tmp_path, "proton-1", 100)
    _mk_slot(tmp_path, "proton-2", 100, playable="no")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1), ("proton-2", 2)], str(tmp_path), {}, now=1000)
    assert got == ("proton-1", 1)


def test_is_playable_survives_garbage(tmp_path):
    for body in ("", "junk", "PLAYABLE=no\nAT=notanumber\n", "PLAYABLE=maybe\n"):
        (tmp_path / ".playability-state.proton-9").write_text(body)
        assert dispatcher_logic.is_playable(str(tmp_path), "proton-9", 1000) is True
    assert dispatcher_logic.is_playable(str(tmp_path), "proton-absent", 1000) is True


def test_prefer_playable_can_be_disabled(tmp_path):
    _mk_slot(tmp_path, "proton-1", 100, playable="no")
    _mk_slot(tmp_path, "proton-2", 100, playable="yes")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1), ("proton-2", 2)], str(tmp_path), {2: 9},
        now=1000, prefer_playable=False)
    assert got == ("proton-1", 1)


def test_degraded_still_excluded_regardless_of_playability(tmp_path):
    (tmp_path / "proton-1.state").write_text(
        "STATUS=degraded\nCOMPOSITE_SCORE=100\nSCORE_UPDATED_AT=1000\n")
    (tmp_path / ".playability-state.proton-1").write_text("PLAYABLE=yes\nAT=1000\n")
    _mk_slot(tmp_path, "proton-2", 50, playable="no")
    got = dispatcher_logic.pick_distributed(
        [("proton-1", 1), ("proton-2", 2)], str(tmp_path), {}, now=1000)
    assert got == ("proton-2", 2)          # degraded loses even to a gated slot


# --- Cloudflare verdict bias ---------------------------------------------------
from dispatcher_logic import is_cf_clean, pick_distributed


def _cf(p: Path, clean: str, at: int, failing: str = "") -> None:
    p.write_text(f"CF_CLEAN={clean}\nAT={at}\nFAILING={failing}\n")


def _pl(p: Path, playable: str, at: int) -> None:
    p.write_text(f"PLAYABLE={playable}\nAT={at}\n")


def test_is_cf_clean_fails_open(tmp_path: Path) -> None:
    now = 1_800_000_000
    assert is_cf_clean(str(tmp_path), "proton-1", now)                       # no file
    (tmp_path / ".cf-state.proton-1").write_text("garbage\n")
    assert is_cf_clean(str(tmp_path), "proton-1", now)                       # malformed
    _cf(tmp_path / ".cf-state.proton-1", "no", now - 7200)
    assert is_cf_clean(str(tmp_path), "proton-1", now)                       # stale "no"
    (tmp_path / ".cf-state.proton-1").write_text("CF_CLEAN=no\nAT=abc\n")
    assert is_cf_clean(str(tmp_path), "proton-1", now)                       # bad timestamp
    _cf(tmp_path / ".cf-state.proton-1", "no", now - 60, "discord.com")
    assert not is_cf_clean(str(tmp_path), "proton-1", now)                   # fresh "no"
    _cf(tmp_path / ".cf-state.proton-1", "yes", now - 60)
    assert is_cf_clean(str(tmp_path), "proton-1", now)


def _three_equal_slots(tmp_path: Path, now: int):
    for n in ("proton-1", "proton-2", "proton-3"):
        _write_state(tmp_path / f"{n}.state", "ok", 80.0, now)
    return [("proton-1", 1), ("proton-2", 2), ("proton-3", 3)]


def test_pick_prefers_clean_and_playable_then_clean_then_playable(tmp_path: Path) -> None:
    now = 1_800_000_000
    inst = _three_equal_slots(tmp_path, now)
    # 1: challenged + playable, 2: clean + gated, 3: clean + playable
    _cf(tmp_path / ".cf-state.proton-1", "no", now - 10, "discord.com")
    _pl(tmp_path / ".playability-state.proton-2", "no", now - 10)
    assert pick_distributed(inst, str(tmp_path), {}, now=now) == ("proton-3", 3)
    # drop slot 3: clean beats playable
    inst2 = inst[:2]
    assert pick_distributed(inst2, str(tmp_path), {}, now=now) == ("proton-2", 2)
    # only challenged-but-playable and challenged-and-gated: playable wins
    _cf(tmp_path / ".cf-state.proton-2", "no", now - 10, "discord.com")
    assert pick_distributed(inst2, str(tmp_path), {}, now=now) == ("proton-1", 1)


def test_pick_keeps_full_set_when_every_slot_is_challenged_and_gated(tmp_path: Path) -> None:
    now = 1_800_000_000
    inst = _three_equal_slots(tmp_path, now)
    for n in ("proton-1", "proton-2", "proton-3"):
        _cf(tmp_path / f".cf-state.{n}", "no", now - 10, "discord.com")
        _pl(tmp_path / f".playability-state.{n}", "no", now - 10)
    assert pick_distributed(inst, str(tmp_path), {2: 0, 1: 5, 3: 5}, now=now) == ("proton-2", 2)


def test_pick_cf_bias_only_narrows_within_scored_slots(tmp_path: Path) -> None:
    now = 1_800_000_000
    inst = _three_equal_slots(tmp_path, now)
    _write_state(tmp_path / "proton-3.state", "degraded", 99.0, now)      # degraded stays out
    _cf(tmp_path / ".cf-state.proton-1", "no", now - 10, "discord.com")
    assert pick_distributed(inst, str(tmp_path), {}, now=now) == ("proton-2", 2)


def test_cf_bias_is_off_in_advisory_tier(tmp_path: Path, monkeypatch) -> None:
    """Shadow mode records verdicts but never acts, including on new-pin placement."""
    now = 1_800_000_000
    inst = _three_equal_slots(tmp_path, now)
    _cf(tmp_path / ".cf-state.proton-1", "no", now - 10, "discord.com")
    _cf(tmp_path / ".cf-state.proton-2", "no", now - 10, "discord.com")
    monkeypatch.setattr(dispatcher_logic, "CF_BIAS", False)
    assert pick_distributed(inst, str(tmp_path), {3: 5, 1: 0, 2: 0}, now=now) == ("proton-1", 1)
    monkeypatch.setattr(dispatcher_logic, "CF_BIAS", True)
    assert pick_distributed(inst, str(tmp_path), {3: 5, 1: 0, 2: 0}, now=now) == ("proton-3", 3)


# --- pinning trusted sources -------------------------------------------------
def test_is_pinnable_source_accepts_a_sequence_of_ranges() -> None:
    cidrs = ["172.16.1.0/24", "192.168.7.0/24", "10.99.99.0/30"]
    assert is_pinnable_source("172.16.1.50", cidrs)
    assert is_pinnable_source("192.168.7.9", cidrs)
    assert is_pinnable_source("10.99.99.2", cidrs)
    assert not is_pinnable_source("10.44.0.1", cidrs)
    assert not is_pinnable_source("0.0.0.0", cidrs)
    assert not is_pinnable_source("not-an-ip", cidrs)


def test_is_pinnable_source_still_takes_a_bare_string() -> None:
    """Existing callers and tests pass one CIDR; that must keep working."""
    assert is_pinnable_source("172.16.1.50", "172.16.1.0/24")
    assert not is_pinnable_source("192.168.7.9", "172.16.1.0/24")


def test_is_pinnable_source_rejects_network_and_broadcast_per_range() -> None:
    cidrs = ["172.16.1.0/24", "192.168.7.0/24"]
    for junk in ("172.16.1.0", "172.16.1.255", "192.168.7.0", "192.168.7.255"):
        assert not is_pinnable_source(junk, cidrs), junk


def test_is_pinnable_source_handles_a_single_host_range() -> None:
    """A /32 is how one infra host is trusted without trusting its subnet. Its
    only address is both network and broadcast, so the junk-address guard must
    not swallow it."""
    assert is_pinnable_source("172.20.0.150", ["172.20.0.150/32"])
    assert not is_pinnable_source("172.20.0.151", ["172.20.0.150/32"])
    assert is_pinnable_source("10.99.99.2", ["10.99.99.2/31"])


def test_is_pinnable_source_skips_malformed_ranges_without_failing_the_rest() -> None:
    assert is_pinnable_source("192.168.7.9", ["not-a-cidr", "192.168.7.0/24"])


# --- recognising the masqueraded tunnel source -------------------------------
from dispatcher_logic import is_udm_tunnel_source


def test_is_udm_tunnel_source_matches_every_address_in_the_subnet() -> None:
    """Both tunnel endpoints count. The UDM's own .2 is what production sees,
    but nothing about the rule depends on which end sent the packet: any source
    inside the tunnel is a source the router already rewrote."""
    for ip in ("10.99.99.1", "10.99.99.2"):
        assert is_udm_tunnel_source(ip, "10.99.99.0/30"), ip


def test_is_udm_tunnel_source_rejects_client_vlan_and_trusted_hosts() -> None:
    """The client VLAN keeps per-source pinning; only tunnel traffic loses it.

    A trusted host's own address is included deliberately: if a future router
    stops masquerading, those packets arrive with real per-host sources and
    should be pinned normally rather than caught by this predicate."""
    for ip in ("172.16.1.50", "192.168.7.9", "8.8.8.8"):
        assert not is_udm_tunnel_source(ip, "10.99.99.0/30"), ip


def test_is_udm_tunnel_source_is_false_without_a_usable_tunnel_cidr() -> None:
    """dispatcher.UDM_TUNNEL_CIDR is None when the env value failed validation,
    and a malformed literal must not raise on the packet path — an exception in
    handle() aborts before the packet is verdicted."""
    assert not is_udm_tunnel_source("10.99.99.2", None)
    assert not is_udm_tunnel_source("10.99.99.2", "")
    assert not is_udm_tunnel_source("10.99.99.2", "not-a-cidr")
    assert not is_udm_tunnel_source("not-an-ip", "10.99.99.0/30")


def test_is_udm_tunnel_source_follows_a_relocated_tunnel() -> None:
    """PROTEUS_UDM_TUNNEL_CIDR is site-settable, so the check reads the
    configured subnet rather than a baked-in 10.99.99.0/30."""
    assert is_udm_tunnel_source("10.98.98.2", "10.98.98.0/30")
    assert not is_udm_tunnel_source("10.99.99.2", "10.98.98.0/30")


# --- the janitor's drain of stopped or removed slots --------------------------

from dispatcher_logic import (  # noqa: E402
    LIVE_SLOT_MARKS, load_state_files, unclaimed_slot_marks,
)


def test_load_state_files_keeps_every_instance(tmp_path: Path) -> None:
    """The drain needs to know which marks are claimed by ANY tunnel that is
    up, not only by the slots the dispatcher hands out."""
    (tmp_path / "proton-1.state").write_text("INSTANCE=proton-1\nFWMARK=0x1\n")
    (tmp_path / "proton-1-s.state").write_text("INSTANCE=proton-1-s\nFWMARK=0x65\n")
    (tmp_path / "dns-6.state").write_text("INSTANCE=dns-6\nFWMARK=0x6\n")
    (tmp_path / "broken.state").write_text("INSTANCE=broken\n")
    assert sorted(load_state_files(str(tmp_path))) == [
        ("dns-6", 0x6), ("proton-1", 0x1), ("proton-1-s", 0x65)]
    assert load_instances(str(tmp_path)) == [("proton-1", 0x1)]


def test_a_broken_state_file_warns_once_not_every_janitor_pass(
        tmp_path: Path, caplog) -> None:
    """The janitor re-reads every state file (dns-6 and staging copies too)
    once a minute. A file that stays broken warns once; it warns again when
    its problem changes, or when it breaks again after a good read."""
    import logging
    caplog.set_level(logging.WARNING, logger="dispatcher")
    bad = tmp_path / "dns-6.state"
    (tmp_path / "proton-1.state").write_text("INSTANCE=proton-1\nFWMARK=0x1\n")

    def warnings() -> list[str]:
        out = [r.getMessage() for r in caplog.records]
        caplog.clear()
        return out

    bad.write_text("INSTANCE=dns-6\nFWMARK=zz\n")
    for _ in range(3):
        assert load_state_files(str(tmp_path)) == [("proton-1", 0x1)]
    assert warnings() == [f"bad FWMARK in {bad}: 'zz'"]

    bad.write_text("INSTANCE=dns-6\nFWMARK=0xq\n")
    load_state_files(str(tmp_path))
    load_state_files(str(tmp_path))
    assert warnings() == [f"bad FWMARK in {bad}: '0xq'"], "a new problem warns"

    bad.write_text("INSTANCE=dns-6\nFWMARK=0x6\n")
    load_state_files(str(tmp_path))
    bad.write_text("INSTANCE=dns-6\nFWMARK=0xq\n")
    load_state_files(str(tmp_path))
    assert warnings() == [f"bad FWMARK in {bad}: '0xq'"], \
        "broken again after a good read warns again"

    bad.unlink()
    bad.mkdir()                                 # open() fails: IsADirectoryError
    load_state_files(str(tmp_path))
    load_state_files(str(tmp_path))
    msgs = warnings()
    assert len(msgs) == 1 and msgs[0].startswith(f"could not read {bad}: "), msgs


def test_unclaimed_slot_marks_are_live_slot_marks_nothing_claims() -> None:
    entries = [("proton-1", 0x1), ("proton-2", 0x2), ("dns-6", 0x6),
               ("proton-1-s", 0x65), ("custom-7", 0x7)]
    out = unclaimed_slot_marks(entries)
    assert 0x3 in out                       # a stopped proton-3
    assert {0x1, 0x2} & out == set()        # live slots
    assert 0x6 not in out and 0x7 not in out, \
        "a mark claimed by a non-slot tunnel's state file is not a slot's"
    assert out <= LIVE_SLOT_MARKS
    assert LIVE_SLOT_MARKS == frozenset(range(1, 100))
    for never in (0x0, 0x65, 0xc7, 0x100, 0x1234):
        assert never not in out, hex(never)


def test_unclaimed_slot_marks_leaves_out_the_excluded_dns_mark() -> None:
    """The DNS tunnel's index sits inside the slot range; while it is down no
    state file claims it, so the caller excludes it by value."""
    out = unclaimed_slot_marks([("proton-1", 0x1)], exclude=[0x63])
    assert 0x63 not in out and 0x62 in out


def test_unclaimed_slot_marks_is_none_without_a_live_slot() -> None:
    """The empty-list guard: a read listing no live slot (a state dir caught
    mid-rewrite, or every file unreadable) must not make every mark drainable."""
    assert unclaimed_slot_marks([]) is None
    assert unclaimed_slot_marks([("dns-6", 0x6), ("proton-1-s", 0x65)]) is None


# --- reading back the mark of an element that clashed ------------------------

from dispatcher_logic import parse_get_element_mark  # noqa: E402

# `nft get element` output, captured from nft 1.1.3 in a scratch netns.
_GET_PIN = """table inet filter {
\tmap source_pin {
\t\ttype ipv4_addr : mark
\t\tsize 256
\t\ttimeout 6h
\t\telements = { 172.16.1.50 timeout 30s expires 29s997ms : 0x0000002a }
\t}
}
"""
_GET_DEST = """table inet filter {
\tmap vpn_dispatch {
\t\ttype ipv4_addr : mark
\t\ttimeout 12h
\t\telements = { 203.0.113.10 expires 11h59m59s997ms : 0x00000001 }
\t}
}
"""


def test_parse_get_element_mark_reads_nft_1_1_3_output() -> None:
    assert parse_get_element_mark(_GET_PIN, "172.16.1.50") == 0x2a
    assert parse_get_element_mark(_GET_DEST, "203.0.113.10") == 0x1
    assert parse_get_element_mark(
        "elements = { 203.0.113.10 : 0x00000003 }", "203.0.113.10") == 0x3
    assert parse_get_element_mark(
        "elements = { 203.0.113.10 : 7 }", "203.0.113.10") == 7


def test_parse_get_element_mark_refuses_anything_else() -> None:
    assert parse_get_element_mark(_GET_PIN, "172.16.1.5") is None, \
        "a key that is a prefix of the listed one is a different host"
    assert parse_get_element_mark(_GET_PIN, "172.16.1.51") is None
    assert parse_get_element_mark("", "172.16.1.50") is None
    assert parse_get_element_mark(None, "172.16.1.50") is None
    assert parse_get_element_mark("elements = { 172.16.1.50 : }", "172.16.1.50") is None
