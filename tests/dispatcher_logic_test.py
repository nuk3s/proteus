"""Tests for etc/multivpn/bin/dispatcher_logic.py — pure logic only."""
from pathlib import Path
import pytest

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
