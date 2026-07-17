"""Tests for etc/multivpn/bin/serverlist_cache.py — pure repair logic."""
import json
from pathlib import Path

from serverlist_cache import repair, is_valid_json


VALID = json.dumps({"LogicalServers": [{"id": 1}], "MaxTier": 2})


def test_valid_cache_is_left_alone_and_snapshotted(tmp_path: Path) -> None:
    cache = tmp_path / "serverlist.json"
    good = tmp_path / "serverlist.json.lastgood"
    cache.write_text(VALID)

    assert repair(str(cache), str(good)) == "valid"
    assert is_valid_json(str(cache))
    # A known-good snapshot is now maintained.
    assert good.read_text() == VALID


def test_tail_junk_is_truncated(tmp_path: Path) -> None:
    """Concurrent-write corruption: valid document + stray trailing byte(s)."""
    cache = tmp_path / "serverlist.json"
    good = tmp_path / "serverlist.json.lastgood"
    cache.write_text(VALID + "\x00garbage")

    assert repair(str(cache), str(good)) == "truncated"
    assert is_valid_json(str(cache))
    assert json.loads(cache.read_text()) == json.loads(VALID)


def test_midfile_corruption_restored_from_snapshot(tmp_path: Path) -> None:
    """Interrupted-write corruption: no valid leading document -> use snapshot."""
    cache = tmp_path / "serverlist.json"
    good = tmp_path / "serverlist.json.lastgood"
    good.write_text(VALID)
    cache.write_text('{"LogicalServers": [{"id": 1}, {"id": ')  # truncated mid-object

    assert repair(str(cache), str(good)) == "restored"
    assert cache.read_text() == VALID


def test_midfile_corruption_without_snapshot_is_quarantined(tmp_path: Path) -> None:
    cache = tmp_path / "serverlist.json"
    good = tmp_path / "serverlist.json.lastgood"
    cache.write_text('{"LogicalServers": [{"id": ')  # unrepairable, no snapshot

    assert repair(str(cache), str(good)) == "quarantined"
    assert not cache.exists()
    assert (tmp_path / "serverlist.json.corrupt").exists()


def test_absent_cache_restored_from_snapshot(tmp_path: Path) -> None:
    cache = tmp_path / "serverlist.json"
    good = tmp_path / "serverlist.json.lastgood"
    good.write_text(VALID)

    assert repair(str(cache), str(good)) == "absent-restored"
    assert cache.read_text() == VALID


def test_absent_cache_and_no_snapshot(tmp_path: Path) -> None:
    cache = tmp_path / "serverlist.json"
    good = tmp_path / "serverlist.json.lastgood"
    assert repair(str(cache), str(good)) == "absent"
    assert not cache.exists()


def test_corrupt_snapshot_not_used_for_restore(tmp_path: Path) -> None:
    """A corrupt snapshot must not be trusted — fall through to quarantine."""
    cache = tmp_path / "serverlist.json"
    good = tmp_path / "serverlist.json.lastgood"
    cache.write_text('{"LogicalServers": [{"id": ')   # unrepairable
    good.write_text('{"also": ')                       # snapshot also broken

    assert repair(str(cache), str(good)) == "quarantined"
    assert (tmp_path / "serverlist.json.corrupt").exists()
