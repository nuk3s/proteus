"""Tests for etc/proteus/bin/ledger.py — the exit ledger (pure logic + file IO)."""
from __future__ import annotations
import json
import threading
import time
from pathlib import Path

import ledger

NOW = 1_800_000_000
H = ["discord.com", "www.patreon.com"]


def rec(ts, exit_ip, entry_ip="10.0.0.1", source="gate", verdict="pass",
        canaries=None, checks=None, slot="proton-1"):
    return {"ts": ts, "exit_ip": exit_ip, "entry_ip": entry_ip, "logical": "US-XX#1",
            "slot": slot, "source": source, "verdict": verdict,
            "canaries": canaries if canaries is not None else {h: "clean" for h in H},
            "checks": checks or {}, "standing": 2, "of": 2}


# RFC 1918 stand-ins: just two distinct exit_ip values to check roundtrip
# ordering, not real addresses.
def test_append_and_load_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    ledger.append(str(p), rec(NOW, "10.210.0.1"))
    ledger.append(str(p), rec(NOW + 1, "10.210.0.2"))
    got = ledger.load(str(p))
    assert [r["exit_ip"] for r in got] == ["10.210.0.1", "10.210.0.2"]


def test_load_skips_malformed_lines_and_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    p.write_text('{"ts": 1, "exit_ip": "a"}\nnot json\n[1,2]\n\n')
    assert [r["exit_ip"] for r in ledger.load(str(p))] == ["a"]
    assert ledger.load(str(tmp_path / "missing.jsonl")) == []


def test_load_since_filters_old_records(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    ledger.append(str(p), rec(NOW - 100, "old"))
    ledger.append(str(p), rec(NOW, "new"))
    assert [r["exit_ip"] for r in ledger.load(str(p), since=NOW)] == ["new"]


def test_meets_and_fails_standard() -> None:
    clean = rec(NOW, "a")
    chal = rec(NOW, "a", canaries={"discord.com": "clean", "www.patreon.com": "challenge"})
    blk = rec(NOW, "a", canaries={"discord.com": "block-1020", "www.patreon.com": "clean"})
    skip = rec(NOW, "a", canaries={"discord.com": "clean", "www.patreon.com": "not-cloudflare"})
    assert ledger.meets_standard(clean, H)
    assert not ledger.meets_standard(chal, H)
    assert ledger.fails_standard(chal, H)
    assert ledger.fails_standard(blk, H)
    assert not ledger.fails_standard(skip, H)
    assert not ledger.meets_standard(skip, H)
    assert ledger.meets_standard(skip, ["discord.com"])   # standard = active hosts only
    assert ledger.meets_standard(clean, [])               # empty standard: everything meets it


def test_pool_is_good_within_ttl_minus_recent_fails() -> None:
    recs = [
        rec(NOW - 3 * 86400, "good"),                                  # met standard 3d ago
        rec(NOW - 20 * 86400, "expired"),                              # older than 14d ttl
        rec(NOW - 3 * 86400, "flipped"),                               # good 3d ago...
        rec(NOW - 3600, "flipped", canaries={"discord.com": "challenge", "www.patreon.com": "clean"}),
        rec(NOW - 3600, "custom-fail", verdict="fail"),                # rejected by an operator custom check
        rec(NOW - 3 * 86400, "custom-fail"),
        rec(NOW - 3600, "promoted-only", source="promote"),            # promote records don't count
    ]
    assert ledger.pool(recs, H, NOW) == {"good"}
    assert ledger.pool(recs, H, NOW, key="entry_ip") == set()          # all share entry 10.0.0.1 and one failed


def test_recent_fail_keys_and_last_promoted() -> None:
    recs = [
        rec(NOW - 3600, "x", entry_ip="e1", verdict="fail"),
        rec(NOW - 2 * 86400, "y", entry_ip="e2", verdict="fail"),      # outside 24h window
        rec(NOW - 10, "z", entry_ip="e3", source="promote"),
        rec(NOW - 100, "z", entry_ip="e3", source="promote"),
    ]
    assert ledger.recent_fail_keys(recs, H, NOW) == {"x"}
    assert ledger.recent_fail_keys(recs, H, NOW, key="entry_ip") == {"e1"}
    assert ledger.last_promoted(recs) == {"z": NOW - 10}
    assert ledger.last_promoted(recs, key="entry_ip") == {"e3": NOW - 10}


def test_last_failed_keeps_max_ts_and_ignores_promotes() -> None:
    recs = [
        rec(NOW - 3 * 86400, "x", verdict="fail"),
        rec(NOW - 1 * 86400, "x", verdict="fail"),
        rec(NOW - 10, "x", source="promote"),                          # promote records ignored
        rec(NOW - 5, "y"),                                             # clean record, not a failure
    ]
    assert ledger.last_failed(recs, H) == {"x": NOW - 1 * 86400}


def test_last_failed_keyed_by_entry_ip() -> None:
    recs = [
        rec(NOW - 3600, "a", entry_ip="e1", verdict="fail"),
        rec(NOW - 100, "b", entry_ip="e1", canaries={"discord.com": "challenge", "www.patreon.com": "clean"}),
    ]
    assert ledger.last_failed(recs, H, key="entry_ip") == {"e1": NOW - 100}


def test_per_canary_counts_distinct_exits_and_ignores_skips() -> None:
    recs = [
        rec(NOW - 10, "a", canaries={"discord.com": "clean"}),
        rec(NOW - 20, "a", canaries={"discord.com": "challenge"}),     # same exit, counted once
        rec(NOW - 30, "b", canaries={"discord.com": "challenge"}),
        rec(NOW - 40, "c", canaries={"discord.com": "not-cloudflare"}),
        rec(NOW - 50, "d", canaries={"discord.com": "transport"}),
        rec(NOW - 2 * 86400, "e", canaries={"discord.com": "challenge"}),
    ]
    assert ledger.per_canary(recs, "discord.com", NOW) == (2, 1)


def test_quarantine_needs_min_exits_all_failing() -> None:
    fails = [rec(NOW - i, f"10.1.1.{i}", canaries={"discord.com": "challenge"}) for i in range(1, 9)]
    assert ledger.quarantined(fails, "discord.com", NOW, min_exits=8)
    assert not ledger.quarantined(fails[:7], "discord.com", NOW, min_exits=8)
    one_clean = fails + [rec(NOW - 99, "10.1.1.99", canaries={"discord.com": "clean"})]
    assert not ledger.quarantined(one_clean, "discord.com", NOW, min_exits=8)


def test_attainable_presumed_true_on_thin_ledger() -> None:
    recs = [rec(NOW - 10, "a", verdict="fail")] * 5
    assert ledger.attainable(recs, H, NOW, slots=5)


def test_attainable_needs_slots_distinct_passing_exits_in_24h() -> None:
    fails = [rec(NOW - i, f"10.2.2.{i}", verdict="fail",
                 canaries={"discord.com": "challenge", "www.patreon.com": "clean"}) for i in range(1, 12)]
    goods = [rec(NOW - 100 - i, f"10.3.3.{i}") for i in range(1, 6)]
    assert ledger.attainable(fails + goods, H, NOW, slots=5)
    assert not ledger.attainable(fails + goods[:4], H, NOW, slots=5)
    old_goods = [rec(NOW - 2 * 86400 - i, f"10.4.4.{i}") for i in range(1, 6)]
    assert not ledger.attainable(fails + old_goods, H, NOW, slots=5)


# RFC 1918 stand-ins: 10.211.12.4/.5 share a /24 (two distinct exits, one net);
# 10.212.22.9 is a second distinct net within the window; 10.213.33.8 is
# outside the 7-day window; 10.214.44.7 is not a promote record. None of these
# are real provider addresses.
def test_diversity_counts_promotions_by_exit_and_slash24() -> None:
    recs = [rec(NOW - 10, "10.211.12.4", source="promote"),
            rec(NOW - 20, "10.211.12.5", source="promote"),
            rec(NOW - 30, "10.212.22.9", source="promote"),
            rec(NOW - 8 * 86400, "10.213.33.8", source="promote"),
            rec(NOW - 40, "10.214.44.7")]
    assert ledger.diversity(recs, NOW, 7 * 86400) == (3, 2)


def test_status_shape() -> None:
    recs = [rec(NOW - 10, "a"), rec(NOW - 20, "b", source="promote")]
    st = ledger.status(recs, H, NOW, slots=5, target=20, min_exits=8)
    assert [c["host"] for c in st["canaries"]] == H
    assert st["canaries"][0] == {"host": "discord.com", "exits_seen_24h": 1,
                                 "pass_rate_24h": 1.0, "quarantined": False}
    assert st["standard"] == {"size": 2, "attainable": True, "passing_exits_24h": 1}
    assert st["pool"] == {"known_good": 1, "target": 20, "distinct_exits_7d": 1, "distinct_slash24_7d": 1}


def test_status_excludes_quarantined_from_standard() -> None:
    recs = [rec(NOW - i, f"10.5.5.{i}", canaries={"discord.com": "challenge", "www.patreon.com": "clean"})
            for i in range(1, 9)]
    st = ledger.status(recs, H, NOW, slots=1, target=20, min_exits=8)
    assert st["canaries"][0]["quarantined"] is True
    assert st["standard"]["size"] == 1


def test_compact_drops_expired(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    ledger.append(str(p), rec(NOW - 20 * 86400, "old"))
    ledger.append(str(p), rec(NOW, "new"))
    assert ledger.compact(str(p), NOW) == 1
    assert [r["exit_ip"] for r in ledger.load(str(p))] == ["new"]


def test_canary_hosts_default_and_file(tmp_path: Path) -> None:
    assert ledger.canary_urls(str(tmp_path / "missing.json")) == ledger.DEFAULT_CANARIES
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"canaries": [{"url": "https://a.invalid/"}, {"url": "http://b.invalid/"},
                                          {"url": "https://a.invalid/"}, {"url": "https://c.invalid/x y"}]}))
    assert ledger.canary_urls(str(f)) == ["https://a.invalid/"]
    f.write_text("garbage")
    assert ledger.canary_urls(str(f)) == ledger.DEFAULT_CANARIES
    f.write_text(json.dumps({"canaries": []}))
    assert ledger.canary_urls(str(f)) == ledger.DEFAULT_CANARIES
    # userinfo: host_of would report a.invalid, curl would fetch evil.invalid
    f.write_text(json.dumps({"canaries": [{"url": "https://a.invalid@evil.invalid/"}]}))
    assert ledger.canary_urls(str(f)) == ledger.DEFAULT_CANARIES
    assert ledger.host_of("https://www.example.invalid/path?x=1") == "www.example.invalid"
    assert ledger.host_of("https://example.invalid:8443/") == "example.invalid"


def test_fail_window_boundary_is_inclusive() -> None:
    at_boundary = rec(NOW - ledger.FAIL_WINDOW_S, "in",
                       canaries={"discord.com": "challenge", "www.patreon.com": "clean"})
    past_boundary = rec(NOW - ledger.FAIL_WINDOW_S - 1, "out",
                         canaries={"discord.com": "challenge", "www.patreon.com": "clean"})
    assert ledger.recent_fail_keys([at_boundary], H, NOW) == {"in"}
    assert ledger.recent_fail_keys([past_boundary], H, NOW) == set()


def test_ttl_boundary_is_inclusive() -> None:
    at_boundary = rec(NOW - ledger.DEFAULT_TTL_S, "in")
    past_boundary = rec(NOW - ledger.DEFAULT_TTL_S - 1, "out")
    assert ledger.pool([at_boundary], H, NOW) == {"in"}
    assert ledger.pool([past_boundary], H, NOW) == set()


def test_main_quarantined_and_attainable_exit_codes(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    now = int(time.time())
    for i in range(1, 12):
        ledger.append(str(p), rec(now - i, f"10.6.6.{i}", canaries={"discord.com": "challenge"}))
    assert ledger.main(["quarantined", "--path", str(p), "--host", "discord.com"]) == 0
    assert ledger.main(["quarantined", "--path", str(p), "--host", "www.patreon.com"]) == 1
    assert ledger.main(["attainable", "--path", str(p), "--hosts", "discord.com", "--slots", "1"]) == 1
    ledger.append(str(p), rec(now - 50, "10.7.7.1"))
    assert ledger.main(["attainable", "--path", str(p), "--hosts", "discord.com", "--slots", "1"]) == 0


def test_main_returns_3_when_a_record_breaks_the_query(tmp_path: Path) -> None:
    """A ledger whose "canaries" field is a string, not an object, makes the
    quarantine query raise. checklib's cf_quarantined demotes the canary on any
    exit code but 0 and 1, so that path only fires if the crash keeps clear of
    them: exit 1 has to keep meaning "not quarantined"."""
    p = tmp_path / "l.jsonl"
    p.write_text(json.dumps({"ts": int(time.time()), "exit_ip": "a",
                             "source": "gate", "canaries": "boom"}) + "\n")
    assert ledger.main(["quarantined", "--path", str(p), "--host", "h"]) == 3


def test_main_append_defaults_verdict_pass_and_enters_pool(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    rc = ledger.main(["append", "--path", str(p), "--exit-ip", "9.9.9.9", "--entry-ip", "1.1.1.1",
                       "--logical", "US-XX#1", "--slot", "proton-1", "--source", "gate",
                       "--canaries", "discord.com=clean"])
    assert rc == 0
    recs = ledger.load(str(p))
    assert recs[0]["verdict"] == "pass"
    assert "9.9.9.9" in ledger.pool(recs, ["discord.com"], int(time.time()))


def test_main_append_hosts_are_stripped(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    now = int(time.time())
    ledger.append(str(p), rec(now - 10, "a"))
    assert ledger.main(["attainable", "--path", str(p), "--hosts", " discord.com , www.patreon.com ",
                         "--slots", "1"]) == 0


def test_auto_compaction_on_append_drops_expired_and_keeps_newest(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    now = int(time.time())
    old_ts = now - ledger.DEFAULT_TTL_S - 100
    with open(p, "w") as f:
        for i in range(2001):
            r = rec(old_ts, f"10.8.{i // 256}.{i % 256}")
            f.write(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n")
    assert sum(1 for _ in open(p)) == 2001
    rc = ledger.main(["append", "--path", str(p), "--exit-ip", "9.9.9.9", "--entry-ip", "1.1.1.1",
                       "--logical", "US-XX#1", "--slot", "proton-1", "--source", "gate"])
    assert rc == 0
    recs = ledger.load(str(p))
    assert len(recs) < 2001
    assert recs[-1]["exit_ip"] == "9.9.9.9"


def test_concurrent_append_and_compact_do_not_lose_or_corrupt_records(tmp_path: Path) -> None:
    p = tmp_path / "l.jsonl"
    now = int(time.time())
    n_writers, n_each = 4, 200
    errors: list[Exception] = []

    def writer(idx: int) -> None:
        try:
            for i in range(n_each):
                ledger.append(str(p), rec(now - i, f"10.9.{idx}.{i % 256}"))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def compactor() -> None:
        try:
            ledger.compact(str(p), now)
            ledger.compact(str(p), now)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(n_writers)]
    ct = threading.Thread(target=compactor)
    for t in threads:
        t.start()
    ct.start()
    for t in threads:
        t.join()
    ct.join()

    assert not errors
    lines = [line for line in p.read_text().splitlines() if line.strip()]
    recs = [json.loads(line) for line in lines]  # raises if any line is corrupt/spliced
    assert len(recs) == n_writers * n_each


def test_canary_urls_survives_odd_shapes(tmp_path: Path) -> None:
    f = tmp_path / "c.json"
    for bad in ('{"canaries": 5}', '{"canaries": {"url": "https://a.invalid/"}}', '[1, 2]', '"str"', "null"):
        f.write_text(bad)
        assert ledger.canary_urls(str(f)) == ledger.DEFAULT_CANARIES, bad


def test_host_of_cuts_at_a_fragment() -> None:
    assert ledger.host_of("https://a.invalid#frag") == "a.invalid"
    assert ledger.host_of("https://a.invalid:8443/x#y") == "a.invalid"


# From here down, the "provider range" literals (10.50, 10.60, 10.70, 10.90,
# 10.100, 10.110, 10.120, 10.130, 10.140, 10.150) are deliberate RFC 1918
# stand-ins for real VPN entry/exit ranges. The publish gate rejects real
# provider addresses, and restoring realistic-looking values here would leak
# which ranges the gateway uses.
def test_slash16_is_the_first_two_octets() -> None:
    assert ledger.slash16("10.50.1.2") == "10.50"
    assert ledger.slash16("10.0.0.1") == "10.0"


def test_banned_prefixes_from_a_check_are_entry_ranges_and_exits_are_separate() -> None:
    recs = [rec(NOW - 100, "10.50.1.2", entry_ip="10.110.3.4",
                checks={"custom:x.invalid": "block-1005"}, verdict="fail")]
    # mint only ever knows entry IPs, so that is what the acting set holds.
    assert ledger.banned_prefixes(recs, NOW) == {"10.110"}
    assert ledger.banned_exit_prefixes(recs, NOW) == {"10.50"}


def test_banned_prefixes_from_a_canary_count_too() -> None:
    recs = [rec(NOW - 100, "10.120.5.6", entry_ip="10.120.9.9", source="live",
                canaries={"discord.com": "block-1005"}, verdict="fail")]
    assert ledger.banned_prefixes(recs, NOW) == {"10.120"}


def test_canary_1005s_can_be_ignored_but_check_1005s_never_are() -> None:
    canary = [rec(NOW, "10.50.1.2", entry_ip="10.110.3.4",
                  canaries={"discord.com": "block-1005"}, verdict="fail")]
    assert ledger.banned_prefixes(canary, NOW, canaries=False) == set()
    assert ledger.banned_exit_prefixes(canary, NOW, canaries=False) == set()
    check = [rec(NOW, "10.50.1.2", entry_ip="10.110.3.4",
                 checks={"custom:x.invalid": "block-1005"}, verdict="fail")]
    assert ledger.banned_prefixes(check, NOW, canaries=False) == {"10.110"}


def test_banned_prefixes_ignores_other_block_classes() -> None:
    recs = [rec(NOW - 100, "10.50.1.2", entry_ip="10.110.3.4",
                canaries={"discord.com": "block-1020"},
                checks={"custom:x.invalid": "challenge"}, verdict="fail")]
    assert ledger.banned_prefixes(recs, NOW) == set()
    assert ledger.banned_exit_prefixes(recs, NOW) == set()


def test_banned_prefixes_expire_with_the_window() -> None:
    recs = [rec(NOW - 8 * 86400, "10.50.1.2", entry_ip="10.110.3.4",
                checks={"custom:x.invalid": "block-1005"}, verdict="fail")]
    assert ledger.banned_prefixes(recs, NOW) == set()
    assert ledger.banned_prefixes(recs, NOW, window_s=9 * 86400) == {"10.110"}


def test_banned_prefixes_ignores_promote_records() -> None:
    recs = [rec(NOW - 100, "10.50.1.2", entry_ip="10.110.3.4", source="promote",
                checks={"custom:x.invalid": "block-1005"})]
    assert ledger.banned_prefixes(recs, NOW) == set()


def test_banned_prefixes_survives_odd_records() -> None:
    recs = [
        rec(NOW, "10.50.1.2", entry_ip="10.110.3.4", checks={"custom:x.invalid": "block-1005"}),
        rec(NOW, "10.50.1.3", entry_ip="", checks={"custom:x.invalid": "block-1005"}),
        {"ts": NOW, "source": "gate", "canaries": "not-a-dict", "checks": ["nor", "this"],
         "exit_ip": "10.216.3.4", "entry_ip": "10.217.7.8"},
        {"ts": NOW, "source": "gate", "checks": {"custom:x.invalid": "block-1005"},
         "exit_ip": None, "entry_ip": 12345},
    ]
    assert ledger.banned_prefixes(recs, NOW) == {"10.110"}
    assert ledger.banned_exit_prefixes(recs, NOW) == {"10.50"}


def test_good_prefixes_marks_ranges_that_produced_a_pass() -> None:
    recs = [rec(NOW - 100, "10.60.1.2", entry_ip="10.70.251.132")]
    assert ledger.good_prefixes(recs, NOW) == {"10.70"}


def test_good_prefixes_ignores_failures_and_promotions() -> None:
    fail = [rec(NOW - 100, "10.60.1.2", entry_ip="10.90.1.1", verdict="fail")]
    assert ledger.good_prefixes(fail, NOW) == set()
    # A canary failure is a fail even with verdict=pass on the record.
    chal = [rec(NOW - 100, "10.60.1.2", entry_ip="10.90.1.1", verdict="fail",
                canaries={"discord.com": "challenge", "www.patreon.com": "clean"})]
    assert ledger.good_prefixes(chal, NOW) == set()
    # promote records say an exit went live, not which canaries it passed.
    promo = [rec(NOW - 100, "10.60.1.2", entry_ip="10.130.4.4", source="promote")]
    assert ledger.good_prefixes(promo, NOW) == set()


def test_good_prefixes_respect_the_window() -> None:
    recs = [rec(NOW - 8 * 86400, "10.60.1.2", entry_ip="10.100.7.7")]
    assert ledger.good_prefixes(recs, NOW) == set()
    assert ledger.good_prefixes(recs, NOW, window_s=9 * 86400) == {"10.100"}


def test_good_prefixes_survive_a_non_string_entry_ip() -> None:
    recs = [{"ts": NOW, "source": "gate", "verdict": "pass", "entry_ip": 12345},
            {"ts": NOW, "source": "gate", "verdict": "pass", "entry_ip": None},
            {"ts": NOW, "source": "live", "verdict": "pass", "entry_ip": "10.140.9.9"}]
    assert ledger.good_prefixes(recs, NOW) == {"10.140"}


# exit_ip values here are unrelated RFC 1918 filler; only entry_ip is checked.
def test_good_prefixes24_marks_passing_entry_subnets() -> None:
    recs = [rec(NOW - 10, "10.218.1.1", entry_ip="10.100.217.216"),
            rec(NOW - 20, "10.218.1.2", entry_ip="10.100.221.205", verdict="fail"),
            rec(NOW - 30, "10.218.1.3", entry_ip="10.70.251.130", source="promote"),
            rec(NOW - 8 * 86400, "10.218.1.4", entry_ip="10.150.1.1")]
    assert ledger.good_prefixes24(recs, NOW) == {"10.100.217"}
    assert ledger.slash24("10.100.217.216") == "10.100.217"
