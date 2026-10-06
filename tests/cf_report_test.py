"""Tests for etc/proteus/bin/proteus-cf-report (imported via importlib: no .py suffix)."""
from __future__ import annotations
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import ledger

ROOT = Path(__file__).resolve().parent.parent
_script = str(ROOT / "etc/proteus/bin/proteus-cf-report")
spec = importlib.util.spec_from_file_location("cf_report", _script, loader=SourceFileLoader("cf_report", _script))
cf_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf_report)

NOW = 1_800_000_000
DAY = 86400
H = ["discord.com", "www.patreon.com"]


def rec(ts, exit_ip, source="gate", verdict="pass", canaries=None, checks=None):
    return {"ts": ts, "exit_ip": exit_ip, "entry_ip": "e" + exit_ip, "logical": "L", "slot": "proton-1",
            "source": source, "verdict": verdict,
            "canaries": canaries if canaries is not None else {h: "clean" for h in H},
            "checks": checks or {}, "standing": 2, "of": 2}


def sample():
    recs = []
    # 6 candidates the custom check rejected; discord flags 5 of them, patreon 2
    for i in range(6):
        recs.append(rec(NOW - 100 - i, f"10.1.1.{i}", verdict="fail",
                        canaries={"discord.com": "challenge" if i < 5 else "clean",
                                  "www.patreon.com": "challenge" if i < 2 else "clean"},
                        checks={"custom:x.invalid": "challenge", "youtube": "clean"}))
    # 4 candidates it passed; discord flags none, patreon flags 1
    for i in range(4):
        recs.append(rec(NOW - 200 - i, f"10.2.2.{i}",
                        canaries={"discord.com": "clean", "www.patreon.com": "challenge" if i == 0 else "clean"},
                        checks={"custom:x.invalid": "clean"}))
    # promotions: one exit reused inside the week
    recs += [rec(NOW - 6 * DAY, "10.2.2.1", source="promote"),
             rec(NOW - 1 * DAY, "10.2.2.1", source="promote"),
             rec(NOW - 2 * DAY, "10.2.2.2", source="promote"),
             rec(NOW - 20 * DAY, "10.3.3.3", source="promote")]
    return recs


def test_agreement_table():
    a = cf_report.agreement(sample(), H, H, NOW)
    row = a["custom:x.invalid"]
    assert row["rejected"] == 6 and row["passed"] == 4
    assert row["discord.com"] == {"rejected_seen": 6, "rejected_flagged": 5,
                                  "passed_seen": 4, "passed_flagged": 0}
    assert row["www.patreon.com"] == {"rejected_seen": 6, "rejected_flagged": 2,
                                      "passed_seen": 4, "passed_flagged": 1}
    assert row["basket"] == {"rejected_seen": 6, "rejected_flagged": 5,
                             "passed_seen": 4, "passed_flagged": 1}


def test_agreement_denominators_exclude_non_verdicts_and_inactive_canaries():
    # discord.com gets a real verdict in every record; patreon reports
    # "transport" in the first record (not a real verdict, so it must not
    # count toward patreon's own denominator either), and patreon is treated
    # as inactive/quarantined so its flag on record "b" must not count
    # toward the basket even though the canary itself flagged it.
    recs = [
        rec(NOW, "a", verdict="fail", canaries={"discord.com": "challenge", "www.patreon.com": "transport"},
            checks={"custom:x.invalid": "challenge"}),
        rec(NOW, "b", verdict="fail", canaries={"discord.com": "clean", "www.patreon.com": "challenge"},
            checks={"custom:x.invalid": "challenge"}),
    ]
    a = cf_report.agreement(recs, H, ["discord.com"], NOW)
    row = a["custom:x.invalid"]
    assert row["rejected"] == 2
    assert row["discord.com"] == {"rejected_seen": 2, "rejected_flagged": 1,
                                  "passed_seen": 0, "passed_flagged": 0}
    assert row["www.patreon.com"] == {"rejected_seen": 1, "rejected_flagged": 1,
                                      "passed_seen": 0, "passed_flagged": 0}
    assert row["basket"] == {"rejected_seen": 2, "rejected_flagged": 1,
                             "passed_seen": 0, "passed_flagged": 0}


def test_agreement_ignores_errors_skips_and_non_custom():
    recs = [rec(NOW, "a", checks={"custom:x.invalid": "error", "youtube": "block"}),
            rec(NOW, "b", checks={"custom:x.invalid": "skip"})]
    assert cf_report.agreement(recs, H, H, NOW) == {}


def test_build_adds_diversity_and_7d_rates():
    st = cf_report.build(sample(), H, NOW, slots=5, target=20, min_exits=8)
    assert st["pool"]["promotions_7d"] == 3
    assert st["pool"]["reused_within_window_7d"] == 1
    assert st["pool"]["distinct_exits_7d"] == 2 and st["pool"]["distinct_exits_30d"] == 3
    d = next(c for c in st["canaries"] if c["host"] == "discord.com")
    assert d["exits_seen_7d"] == 10 and d["pass_rate_7d"] == 0.5
    assert st["records"] == len(sample())
    assert "agreement" in st and "custom:x.invalid" in st["agreement"]
    assert st["standard"]["slots"] == 5
    active = ledger.active_hosts(sample(), H, NOW, 8)
    assert st["standard"]["passing_exits_7d"] == len(ledger.pool(sample(), active, NOW, ttl_s=7 * DAY))


def test_render_mentions_quarantine_and_agreement():
    # 12 gate records in 24h (enough to judge), all rejected: discord is
    # quarantined (0 of 12 clean) and nothing met the standard, so it is not
    # attainable. patreon stays clean throughout, so it is the only active
    # canary and the only one that can drive the "basket" row.
    recs = [rec(NOW - i, f"10.9.9.{i}", canaries={"discord.com": "challenge", "www.patreon.com": "clean"},
                checks={"custom:x.invalid": "challenge"}, verdict="fail") for i in range(1, 13)]
    st = cf_report.build(recs, H, NOW, slots=5, target=20, min_exits=8)
    text = cf_report.render(st)
    assert "QUARANTINED" in text
    assert "custom:x.invalid" in text
    assert "not attainable" in text
    assert "basket (any active canary)" in text
    assert "slots: 5" in text
    assert "exits meeting it in 7d:" in text
    assert max(len(line) for line in text.splitlines()) < 100


def test_build_and_render_survive_malformed_records():
    recs = [
        {"ts": "abc"},  # missing everything else, non-numeric ts
        rec(NOW, "10.5.5.5", checks=["not", "a", "dict"]),
        rec(NOW, "10.5.5.6", canaries="not-a-dict"),
    ]
    st = cf_report.build(recs, H, NOW, slots=5, target=20, min_exits=8)
    text = cf_report.render(st)
    assert st["records"] == 3
    assert "Ledger records: 3" in text


def test_pct_none_is_four_chars():
    assert cf_report._pct(None) == " n/a"
    assert len(cf_report._pct(None)) == 4


def test_env_int_reads_quoted_and_unquoted_and_falls_back(tmp_path, monkeypatch):
    f1 = tmp_path / "a.env"
    f2 = tmp_path / "b.env"
    f1.write_text("PROTEUS_MINT_POOL_TARGET=15\n")
    f2.write_text('PROTEUS_CF_QUARANTINE_MIN_EXITS="9"\n')
    monkeypatch.setattr(cf_report, "ENV_FILES", (str(f1), str(f2)))
    assert cf_report.env_int("PROTEUS_MINT_POOL_TARGET", 20) == 15
    assert cf_report.env_int("PROTEUS_CF_QUARANTINE_MIN_EXITS", 8) == 9
    assert cf_report.env_int("PROTEUS_NO_SUCH_KEY", 42) == 42


def test_cli_counts_slots_from_state_dir(tmp_path: Path, capsys):
    (tmp_path / "proton-1.state").write_text("x")
    (tmp_path / "proton-2.state").write_text("x")
    p = tmp_path / "l.jsonl"
    rc = cf_report.main(["--path", str(p), "--canaries-file", str(tmp_path / "none.json"),
                         "--state-dir", str(tmp_path), "--target", "20", "--min-exits", "8",
                         "--json", "--now", str(NOW)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["standard"]["slots"] == 2


def test_cli_compact_missing_path_returns_1(tmp_path: Path, capsys):
    p = tmp_path / "does-not-exist.jsonl"
    rc = cf_report.main(["--path", str(p), "--compact", "--now", str(NOW)])
    assert rc == 1
    assert "no ledger" in capsys.readouterr().out


def test_cli_json_and_compact(tmp_path: Path, capsys):
    p = tmp_path / "l.jsonl"
    for r in sample() + [rec(NOW - 40 * DAY, "old")]:
        ledger.append(str(p), r)
    rc = cf_report.main(["--path", str(p), "--canaries-file", str(tmp_path / "none.json"),
                         "--slots", "5", "--target", "20", "--min-exits", "8",
                         "--json", "--now", str(NOW)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["pool"]["target"] == 20
    assert [c["host"] for c in out["canaries"]] == [ledger.host_of(u) for u in ledger.DEFAULT_CANARIES]
    rc = cf_report.main(["--path", str(p), "--compact", "--now", str(NOW)])
    assert rc == 0
    assert all(NOW - r["ts"] <= ledger.DEFAULT_TTL_S for r in ledger.load(str(p)))


# From here down, the "provider range" literals (10.50, 10.60, 10.70, 10.90,
# 10.100, 10.110) are deliberate RFC 1918 stand-ins for real VPN entry/exit
# ranges. The publish gate rejects real provider addresses, and restoring
# realistic-looking values here would leak which ranges the gateway uses.
def test_build_and_render_report_asn_banned_ranges():
    r = rec(NOW - 100, "10.50.1.2", verdict="fail", checks={"custom:x.invalid": "block-1005"})
    r["entry_ip"] = "10.110.3.4"
    st = cf_report.build(sample() + [r], H, NOW, slots=5, target=20, min_exits=8)
    assert st["banned_prefixes"] == ["10.110"]
    assert st["banned_exit_prefixes"] == ["10.50"]
    text = cf_report.render(st)
    assert "ASN-banned entry ranges (act at mint): 10.110/16" in text
    assert "ASN-banned exit ranges (seen): 10.50/16" in text


def test_render_says_none_when_nothing_is_asn_banned():
    st = cf_report.build(sample(), H, NOW, slots=5, target=20, min_exits=8)
    assert st["banned_prefixes"] == [] and st["banned_exit_prefixes"] == []
    text = cf_report.render(st)
    assert "ASN-banned entry ranges (act at mint): none" in text
    assert "ASN-banned exit ranges (seen): none" in text


def test_build_advisory_tier_scores_pool_on_verdicts_only() -> None:
    # In advisory mode the canaries do not gate anything: a verdict-pass exit with
    # a challenged canary is known-good, and the standard is empty.
    recs = [rec(NOW - 10, "10.1.1.1", canaries={"discord.com": "clean", "www.patreon.com": "challenge"})]
    strict = cf_report.build(recs, H, NOW, slots=1, target=20, min_exits=8, tier="mandatory")
    shadow = cf_report.build(recs, H, NOW, slots=1, target=20, min_exits=8, tier="advisory")
    assert strict["pool"]["known_good"] == 0 and strict["standard"]["size"] == 2
    assert shadow["pool"]["known_good"] == 1 and shadow["standard"]["size"] == 0
    assert shadow["standard"]["tier"] == "advisory" and shadow["standard"]["passing_exits_24h"] == 1
    assert "tier: advisory" in cf_report.render(shadow)
    assert "tier: mandatory" in cf_report.render(strict)
    assert [c["host"] for c in shadow["canaries"]] == H          # canary stats still use the full basket


def test_build_defaults_to_mandatory() -> None:
    st = cf_report.build([], H, NOW, slots=1, target=20, min_exits=8)
    assert st["standard"]["tier"] == "mandatory"
    assert "advisory" not in cf_report.render(st)


def test_cli_cf_tier_flag(tmp_path: Path, capsys) -> None:
    p = tmp_path / "l.jsonl"
    ledger.append(str(p), rec(NOW - 10, "10.1.1.1", canaries={"discord.com": "challenge", "www.patreon.com": "clean"}))
    args = ["--path", str(p), "--canaries-file", str(tmp_path / "none.json"), "--slots", "1",
            "--target", "20", "--min-exits", "8", "--now", str(NOW), "--json"]
    assert cf_report.main(args + ["--cf-tier", "advisory"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["standard"]["tier"] == "advisory" and out["pool"]["known_good"] == 1
    assert cf_report.main(args + ["--cf-tier", "bogus"]) == 0           # anything but mandatory is advisory
    assert json.loads(capsys.readouterr().out)["standard"]["tier"] == "advisory"
    assert cf_report.main(args + ["--cf-tier", ""]) == 0                # empty is mandatory, as in checklib.sh
    assert json.loads(capsys.readouterr().out)["standard"]["tier"] == "mandatory"


def test_cf_report_env_path_reads_an_empty_tier_as_mandatory(tmp_path: Path, monkeypatch) -> None:
    env = tmp_path / "proteus.env"
    env.write_text("PROTEUS_CF_TIER=\n")
    monkeypatch.setattr(cf_report, "ENV_FILES", (str(env),))
    assert cf_report.env_str("PROTEUS_CF_TIER", "mandatory") == "mandatory"
    env.write_text('PROTEUS_CF_TIER=""\n')
    assert cf_report.env_str("PROTEUS_CF_TIER", "mandatory") == "mandatory"


def test_cli_cf_tier_defaults_to_the_env_files(tmp_path: Path, capsys, monkeypatch) -> None:
    p = tmp_path / "l.jsonl"
    ledger.append(str(p), rec(NOW - 10, "10.1.1.1", canaries={"discord.com": "challenge", "www.patreon.com": "clean"}))
    env = tmp_path / "proteus.env"
    env.write_text('PROTEUS_CF_TIER="advisory"\n')
    monkeypatch.setattr(cf_report, "ENV_FILES", (str(env),))
    args = ["--path", str(p), "--canaries-file", str(tmp_path / "none.json"), "--slots", "1",
            "--target", "20", "--min-exits", "8", "--now", str(NOW), "--json"]
    assert cf_report.main(args) == 0
    assert json.loads(capsys.readouterr().out)["standard"]["tier"] == "advisory"
    monkeypatch.setattr(cf_report, "ENV_FILES", (str(tmp_path / "missing.env"),))
    assert cf_report.main(args) == 0
    assert json.loads(capsys.readouterr().out)["standard"]["tier"] == "mandatory"


# RFC 1918 stand-ins (see the block below this one too): good_prefixes is
# sorted() as plain strings, so the order below is "10.100" before "10.70"
# lexicographically, not numerically.
def test_build_and_render_report_proven_entry_ranges():
    # Two passing exits out of the same entry /16 and one out of another; the
    # rejected candidate's range is not proven by a record that failed.
    recs = [rec(NOW - 100, "10.60.1.1"), rec(NOW - 200, "10.60.1.2"),
            rec(NOW - 300, "10.60.1.3", verdict="fail")]
    recs[0]["entry_ip"] = "10.70.1.1"
    recs[1]["entry_ip"] = "10.100.2.2"
    recs[2]["entry_ip"] = "10.90.3.3"
    st = cf_report.build(recs, H, NOW, slots=5, target=20, min_exits=8)
    assert st["good_prefixes"] == ["10.100", "10.70"]
    text = cf_report.render(st)
    assert "Proven entry ranges (7d): 10.100/16, 10.70/16" in text


def test_render_says_none_when_no_entry_range_is_proven():
    recs = [rec(NOW - 100, "10.60.1.1", verdict="fail")]
    st = cf_report.build(recs, H, NOW, slots=5, target=20, min_exits=8)
    assert st["good_prefixes"] == []
    assert "Proven entry ranges (7d): none" in cf_report.render(st)


def test_report_lists_proven_slash24_count() -> None:
    recs = [rec(NOW - 10, "10.1.1.1")]
    st = cf_report.build(recs, H, NOW, slots=1, target=20, min_exits=8)
    assert st["good_prefixes24"] == ["e10.1.1"] or st["good_prefixes24"] == [ledger.slash24("e10.1.1.1")]
    assert "Proven entry /24s (exempt from range bans): 1" in cf_report.render(st)
