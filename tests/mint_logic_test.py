"""Tests for etc/proteus/bin/mint_logic.py — ledger-aware server choice."""
from __future__ import annotations
from types import SimpleNamespace as NS

import ledger
import mint_logic

NOW = 1_800_000_000
H = ["discord.com"]
DAY = 86400


def cand(entry_ip, name="L", load=10):
    return (NS(name=name, load=load), NS(entry_ip=entry_ip))


def rec(ts, entry_ip, source="gate", verdict="pass", canaries=None):
    return {"ts": ts, "exit_ip": "9." + entry_ip, "entry_ip": entry_ip, "source": source,
            "verdict": verdict, "canaries": canaries if canaries is not None else {"discord.com": "clean"}}


class FixedRng:
    """random() returns `r`; choice() returns the first element (deterministic)."""
    def __init__(self, r=0.9):
        self.r = r
    def random(self):
        return self.r
    def choice(self, seq):
        return seq[0]


def pick(cands, records, **kw):
    log = []
    kw.setdefault("rng", FixedRng())
    out = mint_logic.choose(cands, records=records, hosts=H, now=NOW, log=log.append, **kw)
    return (out[1].entry_ip if out else None), log


def test_slash24():
    assert mint_logic.slash24("10.1.2.3") == "10.1.2"


# The entry_ip values below are deliberately RFC 1918 stand-ins, not real
# provider addresses: the public-mirror gate rejects real VPN entry/exit
# ranges, and these are just distinct identifiers for filter behavior.
def test_candidate_servers_filters_like_pick_server():
    streaming = "STREAMING"
    logicals = [
        NS(enabled=True, exit_country="US", tier=0, features={streaming}, load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.201.0.1"),
                             NS(enabled=False, x25519_pk="k", entry_ip="10.201.0.2"),
                             NS(enabled=True, x25519_pk="", entry_ip="10.201.0.3")]),
        NS(enabled=True, exit_country="CH", tier=0, features={streaming}, load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.202.0.2")]),
        NS(enabled=True, exit_country="US", tier=2, features={streaming}, load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.203.0.3")]),
        NS(enabled=True, exit_country="US", tier=0, features=set(), load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.204.0.4")]),
        NS(enabled=True, exit_country="US", tier=0, features={streaming}, load=90,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.205.0.5")]),
        NS(enabled=False, exit_country="US", tier=0, features={streaming}, load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.206.0.6")]),
    ]
    out = mint_logic.candidate_servers(logicals, "us", True, 1, streaming)
    assert [p.entry_ip for _, p in out] == ["10.201.0.1"]
    out = mint_logic.candidate_servers(logicals, "US", False, 1, streaming)
    assert [p.entry_ip for _, p in out] == ["10.201.0.1", "10.204.0.4"]


def test_empty_ledger_draws_from_unknown_and_honours_exclusions():
    c = [cand("10.0.0.1"), cand("10.0.0.2")]
    ip, _ = pick(c, [], attempt=1, sibling_entries={"10.0.0.1"})
    assert ip == "10.0.0.2"
    ip, _ = pick(c, [], attempt=1, sibling_entries={"10.0.0.1", "10.0.0.2"})
    assert ip is None


def test_exploration_forced_below_target_on_odd_attempts():
    recs = [rec(NOW - 100, "10.0.0.1")]                       # e1 known-good
    c = [cand("10.0.0.1"), cand("10.0.0.2")]
    ip, _ = pick(c, recs, attempt=1, pool_target=20)          # pool 1 < 20 -> explore
    assert ip == "10.0.0.2"
    ip, _ = pick(c, recs, attempt=2, pool_target=20)          # even -> known-good
    assert ip == "10.0.0.1"


def test_exploration_probabilistic_at_target():
    recs = [rec(NOW - 100, "10.0.0.1")]
    c = [cand("10.0.0.1"), cand("10.0.0.2")]
    ip, _ = pick(c, recs, attempt=1, pool_target=1, explore_p=0.5, rng=FixedRng(0.9))
    assert ip == "10.0.0.1"                                    # 0.9 >= 0.5: no exploration
    ip, _ = pick(c, recs, attempt=1, pool_target=1, explore_p=0.5, rng=FixedRng(0.1))
    assert ip == "10.0.0.2"                                    # 0.1 < 0.5: explore


def test_reuse_floor_sets_aside_recent_promotions_then_relaxes():
    recs = [rec(NOW - 100, "10.0.0.1"), rec(NOW - 100, "10.0.0.2"),
            rec(NOW - 3600, "10.0.0.1", source="promote"),
            rec(NOW - 10 * DAY, "10.0.0.2", source="promote")]
    c = [cand("10.0.0.1"), cand("10.0.0.2")]
    ip, log = pick(c, recs, attempt=2, reuse_min_s=7 * DAY)
    assert ip == "10.0.0.2" and log == []
    recs2 = recs + [rec(NOW - 2 * DAY, "10.0.0.2", source="promote")]
    ip, log = pick(c, recs2, attempt=2, reuse_min_s=7 * DAY)
    assert ip == "10.0.0.2"                                    # least recently promoted of the two
    assert any("reuse floor relaxed" in m for m in log)


def test_never_promoted_beats_least_recently_promoted():
    recs = [rec(NOW - 100, "10.0.0.1"), rec(NOW - 100, "10.0.0.2"),
            rec(NOW - 30 * DAY, "10.0.0.1", source="promote")]
    c = [cand("10.0.0.1"), cand("10.0.0.2")]
    ip, _ = pick(c, recs, attempt=2)
    assert ip == "10.0.0.2"


def test_slash24_preference_against_siblings():
    c = [cand("10.0.1.5"), cand("10.0.2.5")]
    ip, _ = pick(c, [], attempt=1, sibling_entries={"10.0.1.9"})
    assert ip == "10.0.2.5"


def test_load_never_enters_the_draw():
    c = [cand("10.0.0.1", load=80), cand("10.0.0.2", load=1)]
    ip, _ = pick(c, [], attempt=1)
    assert ip == "10.0.0.1"                                    # first equal candidate, not the lightest


def test_recent_fail_is_last_resort_and_logged():
    recs = [rec(NOW - 100, "10.0.0.1", verdict="fail",
                canaries={"discord.com": "challenge"})]
    c = [cand("10.0.0.1")]
    ip, log = pick(c, recs, attempt=1)
    assert ip == "10.0.0.1"
    assert any("recent-fail" in m for m in log)
    c2 = [cand("10.0.0.1"), cand("10.0.0.2")]
    ip, log = pick(c2, recs, attempt=1)
    assert ip == "10.0.0.2" and log == []


def test_stale_failure_counts_as_unknown_again():
    recs = [rec(NOW - 3 * DAY, "10.0.0.1", verdict="fail", canaries={"discord.com": "challenge"})]
    c = [cand("10.0.0.1")]
    ip, log = pick(c, recs, attempt=1)
    assert ip == "10.0.0.1" and log == []


def test_seeded_random_is_deterministic():
    import random
    c = [cand(f"10.0.0.{i}") for i in range(1, 9)]
    a = mint_logic.choose(c, records=[], hosts=H, now=NOW, attempt=1, rng=random.Random(7))
    b = mint_logic.choose(c, records=[], hosts=H, now=NOW, attempt=1, rng=random.Random(7))
    assert a[1].entry_ip == b[1].entry_ip


def test_uniformity_over_ties():
    import random
    c = [cand(f"10.0.0.{i}") for i in range(1, 9)]
    rng = random.Random(0)
    counts = {p.entry_ip: 0 for _, p in c}
    for _ in range(400):
        out = mint_logic.choose(c, records=[], hosts=H, now=NOW, attempt=1, rng=rng)
        counts[out[1].entry_ip] += 1
    assert all(n >= 20 for n in counts.values())


def test_never_seen_beats_old_failure():
    recs = [rec(NOW - 3 * DAY, "10.0.0.1", verdict="fail", canaries={"discord.com": "challenge"})]
    c = [cand("10.0.0.1"), cand("10.0.0.2")]
    ip, _ = pick(c, recs, attempt=1)
    assert ip == "10.0.0.2"                                        # never-seen beats stale failure


# RFC 1918 stand-ins again (see above): these are not the real Quad9/Google
# resolvers, just distinct placeholder identifiers.
def test_candidate_servers_handles_none_country_and_none_features():
    streaming = "STREAMING"
    logicals = [
        NS(enabled=True, exit_country=None, tier=0, features={streaming}, load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.207.0.7")]),
        NS(enabled=True, exit_country="US", tier=0, features=None, load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.208.0.8")]),
        NS(enabled=True, exit_country="US", tier=0, features=None, load=10,
           physical_servers=[NS(enabled=True, x25519_pk="k", entry_ip="10.209.0.9")]),
    ]
    out = mint_logic.candidate_servers(logicals, "US", True, 1, streaming)
    assert out == []                                               # None country never matches; None features has none
    out = mint_logic.candidate_servers(logicals, "US", False, 1, streaming)
    assert [p.entry_ip for _, p in out] == ["10.208.0.8", "10.209.0.9"]   # streaming not required, None features fine


# From here down, the "provider range" literals (10.50, 10.60, 10.70, 10.90,
# 10.100/... etc.) are deliberate RFC 1918 stand-ins for real VPN entry/exit
# ranges. The publish gate rejects real provider addresses, and restoring
# realistic-looking values here would leak which ranges the gateway uses.
def test_banned_range_is_never_drawn_while_another_candidate_exists():
    # The banned candidate is the known-good, best-ranked one: only the /16 ban
    # keeps it out of the draw, on an exploring attempt and on an exploiting one.
    recs = [rec(NOW - 100, "10.50.1.1")]
    c = [cand("10.50.1.1"), cand("10.60.1.1")]
    for attempt in (1, 2):
        ip, log = pick(c, recs, attempt=attempt, banned_prefixes={"10.50"})
        assert ip == "10.60.1.1" and log == []


def test_a_recent_failure_still_beats_a_banned_range():
    recs = [rec(NOW - 100, "10.60.1.1", verdict="fail", canaries={"discord.com": "challenge"})]
    c = [cand("10.50.1.1"), cand("10.60.1.1")]
    ip, log = pick(c, recs, attempt=1, banned_prefixes={"10.50"})
    assert ip == "10.60.1.1"
    assert any("recent-fail" in m for m in log)


def test_banned_range_is_the_last_resort_and_logged():
    c = [cand("10.50.1.1"), cand("10.50.9.9")]
    ip, log = pick(c, [], attempt=1, banned_prefixes={"10.50"})
    assert ip == "10.50.1.1"
    assert any("asn-banned" in m for m in log)


def test_the_ban_check_uses_slash16(monkeypatch):
    assert mint_logic.slash16("10.50.1.1") == "10.50"
    seen = []

    def spy(ip):
        seen.append(ip)
        return ledger.slash16(ip)

    monkeypatch.setattr(mint_logic, "slash16", spy)
    c = [cand("10.50.1.1"), cand("10.60.1.1")]
    ip, _ = pick(c, [], attempt=1, banned_prefixes={"10.50"})
    assert ip == "10.60.1.1" and "10.50.1.1" in seen


def test_a_proven_entry_range_wins_among_unknown_candidates():
    # Neither candidate has a record of its own: the only thing separating them
    # is that some other server in 10.70 has already produced a passing exit.
    recs = [rec(NOW - DAY, "10.70.9.9")]
    c = [cand("10.90.1.1"), cand("10.70.5.5")]
    ip, log = pick(c, recs, attempt=1, good_prefixes={"10.70"})
    assert ip == "10.70.5.5" and log == []
    # Without the hint FixedRng.choice takes the first candidate, so the
    # preference is doing the work rather than the candidate order.
    ip, _ = pick(c, recs, attempt=1)
    assert ip == "10.90.1.1"


def test_a_proven_range_does_not_rescue_a_banned_one():
    c = [cand("10.50.1.1"), cand("10.60.1.1")]
    ip, log = pick(c, [], attempt=1, banned_prefixes={"10.50"}, good_prefixes={"10.50"})
    assert ip == "10.60.1.1" and log == []
    # And with nothing else to draw, it is still the asn-banned tier.
    ip, log = pick([cand("10.50.1.1")], [], attempt=1,
                   banned_prefixes={"10.50"}, good_prefixes={"10.50"})
    assert ip == "10.50.1.1"
    assert any("asn-banned" in m for m in log)


def test_promotion_age_still_beats_a_proven_range():
    # The proven-range candidate was promoted inside the window; the other was
    # never promoted at all, so it goes first and the range never overrides that.
    recs = [rec(NOW - 30 * DAY, "10.70.5.5", source="promote")]
    c = [cand("10.90.1.1"), cand("10.70.5.5")]
    ip, _ = pick(c, recs, attempt=1, good_prefixes={"10.70"}, reuse_min_s=0)
    assert ip == "10.90.1.1"


def test_proven_slash24_is_exempt_from_a_slash16_ban():
    # 10.100.221.x got a 1005 (bans 10.100/16) but 10.100.217.x has passed.
    c = [cand("10.100.217.216"), cand("10.100.221.9"), cand("10.0.0.1")]
    ip, log = pick(c, [], attempt=1, banned_prefixes={"10.100"}, good_prefixes24={"10.100.217"})
    assert ip == "10.100.217.216"          # proven /24 ranks first (key 0), not banned
    ip, log = pick([cand("10.100.221.9"), cand("10.0.0.1")], [], attempt=1,
                   banned_prefixes={"10.100"}, good_prefixes24={"10.100.217"})
    assert ip == "10.0.0.1"                # the unproven /24 in the banned /16 stays last
    ip, log = pick([cand("10.100.221.9")], [], attempt=1, banned_prefixes={"10.100"})
    assert ip == "10.100.221.9" and any("asn-banned" in m for m in log)


def test_rank_prefers_proven_slash24_over_proven_slash16():
    c = [cand("10.70.1.1"), cand("10.70.251.130")]
    ip, _ = pick(c, [], attempt=1, good_prefixes={"10.70"}, good_prefixes24={"10.70.251"})
    assert ip == "10.70.251.130"
