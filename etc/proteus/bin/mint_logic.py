"""mint_logic.py — ledger-aware server choice for proton-mint. Stdlib only.

Candidates are (logical, physical) pairs; this module reads physical.entry_ip
and nothing else, so tests can use SimpleNamespace objects. The ledger is
keyed on the Proton ENTRY IP here (what mint knows before connecting); the
gate records both entry and exit IPs, and a physical server's exit IP is
stable, so entry identity is a faithful proxy.

Why the draw looks the way it does (design 2026-09-03, "wide distribution"):
ranking by load funnels every rotation onto the same few low-load servers, so
load is a filter only; exploration on odd attempts keeps the known-good pool
growing until it reaches target; a reuse floor stops the fleet re-drawing an
exit it held this week; least-recently-promoted first spreads promotions
across the pool; among candidates the ledger knows nothing about, a /16 that has
already produced a passing exit goes first; a /24 not held by a sibling slot wins
ties. A /16 that answered a Cloudflare 1005 is drawn last whatever its own history
says: that error bans an ASN, not an IP, so its neighbours are no better than it is.
"""
from __future__ import annotations

import random

import ledger


def slash24(ip: str) -> str:
    return ".".join(ip.split(".")[:3])


# One definition of "the range Cloudflare banned" for the ledger and the draw.
slash16 = ledger.slash16


def cf_mint_inputs(records, canary_hosts, now: int, quarantine_min_exits: int,
                   tier: str) -> tuple[list, set]:
    """(hosts, banned) for choose(): the canary standard and the entry /16s that
    a Cloudflare 1005 banned. Any tier other than "mandatory" is advisory, the
    same rule checklib.sh applies. In advisory the canaries are recorded and
    shown, and they must not steer which exits get minted. So the standard is
    empty, which makes ledger.pool keep every exit whose verdict passed. Only
    the operator's own checks can raise a ban, because a canary's 1005 is a
    canary verdict too."""
    if (tier or "mandatory") != "mandatory":
        return [], ledger.banned_prefixes(records, now, canaries=False)
    hosts = ledger.active_hosts(records, list(canary_hosts), now, quarantine_min_exits)
    return hosts, ledger.banned_prefixes(records, now)


def candidate_servers(logicals, country: str, require_streaming: bool, user_tier: int,
                      streaming_feature) -> list:
    """Every enabled physical of every logical that matches country, tier,
    streaming flag and load <= 85. Order preserved from the server list."""
    out = []
    for logical in logicals:
        if not logical.enabled:
            continue
        if logical.exit_country is None or logical.exit_country.upper() != country.upper():
            continue
        if logical.tier > user_tier:
            continue
        if require_streaming and streaming_feature not in (logical.features or set()):
            continue
        if logical.load is not None and logical.load > 85:
            continue
        for p in logical.physical_servers:
            if p.enabled and p.x25519_pk and p.entry_ip:
                out.append((logical, p))
    return out


def _draw(tier, promoted, failed, now, reuse_min_s, sib24, rng, log, good16=frozenset(),
          good24=frozenset()):
    if not tier:
        return None
    fresh = [c for c in tier if now - promoted.get(c[1].entry_ip, 0) >= reuse_min_s]
    if not fresh:
        log("mint: reuse floor relaxed (every eligible exit was promoted within the window)")
        fresh = list(tier)
    # Rank by (promotion age, failure age, proven range): never-promoted-and-
    # never-failed first, then never-promoted-but-failed-long-ago, then by
    # promotion age. The third key only ever separates candidates the first two
    # tied on — among servers with no history at all, one in a /16 that has
    # already produced a passing exit is the better guess.
    def rank(c):
        ip = c[1].entry_ip
        rng_key = 0 if slash24(ip) in good24 else (1 if slash16(ip) in good16 else 2)
        return (promoted.get(ip, 0), failed.get(ip, 0), rng_key)
    fresh.sort(key=rank)
    oldest = rank(fresh[0])
    equals = [c for c in fresh if rank(c) == oldest]
    pref = [c for c in equals if slash24(c[1].entry_ip) not in sib24] or equals
    return rng.choice(pref)


def choose(candidates, *, records, hosts, now: int, attempt: int, sibling_entries=(),
           banned_prefixes=(), good_prefixes=(), good_prefixes24=(), pool_target: int = 20,
           explore_p: float = 0.5,
           reuse_min_s: int = 604800, ttl_s: int = ledger.DEFAULT_TTL_S, rng=None, log=None):
    """Pick (logical, physical) or None. `hosts` is the active canary standard.
    `banned_prefixes` is the set of /16s a Cloudflare 1005 has condemned (see
    ledger.banned_prefixes): every server in one of those ranges is set aside,
    whatever its own history says, because the ban is against the ASN and not
    against the IP. `good_prefixes` (ledger.good_prefixes) is the other side of
    the same coin, and is only a tie-break: among candidates with no history of
    their own, one in a range that has produced a passing exit goes first. It
    never promotes a candidate over an older-untried one, and it never rescues a
    banned range."""
    rng = rng if rng is not None else random
    log = log or (lambda m: None)
    excluded = set(sibling_entries)
    cands = [c for c in candidates if c[1].entry_ip not in excluded]
    if not cands:
        return None
    banned = set(banned_prefixes)
    good16 = set(good_prefixes) - banned
    # A proven /24 beats a banned /16: hosting ranges mix servers that exit
    # directly (banned) with servers that exit through Proton's own range
    # (passing), and a subnet that already produced a pass is not condemned by
    # its neighbours.
    good24 = set(good_prefixes24)

    def is_banned(c):
        ip = c[1].entry_ip
        return slash16(ip) in banned and slash24(ip) not in good24

    asn_banned = [c for c in cands if is_banned(c)]
    cands = [c for c in cands if not is_banned(c)]
    good = ledger.pool(records, hosts, now, ttl_s=ttl_s, key="entry_ip")
    bad = ledger.recent_fail_keys(records, hosts, now, key="entry_ip")
    promoted = ledger.last_promoted(records, key="entry_ip")
    failed = ledger.last_failed(records, hosts, key="entry_ip")
    known = [c for c in cands if c[1].entry_ip in good]
    recent_fail = [c for c in cands if c[1].entry_ip in bad]
    unknown = [c for c in cands if c[1].entry_ip not in good and c[1].entry_ip not in bad]
    explore = attempt % 2 == 1 and (len(good) < pool_target or rng.random() < explore_p)
    tiers = [("unknown", unknown), ("known-good", known)] if explore else [("known-good", known), ("unknown", unknown)]
    tiers.append(("recent-fail", recent_fail))
    tiers.append(("asn-banned", asn_banned))
    sib24 = {slash24(e) for e in excluded}
    for name, tier in tiers:
        pick = _draw(tier, promoted, failed, now, reuse_min_s, sib24, rng, log, good16, good24)
        if pick is not None:
            if name == "recent-fail":
                log("mint: every eligible exit failed within 24h; drawing from recent-fail")
            elif name == "asn-banned":
                log("mint: every eligible exit is in a 1005-banned range; drawing from asn-banned")
            return pick
    return None
