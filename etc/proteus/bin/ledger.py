#!/usr/bin/env python3
"""ledger.py — the exit ledger: one JSON object per probe run per exit.

Importable (stdlib only) and a CLI for the bash scripts. The ledger answers:
which exits are known-good for the current standard (pool), which canary is
blocking every exit (quarantine), and whether the standard is attainable at
fleet scale. Design: architecture.md, "Cloudflare canaries, live checks and the exit ledger"

CLI:
  ledger.py append --path P --ts N --exit-ip A --entry-ip B --logical L --slot S
                   --source gate|live|promote --verdict pass|fail
                   [--canaries host=class,...] [--checks label=class,...]
                   [--standing N --of M] [--ttl-s S]
  ledger.py quarantined --path P --host H [--min-exits 8]        exit 0 = quarantined
  ledger.py attainable  --path P --hosts h1,h2 --slots N         exit 0 = attainable
  ledger.py status      --path P --hosts h1,h2 --slots N --target T [--min-exits 8]
  ledger.py canaries    [--file /etc/proteus/canaries.json]      one URL per line
  ledger.py compact     --path P [--ttl-s S]

Records carry third-party strings (Proton logical names). They are JSON only
and must never be shell-sourced; the bash side reads them through this module.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import sys
import time

DEFAULT_PATH = "/etc/proteus/state/exit-ledger.jsonl"
DEFAULT_CANARIES_FILE = "/etc/proteus/canaries.json"
DEFAULT_TTL_S = 14 * 86400
FAIL_WINDOW_S = 86400
COMPACT_ABOVE_LINES = 2000
MAX_CANARIES = 8
# Shipped basket. Measured 2026-09-03 from five gate-approved Proton US exits:
# discord and digitalocean passed all five, patreon three, udemy two. udemy was
# dropped from the basket on 2026-09-04: it challenges roughly 90% of Proton
# exits, and it flags forum-rejected and forum-accepted candidates at the same
# rate, so it costs a probe per exit and separates nothing. See the spec for the
# full table and why stricter sites were left out of the default.
DEFAULT_CANARIES = [
    "https://discord.com/",
    "https://www.digitalocean.com/",
    "https://www.patreon.com/",
]
# Shell metacharacters, plus "@": userinfo would let a canary URL read as one
# host and be fetched from another (https://discord.com@evil.invalid/), so the
# ledger, the report and the UI would all attribute the verdict to the wrong
# site. No legitimate canary needs credentials in its URL.
_URL_BAD = set(" \t\r\n'\"`$;&|\\@")


def _ts(r: dict) -> int:
    try:
        return int(r.get("ts", 0))
    except (TypeError, ValueError):
        return 0


def _group_readable(path: str) -> None:
    """root:proteus-ui 0640 so the unprivileged UI daemon can read it. Best effort."""
    try:
        import grp
        os.chown(path, 0, grp.getgrnam("proteus-ui").gr_gid)
    except (KeyError, OSError):
        pass
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


@contextlib.contextmanager
def _locked(path: str):
    """Exclusive lock on the file currently at `path`, opened in append mode
    so a lock is never taken by truncating it. append() and compact() share
    this helper so they serialize against each other and against other
    processes. flock() locks an open file description, not a path, so a
    concurrent compact() can swap a new file into `path` between our open()
    and our flock(); re-check the inode after locking and retry against the
    new file if it moved."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    while True:
        f = open(path, "a+")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            same = os.fstat(f.fileno()).st_ino == os.stat(path).st_ino
        except OSError:
            same = False
        if same:
            break
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()
    try:
        yield f
    finally:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()


def _compact_now(path: str, now: int, ttl_s: int) -> int:
    """Rewrite `path` keeping only records within ttl_s. Caller must already
    hold the ledger lock (see _locked). The temp file is PID-unique so two
    processes racing to compact never splice each other's output; the lock
    still serializes the actual replace. On any failure the temp file is
    removed before the error propagates."""
    recs = [r for r in load(path) if now - _ts(r) <= ttl_s]
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w") as out:
            for r in recs:
                out.write(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return len(recs)


def append(path: str, record: dict, ttl_s: int = DEFAULT_TTL_S) -> None:
    line = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
    with _locked(path) as f:
        f.write(line)
        f.flush()
        try:
            f.seek(0)
            n = sum(1 for _ in f)
            if n > COMPACT_ABOVE_LINES:
                _compact_now(path, int(time.time()), ttl_s)
        except OSError:
            pass
    _group_readable(path)


def load(path: str, since: int = 0) -> list[dict]:
    out: list[dict] = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict) and _ts(r) >= since:
                    out.append(r)
    except OSError:
        return []
    return out


def is_fail_class(v) -> bool:
    return v == "challenge" or str(v).startswith("block-")


def meets_standard(r: dict, hosts) -> bool:
    """Every host in `hosts` returned clean in this record."""
    c = r.get("canaries") or {}
    return all(c.get(h) == "clean" for h in hosts)


def fails_standard(r: dict, hosts) -> bool:
    c = r.get("canaries") or {}
    return any(is_fail_class(c.get(h)) for h in hosts)


def _is_fail(r: dict, hosts) -> bool:
    return fails_standard(r, hosts) or r.get("verdict") == "fail"


def pool(records, hosts, now: int, *, ttl_s: int = DEFAULT_TTL_S, key: str = "exit_ip") -> set:
    """Known-good keys: met the standard with a passing verdict within ttl_s and
    have no failing record in the last FAIL_WINDOW_S."""
    good, bad = set(), set()
    for r in records:
        k = r.get(key)
        if not k or r.get("source") not in ("gate", "live"):
            continue
        age = now - _ts(r)
        if age <= FAIL_WINDOW_S and _is_fail(r, hosts):
            bad.add(k)
        if age <= ttl_s and meets_standard(r, hosts) and r.get("verdict", "pass") == "pass":
            good.add(k)
    return good - bad


def recent_fail_keys(records, hosts, now: int, key: str = "exit_ip") -> set:
    out = set()
    for r in records:
        k = r.get(key)
        if not k or r.get("source") not in ("gate", "live"):
            continue
        if now - _ts(r) <= FAIL_WINDOW_S and _is_fail(r, hosts):
            out.add(k)
    return out


def last_promoted(records, key: str = "exit_ip") -> dict:
    out: dict = {}
    for r in records:
        k = r.get(key)
        if r.get("source") == "promote" and k:
            out[k] = max(out.get(k, 0), _ts(r))
    return out


def last_failed(records, hosts, key: str = "exit_ip") -> dict:
    """Mirror of last_promoted, but the max ts per key of gate/live records
    that fail the standard (fails_standard) or carry verdict=fail. Used to
    rank never-seen exits ahead of exits that merely failed long ago."""
    out: dict = {}
    for r in records:
        if r.get("source") not in ("gate", "live"):
            continue
        k = r.get(key)
        if k and _is_fail(r, hosts):
            out[k] = max(out.get(k, 0), _ts(r))
    return out


def slash16(ip: str) -> str:
    return ".".join(ip.split(".")[:2])


def _has_1005(r: dict, canaries: bool) -> bool:
    maps = [r.get("checks")]
    if canaries:
        maps.append(r.get("canaries"))
    return any(v == "block-1005" for m in maps if isinstance(m, dict) for v in m.values())


def _banned(records, now: int, window_s: int, canaries: bool, key: str) -> set:
    out: set = set()
    for r in records:
        if r.get("source") not in ("gate", "live") or now - _ts(r) > window_s:
            continue
        if not _has_1005(r, canaries):
            continue
        ip = r.get(key)
        if isinstance(ip, str) and ip:
            out.add(slash16(ip))
    return out


def banned_prefixes(records, now: int, window_s: int = 7 * 86400, canaries: bool = True) -> set:
    """Entry /16s hit by a Cloudflare 1005 (the ASN itself is banned) in the
    window. 1005 says nothing about the individual IP — "the owner has banned
    the autonomous system number your IP is in" — so every neighbour of that
    exit is banned too, and re-sampling them wastes a rotation. The set is
    keyed on the Proton ENTRY IP because that is all minting knows before it
    connects; banned_exit_prefixes reports the other side. Seven days, because
    a whole-ASN ban is a policy decision that outlives the 24h the
    individual-IP memory keeps. `canaries=False` counts only the operator's
    own checks, for the advisory tier.
    """
    return _banned(records, now, window_s, canaries, "entry_ip")


def banned_exit_prefixes(records, now: int, window_s: int = 7 * 86400, canaries: bool = True) -> set:
    """Exit-side counterpart of banned_prefixes: what the banned range looks
    like from the far end. Display only — nothing selects on it."""
    return _banned(records, now, window_s, canaries, "exit_ip")


def good_prefixes(records, now: int, window_s: int = 7 * 86400) -> set[str]:
    """Entry /16s that produced a passing exit in the window. The mirror of
    banned_prefixes, and it reads the same way: Cloudflare's opinion tracks the
    range, not the individual address, so a range one exit already got through
    is a better place to explore than one nothing has ever come out of. Only
    gate and live records count, and only with verdict=pass — a promote record
    is written for every promotion including a step-down, so it is not evidence
    the range passes anything.
    """
    out: set = set()
    for r in records:
        if r.get("source") not in ("gate", "live") or now - _ts(r) > window_s:
            continue
        if r.get("verdict") != "pass":
            continue
        ip = r.get("entry_ip")
        if isinstance(ip, str) and ip:
            out.add(slash16(ip))
    return out


def slash24(ip: str) -> str:
    return ".".join(ip.split(".")[:3])


def good_prefixes24(records, now: int, window_s: int = 7 * 86400) -> set[str]:
    """Entry /24s that produced a passing exit in the window. Finer than
    good_prefixes: a hosting range can hold both servers that exit directly
    (and get banned) and servers that exit through Proton's own range (and
    pass), so a proven /24 is exempt from a /16 ban at mint."""
    out: set = set()
    for r in records:
        if r.get("source") not in ("gate", "live") or now - _ts(r) > window_s:
            continue
        if r.get("verdict") != "pass":
            continue
        ip = r.get("entry_ip")
        if isinstance(ip, str) and ip:
            out.add(slash24(ip))
    return out


def per_canary(records, host: str, now: int, window_s: int = 86400) -> tuple[int, int]:
    """(distinct exits seen, distinct exits clean) for one canary in the window.
    not-cloudflare and transport are not verdicts and are ignored."""
    seen, clean = set(), set()
    for r in records:
        if r.get("source") not in ("gate", "live"):
            continue
        if now - _ts(r) > window_s:
            continue
        v = (r.get("canaries") or {}).get(host)
        ip = r.get("exit_ip")
        if v is None or not ip or v in ("not-cloudflare", "transport"):
            continue
        seen.add(ip)
        if v == "clean":
            clean.add(ip)
    return len(seen), len(clean)


def quarantined(records, host: str, now: int, min_exits: int = 8) -> bool:
    seen, clean = per_canary(records, host, now)
    return seen >= min_exits and clean == 0


def active_hosts(records, hosts, now: int, min_exits: int = 8) -> list:
    return [h for h in hosts if not quarantined(records, h, now, min_exits)]


def attainable(records, hosts, now: int, slots: int, min_records: int = 10) -> bool:
    """At least `slots` distinct exits met the standard in 24 h, or the ledger is
    too thin to judge (fewer than min_records gate records in 24 h)."""
    gate_24h = [r for r in records if r.get("source") == "gate" and now - _ts(r) <= 86400]
    if len(gate_24h) < min_records:
        return True
    return len(pool(records, hosts, now, ttl_s=86400)) >= max(1, slots)


def diversity(records, now: int, window_s: int) -> tuple[int, int]:
    """(distinct exit IPs promoted, distinct /24s promoted) within window_s."""
    exits, nets = set(), set()
    for r in records:
        ip = r.get("exit_ip")
        if r.get("source") == "promote" and ip and now - _ts(r) <= window_s:
            exits.add(ip)
            nets.add(".".join(ip.split(".")[:3]))
    return len(exits), len(nets)


def status(records, hosts, now: int, slots: int, target: int, min_exits: int = 8) -> dict:
    canaries = []
    for h in hosts:
        seen, clean = per_canary(records, h, now)
        canaries.append({"host": h, "exits_seen_24h": seen,
                         "pass_rate_24h": (round(clean / seen, 3) if seen else None),
                         "quarantined": quarantined(records, h, now, min_exits)})
    active = [c["host"] for c in canaries if not c["quarantined"]]
    e7, n7 = diversity(records, now, 7 * 86400)
    return {
        "canaries": canaries,
        "standard": {"size": len(active),
                     "attainable": attainable(records, active, now, slots),
                     "passing_exits_24h": len(pool(records, active, now, ttl_s=86400))},
        "pool": {"known_good": len(pool(records, active, now)), "target": target,
                 "distinct_exits_7d": e7, "distinct_slash24_7d": n7},
    }


def compact(path: str, now: int, ttl_s: int = DEFAULT_TTL_S) -> int:
    try:
        with _locked(path):
            n = _compact_now(path, now, ttl_s)
    except OSError:
        return 0
    _group_readable(path)
    return n


def canary_urls(path: str = DEFAULT_CANARIES_FILE) -> list[str]:
    """Operator list from canaries.json; the shipped basket when the file is
    absent, malformed or empty. Only https URLs without shell metacharacters."""
    urls: list[str] = []
    try:
        with open(path) as f:
            d = json.load(f)
        for c in (d.get("canaries") or [])[:MAX_CANARIES]:
            u = str(c.get("url", "")) if isinstance(c, dict) else ""
            if u.startswith("https://") and not (set(u) & _URL_BAD) and u not in urls:
                urls.append(u)
    except Exception:            # any shape or IO problem: the shipped basket applies
        urls = []
    return urls or list(DEFAULT_CANARIES)


def host_of(url: str) -> str:
    h = url.split("://", 1)[-1]
    for sep in "/?#:":
        h = h.split(sep, 1)[0]
    return h


def _kv_map(s: str) -> dict:
    out = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main(argv=None) -> int:
    # Any unhandled exception is a broken tool, not an answer. checklib's
    # cf_quarantined reads 0 as "quarantined" and 1 as "not quarantined" and
    # demotes the canary on anything else, so a crash on a bad-shape record
    # must not borrow either of those codes.
    try:
        p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
        sub = p.add_subparsers(dest="cmd", required=True)

        a = sub.add_parser("append")
        a.add_argument("--path", default=DEFAULT_PATH)
        a.add_argument("--ts", type=int, default=None)
        for k in ("exit-ip", "entry-ip", "logical", "slot"):
            a.add_argument(f"--{k}", default="")
        a.add_argument("--source", choices=("gate", "live", "promote"), required=True)
        a.add_argument("--verdict", choices=("pass", "fail"), default="pass")
        a.add_argument("--canaries", default="")
        a.add_argument("--checks", default="")
        a.add_argument("--standing", type=int, default=0)
        a.add_argument("--of", type=int, default=0)
        a.add_argument("--ttl-s", type=int, default=DEFAULT_TTL_S)

        q = sub.add_parser("quarantined")
        q.add_argument("--path", default=DEFAULT_PATH)
        q.add_argument("--host", required=True)
        q.add_argument("--min-exits", type=int, default=8)

        t = sub.add_parser("attainable")
        t.add_argument("--path", default=DEFAULT_PATH)
        t.add_argument("--hosts", default="")
        t.add_argument("--slots", type=int, default=1)

        s = sub.add_parser("status")
        s.add_argument("--path", default=DEFAULT_PATH)
        s.add_argument("--hosts", default="")
        s.add_argument("--slots", type=int, default=1)
        s.add_argument("--target", type=int, default=20)
        s.add_argument("--min-exits", type=int, default=8)

        cn = sub.add_parser("canaries")
        cn.add_argument("--file", default=DEFAULT_CANARIES_FILE)

        c = sub.add_parser("compact")
        c.add_argument("--path", default=DEFAULT_PATH)
        c.add_argument("--ttl-s", type=int, default=DEFAULT_TTL_S)

        args = p.parse_args(argv)
        now = int(time.time())

        if args.cmd == "canaries":
            for u in canary_urls(args.file):
                print(u)
            return 0
        if args.cmd == "append":
            rec = {"ts": args.ts if args.ts is not None else now,
                   "exit_ip": args.exit_ip, "entry_ip": args.entry_ip, "logical": args.logical,
                   "slot": args.slot, "source": args.source, "verdict": args.verdict,
                   "canaries": _kv_map(args.canaries), "checks": _kv_map(args.checks),
                   "standing": args.standing, "of": args.of}
            append(args.path, rec, ttl_s=args.ttl_s)
            return 0

        recs = load(args.path)
        hosts = [h.strip() for h in (getattr(args, "hosts", "") or "").split(",") if h.strip()]
        if args.cmd == "quarantined":
            return 0 if quarantined(recs, args.host, now, args.min_exits) else 1
        if args.cmd == "attainable":
            return 0 if attainable(recs, hosts, now, args.slots) else 1
        if args.cmd == "status":
            print(json.dumps(status(recs, hosts, now, args.slots, args.target, args.min_exits)))
            return 0
        if args.cmd == "compact":
            print(compact(args.path, now, args.ttl_s))
            return 0
        return 2
    except Exception as e:
        print(f"ledger.py: internal error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
