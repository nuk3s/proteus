#!/usr/bin/env python3
# A stand-in for ip(8) that keeps the state a reconcile reads back: the policy
# rules, the routing tables and the slot namespaces' routes, in $FIX/ipstate.json.
# Every call is recorded in $FIX/calls.log as "ip <argv>", in call order, and a
# successful rule delete also as "DELETED <argv>". Kernel behaviour it models,
# because the script depends on each:
#   - `rule add` fails "File exists" when an installed rule matches everything
#     the new one says, where the source, destination and tos count only if the
#     new rule names them (the kernel's rule_exists() and fib4_rule_compare()):
#     `from A lookup main pref 90` is refused while `from A to B lookup main
#     pref 90` is installed. A new rule goes after every rule with the same or a
#     lower preference.
#   - `rule del` removes the FIRST rule in list order that matches what the
#     request names; a selector left out matches anything.
#   - routes are keyed by prefix and metric; `replace` swaps in place.
#   - listing a table that has never held a route fails.
#   - deleting wg-udm removes every route through it. Whether wg-udm exists is
#     $FIX/wg-udm.up, so a scenario can say so without a call.
# Switches, each a file in $FIX:
#   check          after every state change, append what would make a packet
#                  leave the wrong way to violations.log (see violations())
#   kill-at        a number: after that many state changes, SIGTERM the process
#   + kill-pgid    group named in kill-pgid, the way systemd stops a unit
#                  mid-run (and only that group, never the test's own)
#   ns-del-fail    namespace route deletes fail
#   rule-add-fail  rule adds fail with something other than "File exists"
import ipaddress, json, os, signal, sys

FIX = os.environ["FIX"]
STATE = os.path.join(FIX, "ipstate.json")
argv = sys.argv[1:]
with open(os.path.join(FIX, "calls.log"), "a") as f:
    f.write("ip " + " ".join(argv) + "\n")

SLOTS = {"ns-proton-1": "172.31.1.1", "ns-proton-2": "172.31.2.1"}
CLIENT = ipaddress.IPv4Network("172.16.1.0/24")
TUNNELS = {ipaddress.IPv4Network("10.99.99.0/30"), ipaddress.IPv4Network("10.98.98.0/30")}
CATCH = 4294967295
# The rules the reconcile installs, as the stub stores them. Only these count as
# the pin or the return rule below: a look-alike at the same preference with a
# source or an extra attribute does not match the same packets.
SELF = {"priority": 90, "src": "172.20.0.119", "table": "254"}
RETURN = {"priority", "src", "dst", "dstlen", "table"}

def slot_routes(n):
    """What vpnns-up.sh leaves in a slot before any trusted range exists."""
    veth = "v-%s-ns" % n[3:]
    return [{"dst": "default", "dev": "wg0"},
            {"dst": "172.16.1.0/24", "gateway": SLOTS[n], "dev": veth}]

def fresh():
    return {"rules": [{"priority": 0, "src": "all", "table": "255"},
                      {"priority": 32766, "src": "all", "table": "254"},
                      {"priority": 32767, "src": "all", "table": "253"}],
            "tables": {}, "ns": {n: slot_routes(n) for n in SLOTS}, "ops": 0}

def save():
    with open(STATE + ".tmp", "w") as f:
        json.dump(st, f)
    os.replace(STATE + ".tmp", STATE)

try:
    with open(STATE) as f:
        st = json.load(f)
except (OSError, ValueError):
    st = fresh()
    save()

def violations():
    """What would make a packet leave the wrong way if the run stopped here.
    Each is a real outcome, not a style rule:
      - pref 100 without pref 90: the web UI's replies to a trusted host go
        down the tunnel (the lockout);
      - pref 100 without pref 95 for that range: the client VLAN's pivot to it
        goes down the tunnel;
      - pref 100 over a table with neither the range's route nor the catch: the
        lookup falls through to main and out the uplink;
      - a slot routing a range back here with no pref-100 rule for it: its
        replies route via main and out the uplink (the leak this guards);
      - a slot routing the tunnel subnet back here with neither a pref-100
        rule for it nor wg-udm: the same, once the connected route in main has
        gone with the link."""
    bad = []
    rules = st["rules"]
    def net(r):
        return ipaddress.IPv4Network("%s/%d" % (r["dst"], r.get("dstlen", 32)))
    p100 = [net(r) for r in rules if r["priority"] == 100 and "dst" in r
            and r["src"] == "all" and r.get("table") == "110" and not set(r) - RETURN]
    if p100 and SELF not in rules:
        bad.append("pref 100 without pref 90")
    t110 = st["tables"].get("110", [])
    catch = any(x["dst"] == "default" and x.get("metric") == CATCH for x in t110)
    routed = {ipaddress.IPv4Network(x["dst"]) for x in t110
              if x["dst"] != "default" and not x.get("metric")}
    for d in p100:
        # The tunnel subnet has no pin: main would send the client VLAN's
        # packets for it into wg-udm as well.
        if d not in TUNNELS and not any(r["priority"] == 95 and "dst" in r and net(r) == d
                                        for r in rules):
            bad.append("pref 100 to %s without its pref 95" % d)
        if d not in routed and not catch:
            bad.append("pref 100 to %s over a table with no route and no catch" % d)
    up = os.path.exists(os.path.join(FIX, "wg-udm.up"))
    for n, gw in SLOTS.items():
        for x in st["ns"].get(n, []):
            if x.get("gateway") != gw:
                continue
            d = ipaddress.IPv4Network(x["dst"])
            if d == CLIENT or d in p100:
                continue   # the pref-100 checks above cover where it goes next
            if d in TUNNELS:
                if not up:
                    bad.append("%s routes the tunnel subnet back with no wg-udm"
                               " and no pref-100 rule for it" % n)
            else:
                bad.append("%s routes %s back with no pref-100 rule for it" % (n, d))
    return bad

def changed():
    st["ops"] += 1
    save()
    if os.path.exists(os.path.join(FIX, "check")):
        bad = violations()
        if bad:
            with open(os.path.join(FIX, "violations.log"), "a") as f:
                f.write("op %d (ip %s): %s\n" % (st["ops"], " ".join(sys.argv[1:]), "; ".join(bad)))
    try:
        at = int(open(os.path.join(FIX, "kill-at")).read())
        pgid = int(open(os.path.join(FIX, "kill-pgid")).read())
    except (OSError, ValueError):
        return
    if st["ops"] == at and pgid == os.getpgid(0):
        os.killpg(pgid, signal.SIGTERM)

def fail(msg, rc=2):
    sys.stderr.write(msg + "\n")
    sys.exit(rc)

TABLES = {"main": "254", "local": "255", "default": "253"}

def addr_len(text):
    if text in ("all", "default"):
        return None
    a, _, n = text.partition("/")
    return str(ipaddress.IPv4Address(a)), int(n) if n else 32

def printed(text):
    """How the kernel prints a route prefix: /32 bare, 0/0 as default."""
    if text == "default":
        return "default"
    n = ipaddress.IPv4Network(text, strict=False)
    if n.prefixlen == 0:
        return "default"
    return str(n.network_address) if n.prefixlen == 32 else str(n)

ns = None
opts = set()
while argv and argv[0].startswith("-"):
    o = argv.pop(0)
    if o == "-n":
        ns = argv.pop(0)
    else:
        opts.add(o)
obj = argv[0] if argv else ""
cmd = argv[1] if len(argv) > 1 else ""
rest = argv[2:]

def kv(tokens, flags=()):
    d, extra, i = {}, [], 0
    while i < len(tokens):
        t = tokens[i]
        if t in flags:
            d[t] = True
            i += 1
        elif i + 1 < len(tokens) and t in ("from", "to", "lookup", "table", "pref",
                                           "priority", "dev", "via", "metric", "iif",
                                           "oif", "fwmark", "type"):
            d[t] = tokens[i + 1]
            i += 2
        else:
            extra.append(t)
            i += 1
    return d, extra

def rule_from(d, extra):
    r = {"priority": int(d.get("pref", d.get("priority", 0)))}
    s = addr_len(d.get("from", "all"))
    r["src"] = s[0] if s else "all"
    if s and s[1] != 32:
        r["srclen"] = s[1]
    t = addr_len(d.get("to", "all"))
    if t:
        r["dst"] = t[0]
        if t[1] != 32:
            r["dstlen"] = t[1]
    tbl = d.get("lookup", d.get("table"))
    if tbl:
        r["table"] = TABLES.get(tbl, tbl)
    for k in ("iif", "oif", "fwmark"):
        if k in d:
            r[k] = d[k]
    for x in extra:
        r[x] = None
    return r

def duplicate(x, r):
    """Whether the kernel refuses to add r because x is installed."""
    partial = ("src", "srclen", "dst", "dstlen", "tos")
    if any(x.get(k) != r.get(k) for k in set(x) | set(r) if k not in partial):
        return False
    if r["src"] != "all" and (x["src"], x.get("srclen", 32)) != (r["src"], r.get("srclen", 32)):
        return False
    if "dst" in r and (x.get("dst"), x.get("dstlen", 32)) != (r["dst"], r.get("dstlen", 32)):
        return False
    return "tos" not in r or x.get("tos") == r["tos"]

if obj == "rule":
    if cmd == "add":
        d, extra = kv(rest)
        r = rule_from(d, extra)
        if os.path.exists(os.path.join(FIX, "rule-add-fail")):
            fail("RTNETLINK answers: Operation not permitted")
        if any(duplicate(x, r) for x in st["rules"]):
            fail("RTNETLINK answers: File exists")
        i = 0
        while i < len(st["rules"]) and st["rules"][i]["priority"] <= r["priority"]:
            i += 1
        st["rules"].insert(i, r)
        changed()
    elif cmd == "del":
        d, _ = kv(rest)
        want = rule_from(d, [])
        def hit(x):
            if "pref" in d and x["priority"] != want["priority"]:
                return False
            if "lookup" in d and x.get("table") != want.get("table"):
                return False
            for side, ln in (("src", "srclen"), ("dst", "dstlen")):
                w = want.get(side)
                if w in (None, "all"):
                    continue
                if (x.get(side), x.get(ln, 32)) != (w, want.get(ln, 32)):
                    return False
            return True
        for i, x in enumerate(st["rules"]):
            if hit(x):
                del st["rules"][i]
                with open(os.path.join(FIX, "calls.log"), "a") as f:
                    f.write("DELETED " + " ".join(argv) + "\n")
                changed()
                break
        else:
            fail("RTNETLINK answers: No such file or directory")
    elif cmd in ("show", "list", ""):
        print(json.dumps(st["rules"]))
    sys.exit(0)

if obj == "route" and ns is not None:
    routes = st["ns"].setdefault(ns, [])
    if cmd in ("add", "replace", "del"):
        dst = printed(rest[0])
        d, _ = kv(rest[1:])
        same = [x for x in routes if x["dst"] == dst]
        if cmd == "del":
            if not same or os.path.exists(os.path.join(FIX, "ns-del-fail")):
                fail("RTNETLINK answers: No such process")
            routes.remove(same[0])
        else:
            if same and cmd == "add":
                fail("RTNETLINK answers: File exists")
            e = {"dst": dst}
            if "via" in d:
                e["gateway"] = d["via"]
            if "dev" in d:
                e["dev"] = d["dev"]
            if same:
                routes[routes.index(same[0])] = e
            else:
                routes.append(e)
        changed()
    elif cmd in ("show", "list", ""):
        print(json.dumps(routes))
    sys.exit(0)

if obj == "route":
    if cmd == "flush":
        d, _ = kv(rest)
        st["tables"][d["table"]] = []
        changed()
        sys.exit(0)
    if cmd in ("show", "list"):
        d, _ = kv(rest)
        t = d.get("table", "254")
        if t not in st["tables"]:
            fail("Error: ipv4: FIB table does not exist.\nDump terminated")
        print(json.dumps(st["tables"][t]))
        sys.exit(0)
    if cmd in ("replace", "add", "del"):
        toks = list(rest)
        rtype = None
        if toks and toks[0] in ("blackhole", "unreachable", "prohibit"):
            rtype = toks.pop(0)
        dst = printed(toks.pop(0))
        d, _ = kv(toks)
        tbl = st["tables"].setdefault(d.get("table", "254"), [])
        metric = int(d.get("metric", 0))
        if cmd == "del":
            for x in tbl:
                if x["dst"] == dst and ("metric" not in d or x.get("metric", 0) == metric):
                    tbl.remove(x)
                    break
            else:
                fail("RTNETLINK answers: No such process")
        else:
            e = {"dst": dst}
            if rtype:
                e["type"] = rtype
            if "dev" in d:
                e["dev"] = d["dev"]
            if metric:
                e["metric"] = metric
            same = [x for x in tbl if x["dst"] == dst and x.get("metric", 0) == metric]
            if same and cmd == "add":
                fail("RTNETLINK answers: File exists")
            if same:
                tbl[tbl.index(same[0])] = e
            else:
                tbl.append(e)
        changed()
    sys.exit(0)

up = os.path.join(FIX, "wg-udm.up")
if obj == "link" and argv[1:] == ["show", "wg-udm"]:
    sys.exit(0 if os.path.exists(up) else 1)
if obj == "link" and argv[1:3] == ["add", "wg-udm"]:
    open(up, "w").close()
    changed()
    sys.exit(0)
if obj == "link" and argv[1:] == ["del", "wg-udm"]:
    if os.path.exists(up):
        os.remove(up)
    for t in st["tables"].values():
        t[:] = [x for x in t if x.get("dev") != "wg-udm"]
    changed()
    sys.exit(0)
if obj == "addr" and cmd == "show" and "-o" in opts:
    # The pref-90 rule is derived from our own address, so the mock has to have one.
    print("2: ens18    inet 172.20.0.119/24 brd 172.20.0.255 scope global ens18")
    sys.exit(0)
if obj == "netns" and cmd == "list":
    # Only the two slots the state files name; a namespace a vpnns-up fragment
    # scenario invents does not appear here, as it would not on a real box.
    for n in ("ns-proton-1", "ns-proton-2"):
        print(n)
    sys.exit(0)
sys.exit(0)
