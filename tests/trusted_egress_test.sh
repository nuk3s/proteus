#!/usr/bin/env bash
# tests/trusted_egress_test.sh
#
# The reconcile script is the only thing that turns trusted.json into live
# kernel state, so the properties pinned here are the ones an outage would come
# from: with no pairing, an empty list must be a COMPLETE teardown (this is the
# shipped default, so "off" has to mean off); with a pairing but no ranges the
# tunnel must come up and carry nothing, because that is the state the rollout
# is verified in; a second run must change nothing; and traffic proteus is
# responsible for — its own replies and the client VLAN's — must keep a route
# that does not go down the tunnel. Those rules are the only things keeping the
# web UI reachable from a trusted VLAN host and the client pivot working.
#
# And a reconcile must never open a gap: at every step of every run, including
# one that is killed half way, a slot's reply to a trusted host must still find
# its way to wg-udm (or be dropped), never `main` and the uplink. The ip stub
# keeps kernel-like state so that is checked after every single change it makes
# (tests/_ipmock.py, violations()), not just at the end.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Another version of the script can be run through the same checks, e.g. an
# older one, to watch them fail on it.
SCRIPT="${TRUSTED_EGRESS_SCRIPT:-$ROOT/etc/proteus/bin/proteus-trusted-egress.sh}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/keys"
export FIX="$TMP"

# Mocks record their argv so we can assert on intent rather than on kernel state.
for tool in nft wg; do
  cat > "$TMP/bin/$tool" <<EOF
#!/usr/bin/env bash
echo "$tool \$*" >> "\$FIX/calls.log"
case "\$*" in
  # 'nft -f -' carries the whole transaction on stdin, so argv alone would say
  # nothing about what landed in the set. Record the transaction itself — and
  # read it, or the script's writer takes a SIGPIPE and dies.
  "-f -") cat >> "\$FIX/calls.log";;
  # Which peers the tunnel already carries. A scenario writes this fixture to
  # say a previous pairing is still configured.
  "show wg-udm peers") cat "\$FIX/peers" 2>/dev/null;;
  # Whether nftables holds the set at all; the flag file lets a scenario say the
  # ruleset has not loaded yet.
  "list set"*) [ -f "\$FIX/no-set" ] && exit 1;;
esac
exit 0
EOF
  chmod +x "$TMP/bin/$tool"
done
# ip has to answer what the script reads back (the rules, table 110, each
# slot's routes), so it is a stateful stand-in rather than a recorder. Pinned to
# the interpreter found now: one scenario below puts a failing python3 first on
# PATH, and that must break trusted.py, not the stand-in for the kernel. -S
# skips site-packages: it needs only the standard library, and it starts ~30
# times per run.
{ echo "#!$(command -v python3) -S"; tail -n +2 "$ROOT/tests/_ipmock.py"; } > "$TMP/bin/ip"
chmod +x "$TMP/bin/ip"
# The script refuses to touch the live ruleset, routes and tunnel unless it is
# root. The mocks stand in for the kernel, so root is stood in for as well —
# otherwise every assertion past the pairing check is unreachable.
cat > "$TMP/bin/id" <<'EOF'
#!/usr/bin/env bash
echo 0
EOF
chmod +x "$TMP/bin/id"
# Stands in for the real flock(1): succeeds instantly (no scenario here needs
# real locking semantics) unless $FIX/flock-fail says a concurrent copy is
# holding the lock, in which case it fails the way a real timeout would.
cat > "$TMP/bin/flock" <<'EOF'
#!/usr/bin/env bash
echo "flock $*" >> "$FIX/calls.log"
[ -f "$FIX/flock-fail" ] && exit 1
exit 0
EOF
chmod +x "$TMP/bin/flock"
export PATH="$TMP/bin:$PATH"

cat > "$TMP/state/proton-1.state" <<'EOF'
INSTANCE=proton-1
NS=ns-proton-1
VETH_NS=v-proton-1-ns
TRANSIT_MAIN=172.31.1.1
EOF
cat > "$TMP/state/proton-2.state" <<'EOF'
INSTANCE=proton-2
NS=ns-proton-2
VETH_NS=v-proton-2-ns
TRANSIT_MAIN=172.31.2.1
EOF

# The management subnet the mock's address sits in. The last scenario points it
# somewhere the mock has no address, which is how "we cannot find our own
# address" is provoked.
MGMT_CIDR=172.20.0.0/24
# Where the script looks for trusted.py. One scenario points it at nothing, to
# stand in for a broken interpreter or a missing module.
RUN_BIN=""
# The UI's overlay file. Empty means "no overlay"; one scenario points it at a
# real file to prove the overlay wins over the base config, which is the
# precedence the broker has to match.
RUN_LOCAL_ENV=""
# The client VLAN. The stub's slots were built for 172.16.1.0/24; one scenario
# changes it under them, as an installer apply would.
RUN_CLIENT=172.16.1.0/24

# Every scenario is checked step by step: the stub appends to violations.log
# whenever a change leaves a state a packet could leak through.
touch "$TMP/check"

script_env() {
  env -i PATH="$PATH" FIX="$TMP" \
      PROTEUS_ENV_FILE=/dev/null PROTEUS_LOCAL_ENV_FILE="${RUN_LOCAL_ENV:-/dev/null}" \
      PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
      PROTEUS_STATE_DIR="$TMP/state" \
      PROTEUS_UDM_KEY_DIR="$TMP/keys" \
      PROTEUS_MGMT_CIDR="$MGMT_CIDR" \
      PROTEUS_CLIENT_VLAN_CIDR="$RUN_CLIENT" \
      PROTEUS_BIN="${RUN_BIN:-$ROOT/etc/proteus/bin}" \
      "$@"
}
run() { # run <trusted-json-body>
  printf '%s' "$1" > "$TMP/trusted.json"
  : > "$TMP/calls.log"
  script_env bash "$SCRIPT" </dev/null >"$TMP/out.log" 2>&1
}
# Like run, but SIGTERMed by the ip stub right after its <n>th state change, the
# way `systemctl restart` (the nft refill helper queues one) stops a running
# copy: the whole process group, whatever it is doing. setsid gives the run its
# own group, and the stub only signals the group recorded here, so a mistake
# cannot take the test down with it. `--norc` and the /dev/null stdin are not
# decoration: with SHLVL cleared by env -i and stdin a socket, `bash -c` takes
# itself for an rsh session and sources ~/.bashrc, whose PATH edits then find
# the real id(1) ahead of the stand-in.
run_killed() { # run_killed <n> <trusted-json-body>
  printf '%s' "$2" > "$TMP/trusted.json"
  : > "$TMP/calls.log"
  echo "$1" > "$TMP/kill-at"
  script_env setsid -w bash --norc -c 'echo $$ > "$FIX/kill-pgid"; exec bash "$0"' "$SCRIPT" \
      </dev/null >"$TMP/out.log" 2>&1 || true
  rm -f "$TMP/kill-at" "$TMP/kill-pgid"
}
called() { grep -cF -- "$1" "$TMP/calls.log" 2>/dev/null || true; }
# Every pref-95 rule, and the subset of them that names BOTH a source and a
# destination. The difference is a kill-switch bypass, not a style point: a
# pref-95 rule with no `to` matches every client-VLAN packet, and `lookup main`
# then succeeds on main's own default route — so rule resolution stops at 95 and
# the `fwmark N lookup 10N` rules that pick the slot table never run. The packet
# keeps its mark, the forward chain accepts it on that mark alone, and client
# egress leaves over the management interface with the VPN skipped entirely.
# Asserting only that a pref-95 rule exists cannot see that; counting both forms
# can.
p95_all()    { grep -c 'rule add .*pref 95' "$TMP/calls.log" 2>/dev/null || true; }
p95_scoped() { grep -c 'rule add from [0-9./]\+ to [0-9./]\+ lookup main pref 95' "$TMP/calls.log" 2>/dev/null || true; }
# del_rules calls `ip rule del` until it fails, so a successful teardown always
# shows two invocations. Count the ones that actually removed a rule.
deleted() { grep -cF -- "DELETED $1" "$TMP/calls.log" 2>/dev/null || true; }
# The line of the first call containing <text>, or empty. `|| true`: a call that
# never happened makes grep exit 1, and under `set -e` a failed command
# substitution would abort the whole file, turning one missing call into a run
# that reports nothing at all.
line_of() { grep -nF -- "$1" "$TMP/calls.log" | head -1 | cut -d: -f1 || true; }
# assert <first> happened, <second> happened, and <first> came first.
before() { # before <first> <second> <message>
  local a b r
  a=$(line_of "$1"); b=$(line_of "$2")
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] && r=ok || r="fail ($1 @${a:-never}, $2 @${b:-never})"
  assert_eq "$r" ok "$3"
}
# The stub's kernel state: back to a fresh box, or as a finished run for the
# given ranges would have left it (rules, table 110 with its catch, and a return
# rule, a table-110 route and a return route in each slot per range and for the
# tunnel subnet).
reset_state() { rm -f "$TMP/ipstate.json" "$TMP/violations.log"; }
seed_applied() { # seed_applied <range>...
  reset_state
  ip rule show >/dev/null   # the stub writes a fresh state on first use
  python3 - "$TMP/ipstate.json" "$@" <<'EOF'
import json, sys
path, ranges = sys.argv[1], sys.argv[2:]
st = json.load(open(path))
def dst(c):
    a, n = c.split("/")
    return {"dst": a} if n == "32" else {"dst": a, "dstlen": int(n)}
rules = [r for r in st["rules"] if r["priority"] == 0]
if ranges:
    rules.append({"priority": 90, "src": "172.20.0.119", "table": "254"})
rules += [dict(priority=95, src="172.16.1.0", srclen=24, table="254", **dst(c)) for c in ranges]
rules += [dict(priority=100, src="all", table="110", **dst(c))
          for c in (ranges + ["10.99.99.0/30"] if ranges else [])]
rules += [r for r in st["rules"] if r["priority"] > 0]
st["rules"] = rules
if ranges:
    st["tables"]["110"] = [{"dst": "default", "type": "blackhole", "metric": 4294967295}] + \
        [{"dst": c[:-3] if c.endswith("/32") else c, "dev": "wg-udm"}
         for c in ranges + ["10.99.99.0/30"]]
for n, routes in st["ns"].items():
    gw, veth = routes[1]["gateway"], routes[1]["dev"]
    routes += [{"dst": c, "gateway": gw, "dev": veth}
               for c in (ranges + ["10.99.99.0/30"] if ranges else [])]
st["ops"] = 0
json.dump(st, open(path, "w"))
EOF
  : > "$TMP/calls.log"
}
# Add one rule to the seeded state, at the END of its preference (where the
# kernel puts a rule added later) or, with --first, at the front of it.
seed_rule() { # seed_rule [--first] <rule-json>
  local first=0
  [ "$1" = --first ] && { first=1; shift; }
  python3 - "$TMP/ipstate.json" "$1" "$first" <<'EOF'
import json, sys
path, rule, first = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3] == "1"
st = json.load(open(path))
p = rule["priority"]
i = next(i for i, r in enumerate(st["rules"])
         if (r["priority"] >= p if first else r["priority"] > p))
st["rules"].insert(i, rule)
json.dump(st, open(path, "w"))
EOF
}
# The rules at the three owned preferences, one per line, as pref|from|to|table.
owned_rules() {
  python3 -c '
import json, sys
for r in json.load(open(sys.argv[1]))["rules"]:
    if r["priority"] in (90, 95, 100):
        s = r["src"] if r["src"] == "all" else "%s/%s" % (r["src"], r.get("srclen", 32))
        d = "%s/%s" % (r["dst"], r.get("dstlen", 32)) if "dst" in r else "all"
        print("%d|%s|%s|%s" % (r["priority"], s, d, r.get("table", "-")))' "$TMP/ipstate.json"
}
# A slot's routes (one destination per line) and table 110's.
ns_routes() { python3 -c 'import json,sys; [print(r["dst"]) for r in json.load(open(sys.argv[1]))["ns"][sys.argv[2]]]' "$TMP/ipstate.json" "$1"; }
t110() { python3 -c 'import json,sys; [print(r["dst"], r.get("metric", 0)) for r in json.load(open(sys.argv[1]))["tables"].get("110", [])]' "$TMP/ipstate.json"; }
# Everything but the change counter, order-independent, for "did anything change".
snapshot() {
  python3 -c '
import json, sys
st = json.load(open(sys.argv[1])); st.pop("ops", None)
st["rules"] = sorted(json.dumps(r, sort_keys=True) for r in st["rules"])
for k, v in list(st["tables"].items()) + list(st["ns"].items()):
    v.sort(key=lambda r: json.dumps(r, sort_keys=True))
print(json.dumps(st, sort_keys=True))' "$TMP/ipstate.json"
}
ops() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ops"])' "$TMP/ipstate.json"; }
# Nothing any change left behind could leak through, then start the next
# scenario with a clean log.
no_gap() { # no_gap <message>
  assert_eq "$(cat "$TMP/violations.log" 2>/dev/null)" "" "$1"
  rm -f "$TMP/violations.log"
}

ONE='{"trusted":[{"cidr":"192.168.7.0/24"}]}'

echo "unpaired box: no server key means no tunnel, whatever the list says"
rm -f "$TMP/keys/server.key" "$TMP/keys/peer.pub"
run "$ONE"
assert_eq "$(called 'link add wg-udm')" "0" "no interface without a key"
assert_eq "$(grep -c 'not paired' "$TMP/out.log")" "1" "and it says why"

echo "no pairing at all plus an empty list is a complete teardown (the shipped default)"
echo "PRIVKEY" > "$TMP/keys/server.key"
# Half a pairing is not a pairing: our own key without the UDM's public key
# gives the interface no peer to handshake with, so this must still tear
# everything down. Emptying the list matters on a box that already has a tunnel;
# without one standing, "interface removed" below would pass for the wrong reason.
# Likewise the routing state a previous run for one range would have left.
touch "$TMP/wg-udm.up"
seed_applied 192.168.7.0/24
run '{"trusted":[]}'
assert_eq "$(called 'flush set inet filter trusted_src')" "1" "set emptied"
assert_eq "$(called 'route flush table 110')" "1" "tunnel table emptied"
assert_eq "$(deleted 'rule del pref 100')" "2" "return rules removed, the range's and the tunnel subnet's"
assert_eq "$(deleted 'rule del pref 95')" "1" "client-VLAN pin removed"
assert_eq "$(deleted 'rule del pref 90')" "1" "self pin removed"
assert_eq "$(called 'link del wg-udm')" "1" "interface removed"
assert_eq "$(called 'rule add')" "0" "nothing added back"
assert_eq "$(grep -c 'no trusted ranges configured and no UDM pairing' "$TMP/out.log")" "1" \
    "and the log names both halves of why"

echo "a pairing plus an empty list: the tunnel comes up so it can be verified, and nothing else does"
# The rollout is pair -> confirm the handshake -> watch which source addresses
# arrive -> then configure a range. Every one of those steps needs a live
# interface, and none of them may forward a packet.
echo "CURRENTKEY" > "$TMP/keys/peer.pub"
rm -f "$TMP/wg-udm.up"
seed_applied 192.168.7.0/24
run '{"trusted":[]}'
assert_eq "$(called 'link add wg-udm type wireguard')" "1" "the tunnel is created"
assert_eq "$(called 'link set wg-udm up')" "1" "and brought up"
assert_eq "$(called 'addr replace 10.99.99.1/30 dev wg-udm')" "1" "with its address"
assert_eq "$(called 'link set mtu 1420 dev wg-udm')" "1" "and its MTU"
assert_eq "$(called 'peer CURRENTKEY allowed-ips 10.99.99.0/30')" "1" \
    "the peer is configured, admitting the tunnel subnet and nothing else"
assert_eq "$(called 'link del wg-udm')" "0" "the interface is NOT torn down"
assert_eq "$(called 'add element inet filter trusted_src')" "0" "the gate stays empty"
assert_eq "$(called 'flush set inet filter trusted_src')" "1" "and is flushed of anything stale"
assert_eq "$(called 'rule add')" "0" "no policy rule is installed"
assert_eq "$(deleted 'rule del pref 95')" "1" "and a stale transit rule is removed alongside pref 100"
assert_eq "$(deleted 'rule del pref 100')" "2" \
    "as are the return rule it was paired with and the tunnel subnet's"
assert_eq "$(called 'route replace')" "0" "no route into table 110, and no namespace return route"
assert_eq "$(t110)" "" "table 110 is empty, its catch included"
assert_eq "$(ns_routes ns-proton-1 | tr '\n' ' ')" "default 172.16.1.0/24 " \
    "the range's and the tunnel subnet's return routes are gone from the slots; the client VLAN's stays"
assert_eq "$(grep -c 'up for pairing verification' "$TMP/out.log")" "1" \
    "the log says the tunnel is up for verification"
assert_eq "$(grep -c 'NO trusted ranges are configured' "$TMP/out.log")" "1" \
    "and that nothing is routed through it yet"
# Not checked for gaps: the seeded state routes the tunnel subnet back to a
# wg-udm that does not exist, which is broken before the run starts and is not
# what this scenario is about. The unpaired teardown below covers that order.
rm -f "$TMP/violations.log"

echo "a populated list installs exactly the state the data path needs"
# From a box with no interface, so "tunnel created" below means what it says
# rather than inheriting the one the verification scenario just raised.
rm -f "$TMP/wg-udm.up"
run "$ONE"
assert_eq "$(called 'add element inet filter trusted_src { 192.168.7.0/24 }')" "1" "operator range in the set"
assert_eq "$(called 'add element inet filter trusted_src { 10.99.99.0/30 }')" "1" \
    "tunnel subnet too: covers the case where the UDM masquerades"
assert_eq "$(called 'rule add from 172.20.0.119 lookup main pref 90')" "1" \
    "proteus' own traffic pinned to its normal path (keeps the web UI reachable)"
assert_eq "$(called 'rule add from 172.16.1.0/24 to 192.168.7.0/24 lookup main pref 95')" "1" \
    "client-VLAN transit to the trusted range restored, scoped to that destination"
assert_eq "$(p95_all)" "1" "exactly one pref-95 rule for the one configured range"
assert_eq "$(p95_scoped)" "$(p95_all)" "and it names both a source and a destination"
assert_eq "$(called 'rule add from 172.16.1.0/24 lookup main pref 95')" "0" \
    "never destination-agnostic: that shape shadows the fwmark rules and sends client egress out the WAN"
assert_eq "$(called 'rule add to 192.168.7.0/24 lookup 110 pref 100')" "1" "return rule"
assert_eq "$(called 'route replace 192.168.7.0/24 dev wg-udm table 110')" "1" "return route"
assert_eq "$(called 'route replace blackhole default metric 4294967295 table 110')" "1" \
    "and a catch behind it, so a missing route is a drop and not a fall-through to main"
assert_eq "$(called 'rule add to 10.99.99.0/30 lookup 110 pref 100')" "1" \
    "the tunnel subnet gets a return rule too, so losing wg-udm cannot send its replies to main"
assert_eq "$(called 'route replace 10.99.99.0/30 dev wg-udm table 110')" "1" "and a route in table 110"
assert_eq "$(called 'to 10.99.99.0/30 lookup main pref 95')" "0" \
    "but no client-VLAN pin: main would send those packets into wg-udm as well"
assert_eq "$(called 'link add wg-udm type wireguard')" "1" "tunnel created"
assert_eq "$(called 'addr replace 10.99.99.1/30 dev wg-udm')" "1" "proteus takes the first address"
assert_eq "$(called 'link set mtu 1420 dev wg-udm')" "1" "MTU matches the Proton tunnels"

echo "every existing namespace gets a return route, without waiting for a rotation"
assert_eq "$(called '-n ns-proton-1 route replace 192.168.7.0/24 via 172.31.1.1')" "1" "slot 1"
assert_eq "$(called '-n ns-proton-2 route replace 192.168.7.0/24 via 172.31.2.1')" "1" "slot 2"

echo "the ordering rules that protect the web UI and the client pivot come before the tunnel rule"
# `|| true` on each: a rule that was never added makes grep exit 1, and under
# `set -e` a failed command substitution would abort the whole file — turning a
# single missing rule into a run that reports nothing at all.
P90=$(grep -n 'rule add from 172.20.0.119 lookup main pref 90' "$TMP/calls.log" | head -1 | cut -d: -f1 || true)
P95=$(grep -n 'rule add from 172.16.1.0/24 to 192.168.7.0/24 lookup main pref 95' "$TMP/calls.log" | head -1 | cut -d: -f1 || true)
P100=$(grep -n 'rule add to 192.168.7.0/24 lookup 110 pref 100' "$TMP/calls.log" | head -1 | cut -d: -f1 || true)
[ -n "$P90" ] && [ -n "$P100" ] && [ "$P90" -lt "$P100" ] && r=ok || r=fail
assert_eq "$r" ok "pref 90 installed before pref 100"
[ -n "$P95" ] && [ -n "$P100" ] && [ "$P95" -lt "$P100" ] && r=ok || r=fail
assert_eq "$r" ok "pref 95 installed before pref 100"
before 'route replace blackhole default metric 4294967295 table 110' 'rule add to 192.168.7.0/24 lookup 110 pref 100' \
    "the catch is in table 110 before any rule leads there"
before 'route replace 192.168.7.0/24 dev wg-udm table 110' 'rule add to 192.168.7.0/24 lookup 110 pref 100' \
    "and the range's route before its rule"
before 'route replace 10.99.99.0/30 dev wg-udm table 110' 'rule add to 10.99.99.0/30 lookup 110 pref 100' \
    "as is the tunnel subnet's"
before 'rule add from 172.20.0.119 lookup main pref 90' 'rule add to 10.99.99.0/30 lookup 110 pref 100' \
    "and pref 90 comes before that rule as well"
before 'rule add to 192.168.7.0/24 lookup 110 pref 100' 'nft -f -' \
    "the gate admits the range only once its replies have a way back"
before 'nft -f -' '-n ns-proton-1 route replace 192.168.7.0/24' \
    "and the slots route replies back here only after that"
assert_eq "$(called 'rule del')" "0" "a first apply removes nothing"
no_gap "no step of a first apply leaves a reply a way out through main"

echo "running twice changes nothing, and never takes a live rule or route away even for a moment"
# This is the gap the reconcile used to open on every run (boot, every UI save,
# every pairing): all rules deleted, table 110 flushed, then everything added
# back, with a slot's reply to a trusted host routed via main and out the
# uplink in between.
BEFORE=$(snapshot)
run "$ONE"
assert_eq "$(snapshot)" "$BEFORE" "the kernel state is exactly what it was"
assert_eq "$(called 'rule del')" "0" "no rule was removed, not even to be put back"
assert_eq "$(called 'route flush')" "0" "table 110 was not flushed"
assert_eq "$(called 'route del')" "0" "and no route was removed, in table 110 or in a slot"
no_gap "no step of a repeat run leaves a reply a way out through main"

echo "two ranges get one scoped transit rule each, and nothing wider"
# The count is what pins the shape: a rule built per range can only ever divert
# the destinations the operator named, while a single rule covering "the client
# VLAN" diverts everything that VLAN sends anywhere.
run '{"trusted":[{"cidr":"192.168.7.0/24"},{"cidr":"192.168.8.0/24"}]}'
assert_eq "$(p95_all)" "2" "one pref-95 rule per configured range"
assert_eq "$(p95_scoped)" "2" "each naming both a source and a destination"
assert_eq "$(called 'rule add from 172.16.1.0/24 to 192.168.7.0/24 lookup main pref 95')" "1" "first range"
assert_eq "$(called 'rule add from 172.16.1.0/24 to 192.168.8.0/24 lookup main pref 95')" "1" "second range"
assert_eq "$(grep -c 'rule add to 192.168.[78].0/24 lookup 110 pref 100' "$TMP/calls.log")" "2" \
    "and one return rule per range, as before"

echo "re-pairing revokes the old peer: a superseded key must not keep working"
printf 'STALEKEY\nCURRENTKEY\n' > "$TMP/peers"
run "$ONE"
assert_eq "$(called 'peer CURRENTKEY allowed-ips 10.99.99.0/30,192.168.7.0/24')" "1" \
    "the current peer is given the trusted ranges"
assert_eq "$(called 'peer STALEKEY remove')" "1" "the peer a re-pairing superseded is removed"
assert_eq "$(called 'peer CURRENTKEY remove')" "0" "and the current one is left alone"
rm -f "$TMP/peers"

echo "the UI overlay wins over the base config for the tunnel's own settings"
# The two settings a site may legitimately vary — the tunnel subnet and the MTU
# — are read base-then-overlay, the precedence every script here uses and the
# one the broker has to match, so they can be changed in proteus-local.env
# without editing code. The listen port is deliberately not among them: it is
# fixed in lockstep with nftables.conf's UDM_TUNNEL_PORT define.
cat > "$TMP/local.env" <<'EOF'
PROTEUS_UDM_TUNNEL_CIDR=10.98.98.0/30
PROTEUS_UDM_TUNNEL_MTU=1380
EOF
RUN_LOCAL_ENV="$TMP/local.env"
run "$ONE"
assert_eq "$(called 'link set mtu 1380 dev wg-udm')" "1" "the overlay's MTU is applied"
assert_eq "$(called 'addr replace 10.98.98.1/30 dev wg-udm')" "1" "and the overlay's tunnel subnet"
assert_eq "$(called 'add element inet filter trusted_src { 10.98.98.0/30 }')" "1" \
    "which the gate follows, so the two cannot disagree"
RUN_LOCAL_ENV=""

echo "a partially applied prior state is cleaned up, not added to"
# Two stale ranges survive from an earlier run, rules and all, one with its route.
seed_applied 192.168.7.0/24
seed_rule '{"priority":95,"src":"172.16.1.0","srclen":24,"dst":"192.168.9.0","dstlen":24,"table":"254"}'
seed_rule '{"priority":95,"src":"172.16.1.0","srclen":24,"dst":"192.168.10.5","table":"254"}'
seed_rule '{"priority":100,"src":"all","dst":"192.168.9.0","dstlen":24,"table":"110"}'
seed_rule '{"priority":100,"src":"all","dst":"192.168.10.5","table":"110"}'
python3 -c 'import json,sys; p=sys.argv[1]; st=json.load(open(p)); st["tables"]["110"].append({"dst":"192.168.9.0/24","dev":"wg-udm","metric":5}); json.dump(st,open(p,"w"))' "$TMP/ipstate.json"
run "$ONE"
assert_eq "$(deleted 'rule del pref 100')" "2" "both stale return rules removed"
assert_eq "$(deleted 'rule del pref 95')" "2" "and both stale transit rules"
assert_eq "$(deleted 'rule del pref 100 to 192.168.10.5/32 lookup 110')" "1" \
    "a /32 is named with its length, although ip prints it without one"
assert_eq "$(owned_rules | grep '^100|' | sort | tr '\n' ' ')" "100|all|10.99.99.0/30|110 100|all|192.168.7.0/24|110 " \
    "the return rules left are the configured range's and the tunnel subnet's"
assert_eq "$(called 'route del 192.168.9.0/24 metric 5 table 110')" "1" \
    "a stale route in table 110 is removed by its own metric"
assert_eq "$(t110 | sort | tr '\n' ' ')" "10.99.99.0/30 0 192.168.7.0/24 0 default 4294967295 " \
    "leaving the catch, the range and the tunnel subnet"
no_gap "cleaning up leaves no gap"

echo "nftables not loaded yet: say so rather than report success"
touch "$TMP/no-set"
run "$ONE"
assert_eq "$(called 'add element inet filter trusted_src')" "0" "no elements into a set that is not there"
assert_eq "$(grep -c 'gate not applied' "$TMP/out.log")" "1" "the log says the gate was not applied"
rm -f "$TMP/no-set"

echo "a tooling failure is not an operator decision: change nothing, and say so"
RUN_BIN="$TMP/nonexistent"
rc=0; run "$ONE" || rc=$?
assert_eq "$rc" "1" "non-zero, so a broken tool shows up in systemctl status"
assert_eq "$(called 'rule del')" "0" "nothing torn down"
assert_eq "$(called 'link del wg-udm')" "0" "a working tunnel is left exactly as it was"
assert_eq "$(grep -c 'could not read' "$TMP/out.log")" "1" "and the log says the list could not be read"
RUN_BIN=""

echo "a malformed file is treated as off, never as a wildcard"
run 'this is not json'
assert_eq "$(called 'add element inet filter trusted_src')" "0" "nothing trusted"
assert_eq "$(called 'flush set inet filter trusted_src')" "1" "the gate is emptied"
assert_eq "$(called 'rule add')" "0" "and nothing is routed"
# On a PAIRED box an unreadable list means the same as an empty one: no ranges
# yet. The interface stays so the operator can still see the tunnel state while
# they fix the file; the scenario above covers the unpaired case, where the
# interface does come down.
assert_eq "$(called 'route replace')" "0" "not even a table-110 route"

echo "a range the broker would reject cannot be smuggled in by hand-editing"
run '{"trusted":[{"cidr":"0.0.0.0/0"}]}'
assert_eq "$(called 'add element inet filter trusted_src')" "0" "public range refused by trusted.load"

echo "our own address unfindable: fail closed, because pref 100 without pref 90 IS the lockout"
MGMT_CIDR=172.31.250.0/24   # the mock has no address here
run "$ONE"
assert_eq "$(called 'rule add to 192.168.7.0/24 lookup 110 pref 100')" "0" \
    "no return rule when the rule that protects the web UI cannot be built"
assert_eq "$(called 'add element inet filter trusted_src')" "0" "nothing trusted"
assert_eq "$(called 'link del wg-udm')" "1" "the tunnel is taken down, not left half-configured"
assert_eq "$(called 'link add wg-udm type wireguard')" "0" "and never raised again"
assert_eq "$(grep -c 'no address found inside 172.31.250.0/24' "$TMP/out.log")" "1" "the log names the reason"
MGMT_CIDR=172.20.0.0/24

echo "deleting peer.pub revokes the pairing: the interface goes, and its peers with it"
# Half a pairing cannot carry traffic — there is no peer to handshake with — so
# this is the one state that still removes the interface even though our own key
# is intact. Deleting the link is a stronger revocation than removing the peer:
# whatever keys it carried go with it.
printf 'OLDPEER\n' > "$TMP/peers"
rm -f "$TMP/keys/peer.pub"
touch "$TMP/wg-udm.up"
run "$ONE"
assert_eq "$(called 'link del wg-udm')" "1" "the interface carrying the superseded peer is removed"
assert_eq "$(called 'rule add')" "0" "and nothing is routed to a tunnel that no longer exists"
assert_eq "$(grep -c 'not paired' "$TMP/out.log")" "1" "the log says the box is not paired"
rm -f "$TMP/peers"
echo "CURRENTKEY" > "$TMP/keys/peer.pub"

echo "an unparseable PROTEUS_MGMT_CIDR is named as the cause, not folded into 'feature off'"
MGMT_CIDR="not-a-cidr"
rc=0; run "$ONE" || rc=$?
assert_eq "$rc" "0" "a bad config value is not a crash"
assert_eq "$(called 'add element inet filter trusted_src')" "0" "nothing trusted with a broken guard"
assert_eq "$(grep -c 'no trusted ranges configured' "$TMP/out.log")" "0" \
    "does not misreport a broken guard as an operator choice"
assert_eq "$(grep -c "PROTEUS_MGMT_CIDR 'not-a-cidr' is not a valid IPv4 CIDR" "$TMP/out.log")" "1" \
    "the log names the real cause"
MGMT_CIDR=172.20.0.0/24

echo "a shape-only check is not enough: an out-of-range CIDR must fail too, not just a garbage string"
# /33 and a >255 octet both match a digits-dot-digits-slash-digits regex, so a
# shape check alone would wave them through, come back empty from trusted.py,
# and get logged as "feature off" — the exact misreport this validation exists
# to prevent.
for bad in "172.20.0.0/33" "999.1.1.1/24"; do
    MGMT_CIDR="$bad"
    rc=0; run "$ONE" || rc=$?
    assert_eq "$rc" "0" "$bad: a bad config value is not a crash"
    assert_eq "$(called 'add element inet filter trusted_src')" "0" "$bad: nothing trusted with a broken guard"
    assert_eq "$(grep -c "PROTEUS_MGMT_CIDR '$bad' is not a valid IPv4 CIDR" "$TMP/out.log")" "1" \
        "$bad: named as the cause, not just shape-checked"
done
MGMT_CIDR=172.20.0.0/24

echo "a save that could not get the lock in time is NOT applied — and that shows up in systemctl status"
touch "$TMP/flock-fail"
rc=0; run "$ONE" || rc=$?
assert_eq "$rc" "1" "a timeout surfaces as a failure, not a silent no-op"
assert_eq "$(grep -c 'NOT applied' "$TMP/out.log")" "1" "the log says the save did not take effect"
assert_eq "$(grep -c 'systemctl start proteus-trusted-egress.service' "$TMP/out.log")" "1" "and names the remedy"
assert_eq "$(called 'add element inet filter trusted_src')" "0" "nothing was reconciled while the lock sat elsewhere"
rm -f "$TMP/flock-fail"

# ---------------------------------------------------------------------------
# Make before break. A slot's reply to a trusted host is accepted by the forward
# chain as established, so the moment it finds no pref-100 rule it routes via
# main and out the uplink. The stub checks after every change that no such
# moment exists (no_gap); the scenarios below pin the order that guarantees it.
# ---------------------------------------------------------------------------
A=192.168.7.0/24 C=192.168.9.0/24
AB='{"trusted":[{"cidr":"192.168.7.0/24"},{"cidr":"192.168.8.0/24"}]}'
# A and C applied, and a pref-90 rule left from an earlier management address.
# The next save swaps C for B.
setup_swap() {
  seed_applied "$A" "$C"
  seed_rule '{"priority":90,"src":"172.20.0.50","table":"254"}'
  touch "$TMP/wg-udm.up"
}

echo "a range added and a range removed in one save: every addition before the first removal"
setup_swap
run "$AB"
before 'rule add to 192.168.8.0/24 lookup 110 pref 100' 'DELETED' \
    "the new range's return rule is in before anything is removed"
before '-n ns-proton-1 route del 192.168.9.0/24' 'DELETED rule del pref 100 to 192.168.9.0/24 lookup 110' \
    "slot 1 stops routing the removed range's replies back before its return rule goes"
before '-n ns-proton-2 route del 192.168.9.0/24' 'DELETED rule del pref 100 to 192.168.9.0/24 lookup 110' \
    "and so does slot 2"
before 'DELETED rule del pref 100 to 192.168.9.0/24' 'DELETED rule del pref 95 from 172.16.1.0/24 to 192.168.9.0/24' \
    "the return rule goes before its client-VLAN pin"
before 'DELETED rule del pref 95 from 172.16.1.0/24 to 192.168.9.0/24' 'route del 192.168.9.0/24 table 110' \
    "and the range's route only once no rule leads to it"
before 'DELETED rule del pref 100 to 192.168.9.0/24' 'DELETED rule del pref 90 from 172.20.0.50/32 lookup 254' \
    "a superseded pref-90 rule goes last"
assert_eq "$(grep -c '^DELETED' "$TMP/calls.log")" "3" \
    "exactly the three stale rules are removed, and no live one"
assert_eq "$(owned_rules | sort | tr '\n' ' ')" \
    "100|all|10.99.99.0/30|110 100|all|192.168.7.0/24|110 100|all|192.168.8.0/24|110 90|172.20.0.119/32|all|254 95|172.16.1.0/24|192.168.7.0/24|254 95|172.16.1.0/24|192.168.8.0/24|254 " \
    "the rules are now exactly the new list's"
assert_eq "$(t110 | sort | tr '\n' ' ')" "10.99.99.0/30 0 192.168.7.0/24 0 192.168.8.0/24 0 default 4294967295 " \
    "table 110 holds the new list's routes, the tunnel subnet's and the catch"
assert_eq "$(ns_routes ns-proton-1 | sort | tr '\n' ' ')" \
    "10.99.99.0/30 172.16.1.0/24 192.168.7.0/24 192.168.8.0/24 default " \
    "a slot routes the new list back and keeps the client VLAN's route"
no_gap "no step of the swap leaves a reply a way out through main"

echo "killed at any step of that save, the next run finishes the job, and no step leaves a gap"
# The nft refill helper restarts this unit on every ruleset load, which can land
# in the middle of a run. Kill after each state change in turn, then run again.
setup_swap; run "$AB"; N=$(ops); REF=$(snapshot)
: > "$TMP/sweep-gaps.log"; stopped=""; unconverged=""
for k in $(seq 1 "$N"); do
  setup_swap
  run_killed "$k" "$AB"
  [ "$(ops)" = "$k" ] || stopped="$stopped $k(changes: $(ops); $(tail -1 "$TMP/out.log"))"
  run "$AB"
  [ "$(snapshot)" = "$REF" ] || unconverged="$unconverged $k"
  [ -f "$TMP/violations.log" ] && sed "s/^/killed at $k: /" "$TMP/violations.log" >> "$TMP/sweep-gaps.log"
done
assert_eq "$([ "$N" -ge 10 ] && echo yes || echo "no ($N)")" yes "the swap is at least ten separate changes"
assert_eq "${stopped# }" "" "each killed run stopped right where it was killed"
assert_eq "${unconverged# }" "" "and the run after it reached the same state as an uninterrupted one"
assert_eq "$(cat "$TMP/sweep-gaps.log")" "" "no kill point, and no step of the recovery run, leaves a gap"

echo "switching the feature off (paired, list emptied): gate, then slots, then rules, pref 90 last"
seed_applied "$A"; touch "$TMP/wg-udm.up"
run '{"trusted":[]}'
before 'nft flush set inet filter trusted_src' '-n ns-proton-1 route del 192.168.7.0/24' \
    "the gate closes first, so nothing new is dispatched"
before '-n ns-proton-2 route del 10.99.99.0/30' 'DELETED rule del pref 100' \
    "every slot stops routing trusted replies back before the first return rule goes"
before 'DELETED rule del pref 100' 'DELETED rule del pref 95' "return rules before client-VLAN pins"
before 'DELETED rule del pref 95' 'route flush table 110' "the table only once no rule leads to it"
before 'route flush table 110' 'DELETED rule del pref 90' \
    "pref 90 last: the web UI's replies never meet a pref-100 rule without it"
assert_eq "$(ns_routes ns-proton-1 | sort | tr '\n' ' ')" "172.16.1.0/24 default " \
    "in-flight replies now stay in their slot's tunnel; the client VLAN's route is untouched"
no_gap "no step of switching off leaves a reply a way out through main"

echo "unpairing: the slots stop routing the tunnel subnet back before the interface goes"
# Deleting wg-udm takes the tunnel subnet's connected route with it, and a reply
# a slot still sent here would then route via main.
seed_applied "$A"; touch "$TMP/wg-udm.up"; rm -f "$TMP/keys/peer.pub"
run "$ONE"
before '-n ns-proton-2 route del 10.99.99.0/30' 'link del wg-udm' "slot routes first, interface last"
no_gap "no step of unpairing leaves a reply a way out through main"
echo "CURRENTKEY" > "$TMP/keys/peer.pub"

echo "wg-udm deleted out from under a running config: the catch drops what its routes carried"
# When a device goes away the kernel removes every route through it, table 110's
# included, and a pref-100 lookup over an empty table would fall through to main.
# The tunnel subnet is in the same position: wg-udm's connected route in main
# goes with the device, so without its own return rule a slot's reply to the
# tunnel address would route via main's default. From a fresh box, so the catch
# is the one this run put there.
reset_state; touch "$TMP/wg-udm.up"
run "$ONE"
rm -f "$TMP/violations.log"
ip link del wg-udm
assert_eq "$(t110 | tr '\n' ' ')" "default 4294967295 " "only the catch is left in table 110"
no_gap "so the range's replies and the tunnel subnet's are dropped, not sent to main"

echo "a rule this script never installs is left alone, and named"
seed_applied "$A"; touch "$TMP/wg-udm.up"
seed_rule '{"priority":100,"src":"all","fwmark":"0x5","table":"110"}'
run "$ONE"
assert_eq "$(grep -c '^DELETED' "$TMP/calls.log")" "0" "nothing is removed"
assert_eq "$(owned_rules | grep -c '^100|all|all|110$')" "1" "the foreign rule is still there"
assert_eq "$(grep -c 'WARN: left a rule at pref 100 alone' "$TMP/out.log")" "1" "and the log says so"
no_gap "a foreign rule does not open a gap"

echo "a stale rule whose delete would hit another rule first is kept, and so is its pin"
# `ip rule del pref 100 to C lookup 110` removes the first pref-100 rule to C,
# and a rule with an iif is such a rule: the kernel ignores what the request
# does not name. Deleting would take the wrong one.
seed_applied "$A"; touch "$TMP/wg-udm.up"
seed_rule '{"priority":95,"src":"172.16.1.0","srclen":24,"dst":"192.168.9.0","dstlen":24,"table":"254"}'
seed_rule '{"priority":100,"src":"all","iif":"lo","dst":"192.168.9.0","dstlen":24,"table":"110"}'
seed_rule '{"priority":100,"src":"all","dst":"192.168.9.0","dstlen":24,"table":"110"}'
run "$ONE"
assert_eq "$(deleted 'rule del pref 100')" "0" "neither pref-100 rule to that range is removed"
assert_eq "$(owned_rules | grep -c '^95|172.16.1.0/24|192.168.9.0/24|')" "1" \
    "and its client-VLAN pin stays while a return rule for it does"
assert_eq "$(grep -c 'WARN: kept a stale rule at pref 100' "$TMP/out.log")" "1" "the log names the rule it kept"
no_gap "keeping it opens no gap"

echo "the destination-agnostic pin an old version left behind is removed, the scoped one kept"
# Installed before the scoped rules, so it is first in the list and the delete
# takes it, not them. (The kernel refuses to add it after a scoped rule.) The
# foreign pref-100 rule with no destination is there to prove it does not count
# as "a return rule for the same range" and keep this pin alive.
seed_applied "$A"; touch "$TMP/wg-udm.up"
seed_rule --first '{"priority":95,"src":"172.16.1.0","srclen":24,"table":"254"}'
seed_rule '{"priority":100,"src":"all","fwmark":"0x5","table":"110"}'
run "$ONE"
assert_eq "$(deleted 'rule del pref 95 from 172.16.1.0/24 lookup 254')" "1" "the agnostic pin is removed"
assert_eq "$(owned_rules | grep '^95|' | tr '\n' ' ')" "95|172.16.1.0/24|192.168.7.0/24|254 " \
    "the scoped one is what is left"
no_gap "removing it opens no gap"

echo "a pin left from an earlier client VLAN goes, although its range stays configured"
# Only a STALE return rule keeps a stale pin: the range's live return rule has
# its own, current pin next to it.
seed_applied "$A"; touch "$TMP/wg-udm.up"
seed_rule '{"priority":95,"src":"172.16.2.0","srclen":24,"dst":"192.168.7.0","dstlen":24,"table":"254"}'
run "$ONE"
assert_eq "$(deleted 'rule del pref 95 from 172.16.2.0/24 to 192.168.7.0/24 lookup 254')" "1" "the old pin is removed"
assert_eq "$(owned_rules | grep '^95|' | tr '\n' ' ')" "95|172.16.1.0/24|192.168.7.0/24|254 " "the current one stays"
no_gap "removing it opens no gap"

echo "a slot that cannot be cleaned holds back every removal, and the run fails so it is retried"
setup_swap
touch "$TMP/ns-del-fail"
rc=0; run "$AB" || rc=$?
assert_eq "$rc" "1" "non-zero: Restart=on-failure tries again"
assert_eq "$(grep -c '^DELETED' "$TMP/calls.log")" "0" "no rule is removed while a slot may still route C back"
assert_eq "$(called 'route del 192.168.9.0/24 table 110')" "0" "nor C's route"
assert_eq "$(grep -c 'rules for removed ranges are kept' "$TMP/out.log")" "1" "the log says why"
rm -f "$TMP/ns-del-fail"
run "$AB"
assert_eq "$(owned_rules | grep -c '192.168.9.0/24')" "0" "the next run removes them"
no_gap "neither run leaves a gap"

echo "a rule add that fails for a real reason stops the run before the gate opens"
reset_state; touch "$TMP/wg-udm.up" "$TMP/rule-add-fail"
rc=0; run "$ONE" || rc=$?
assert_eq "$rc" "1" "non-zero"
assert_eq "$(called 'nft -f -')" "0" "the gate is not opened for a range with no rules"
assert_eq "$(grep -c 'ERROR: ip rule add' "$TMP/out.log")" "1" "the log names the failing add"
rm -f "$TMP/rule-add-fail"
no_gap "and nothing it did leaves a gap"

# "File exists" is not proof the rule is there. The kernel's duplicate test
# ignores a selector the new rule leaves out, so a rule with an extra selector at
# the same preference blocks the add, and the removal step then took it for a
# stale rule: the wanted rule never existed.
echo "a look-alike at pref 90 is not taken for the web UI's pin"
seed_applied
seed_rule '{"priority":90,"src":"172.20.0.119","dst":"8.8.8.8","table":"254"}'
run "$ONE"
assert_eq "$(owned_rules | grep '^90|' | tr '\n' ' ')" "90|172.20.0.119/32|all|254 " \
    "the pin is installed, and the look-alike is gone"
before 'DELETED rule del pref 90 from 172.20.0.119/32 to 8.8.8.8/32 lookup 254' \
    'rule add to 192.168.7.0/24 lookup 110 pref 100' "it makes room before any return rule goes in"
assert_eq "$(grep -c 'WARN: removing a rule at pref 90 that blocks' "$TMP/out.log")" "1" "and the log says so"
no_gap "no step sends the web UI's replies to a trusted host into the tunnel"

echo "a look-alike at pref 100 is not taken for a range's return rule"
seed_applied
seed_rule '{"priority":100,"src":"198.51.100.4","dst":"192.168.7.0","dstlen":24,"table":"110"}'
run "$ONE"
assert_eq "$(owned_rules | grep '^100|' | sort | tr '\n' ' ')" "100|all|10.99.99.0/30|110 100|all|192.168.7.0/24|110 " \
    "the return rule is installed, and the look-alike is gone"
before 'DELETED rule del pref 100 from 198.51.100.4/32 to 192.168.7.0/24 lookup 110' 'nft -f -' \
    "before the gate admits the range"
no_gap "no step leaves a reply to the range a way out through main"

echo "a look-alike the script may not remove fails the run before any return rule"
# A tos is compared only when the new rule names one, so this blocks the pin too.
seed_applied
seed_rule '{"priority":90,"src":"172.20.0.119","tos":"0x10","table":"254"}'
rc=0; run "$ONE" || rc=$?
assert_eq "$rc" "1" "non-zero"
assert_eq "$(called 'lookup 110 pref 100')" "0" "no return rule goes in without the pin"
assert_eq "$(called 'nft -f -')" "0" "the gate is not opened"
assert_eq "$(grep -c 'duplicate of a rule this script does not remove: {"priority":90' "$TMP/out.log")" "1" \
    "the log names the rule"
assert_eq "$(called 'rule del')" "0" "which is left alone"
no_gap "and nothing it did leaves a gap"

echo "a slot keeps the client VLAN route it was built with when PROTEUS_CLIENT_VLAN_CIDR changes"
# vpnns-up.sh added it for the CIDR of the day, and an installer apply does not
# rebuild running slots. Removing it would send the clients' replies into the
# slot's own tunnel until the slot rotates. The feature-off paths run on every
# box, at boot and on every nft reload, so they are checked first.
RUN_CLIENT=172.16.0.0/23
reset_state; rm -f "$TMP/keys/peer.pub"
run '{"trusted":[]}'
assert_eq "$(ns_routes ns-proton-1 | grep -c '^172.16.1.0/24$')" "1" "an unpaired box leaves it"
echo "CURRENTKEY" > "$TMP/keys/peer.pub"
run '{"trusted":[]}'
assert_eq "$(ns_routes ns-proton-1 | grep -c '^172.16.1.0/24$')" "1" "so does a paired one with no ranges"
seed_applied "$A"; touch "$TMP/wg-udm.up"
run "$ONE"
assert_eq "$(called 'route del 172.16.1.0/24')" "0" "and a reconcile with a range"
assert_eq "$(ns_routes ns-proton-2 | sort | tr '\n' ' ')" "10.99.99.0/30 172.16.1.0/24 192.168.7.0/24 default " \
    "which still removes nothing else and adds what it should"
RUN_CLIENT=172.16.1.0/25
run '{"trusted":[]}'
assert_eq "$(ns_routes ns-proton-1 | grep -c '^172.16.1.0/24$')" "1" "a narrower client VLAN leaves it too"
RUN_CLIENT=172.16.1.0/24
no_gap "none of it leaves a gap"

echo "switching off with a slot that cannot be cleaned keeps the rules and fails, so it is retried"
# That slot may still route the range's replies back here. With the rules they
# reach wg-udm, whose peer no longer admits the range; without them they would
# route via main and leave the uplink.
seed_applied "$A"; touch "$TMP/wg-udm.up" "$TMP/ns-del-fail"
rc=0; run '{"trusted":[]}' || rc=$?
assert_eq "$rc" "1" "non-zero: Restart=on-failure tries again"
assert_eq "$(called 'nft flush set inet filter trusted_src')" "1" "the gate is closed all the same"
assert_eq "$(grep -c '^DELETED' "$TMP/calls.log")" "0" "no rule is removed"
assert_eq "$(called 'route flush table 110')" "0" "and table 110 is not flushed"
assert_eq "$(grep -c 'rules and table 110 are kept until it can be cleaned' "$TMP/out.log")" "1" "the log says why"
rm -f "$TMP/ns-del-fail"
rc=0; run '{"trusted":[]}' || rc=$?
assert_eq "$rc/$(owned_rules | wc -l)" "0/0" "the retry succeeds and removes them"
no_gap "neither run leaves a gap"

echo "unpairing with a slot that cannot be cleaned: the interface goes, the rules stay over the catch"
seed_applied "$A"; touch "$TMP/wg-udm.up" "$TMP/ns-del-fail"; rm -f "$TMP/keys/peer.pub"
rc=0; run "$ONE" || rc=$?
assert_eq "$rc" "1" "non-zero"
assert_eq "$(called 'link del wg-udm')" "1" "the revoked pairing's interface is removed all the same"
assert_eq "$(owned_rules | grep -c '^100|')" "2" "the return rules stay, the tunnel subnet's included"
assert_eq "$(t110 | tr '\n' ' ')" "default 4294967295 " "over the catch, which drops what the slot still sends"
rm -f "$TMP/ns-del-fail"
rc=0; run "$ONE" || rc=$?
assert_eq "$rc/$(owned_rules | wc -l)" "0/0" "the retry removes them"
echo "CURRENTKEY" > "$TMP/keys/peer.pub"
no_gap "neither run leaves a gap"

# The same kill sweep as for the swap, on the two ways of switching off.
sweep_off() { # sweep_off <label> <trusted-json-body>
  local k n ref stopped="" unconverged=""
  : > "$TMP/sweep-gaps.log"
  seed_applied "$A"; touch "$TMP/wg-udm.up"; run "$2"; n=$(ops); ref=$(snapshot)
  for k in $(seq 1 "$n"); do
    seed_applied "$A"; touch "$TMP/wg-udm.up"
    run_killed "$k" "$2"
    [ "$(ops)" = "$k" ] || stopped="$stopped $k"
    run "$2"
    [ "$(snapshot)" = "$ref" ] || unconverged="$unconverged $k"
    [ -f "$TMP/violations.log" ] && sed "s/^/killed at $k: /" "$TMP/violations.log" >> "$TMP/sweep-gaps.log"
    rm -f "$TMP/violations.log"
  done
  assert_eq "$([ "$n" -ge 8 ] && echo yes || echo "no ($n)")" yes "$1 is at least eight changes"
  assert_eq "${stopped# }/${unconverged# }" "/" "$1: each killed run stopped there, and the next converged"
  assert_eq "$(cat "$TMP/sweep-gaps.log")" "" "$1: no kill point, and no step of the recovery, leaves a gap"
}
echo "killed at any step of switching off or unpairing, the next run finishes it without a gap"
sweep_off "switching off" '{"trusted":[]}'
rm -f "$TMP/keys/peer.pub"
sweep_off "unpairing" "$ONE"
echo "CURRENTKEY" > "$TMP/keys/peer.pub"

echo "a freshly rotated slot gets the same return routes without a reconcile run"
VUP="$ROOT/etc/proteus/bin/vpnns-up.sh"
# The loop is what matters, not the 200 lines of namespace construction around
# it, so extract and run just that block against the mocks.
sed -n '/^# Return path for the client subnet/,/^done$/p' "$VUP" > "$TMP/vup-frag.sh"
assert_eq "$(grep -c 'trusted.py list' "$TMP/vup-frag.sh")" "1" "the fragment consults trusted.py"
assert_eq "$(grep -c -- '--mgmt-cidr' "$TMP/vup-frag.sh")" "1" "and passes the guard subnets, so a hand-edited file cannot widen it"
# The sed range needs a real end-anchor match, or it silently reads to EOF and
# the "isolated" fragment is actually the rest of the script — a re-indented
# `done` reproduces this and every assertion below would still spuriously
# pass, because the mocks swallow whatever runs past the intended block too.
assert_eq "$(grep -c 'route add default dev wg0' "$TMP/vup-frag.sh")" "0" \
    "the fragment stops at its own block, not somewhere later in the file"
: > "$TMP/calls.log"; reset_state
printf '%s' "$ONE" > "$TMP/trusted.json"
env -i PATH="$PATH" FIX="$TMP" \
    NS=ns-proton-3 VETH_NS=v-proton-3-ns TRANSIT_MAIN=172.31.3.1 \
    INSTANCE=proton-3 CLIENT_VLAN_CIDR=172.16.1.0/24 \
    PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
    PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30 \
    PROTEUS_MGMT_CIDR=172.20.0.0/24 \
    PROTEUS_BIN="$ROOT/etc/proteus/bin" \
    bash "$TMP/vup-frag.sh" >/dev/null 2>&1
assert_eq "$(called '-n ns-proton-3 route replace 192.168.7.0/24 via 172.31.3.1')" "1" "trusted range routed back"
assert_eq "$(called '-n ns-proton-3 route replace 10.99.99.0/30 via 172.31.3.1')" "1" "tunnel subnet routed back"

echo "the DNS namespace is left alone: it carries resolver traffic, not client traffic"
: > "$TMP/calls.log"; reset_state
env -i PATH="$PATH" FIX="$TMP" \
    NS=ns-dns-6 VETH_NS=v-dns-6-ns TRANSIT_MAIN=172.31.6.1 \
    INSTANCE=dns-6 CLIENT_VLAN_CIDR=172.16.1.0/24 \
    PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
    PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30 \
    PROTEUS_MGMT_CIDR=172.20.0.0/24 \
    PROTEUS_BIN="$ROOT/etc/proteus/bin" \
    bash "$TMP/vup-frag.sh" >/dev/null 2>&1
assert_eq "$(called '-n ns-dns-6 route replace 192.168.7.0/24')" "0" "no trusted routes in the DNS namespace"

echo "an inherited _trusted from the caller's environment cannot leak into the DNS namespace"
: > "$TMP/calls.log"; reset_state
env -i PATH="$PATH" FIX="$TMP" \
    NS=ns-dns-6 VETH_NS=v-dns-6-ns TRANSIT_MAIN=172.31.6.1 \
    INSTANCE=dns-6 CLIENT_VLAN_CIDR=172.16.1.0/24 \
    PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
    PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30 \
    PROTEUS_MGMT_CIDR=172.20.0.0/24 \
    PROTEUS_BIN="$ROOT/etc/proteus/bin" \
    _trusted="10.55.55.0/24" \
    bash "$TMP/vup-frag.sh" >/dev/null 2>&1
assert_eq "$(called '-n ns-dns-6 route replace 10.55.55.0/24')" "0" \
    "a value _trusted happened to hold on the way in is not this namespace's to route"

echo "a slot brought up while the trusted list is empty gets exactly the routes it did before this feature"
: > "$TMP/calls.log"; reset_state
printf '%s' '{"trusted":[]}' > "$TMP/trusted.json"
env -i PATH="$PATH" FIX="$TMP" \
    NS=ns-proton-3 VETH_NS=v-proton-3-ns TRANSIT_MAIN=172.31.3.1 \
    INSTANCE=proton-3 CLIENT_VLAN_CIDR=172.16.1.0/24 \
    PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
    PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30 \
    PROTEUS_MGMT_CIDR=172.20.0.0/24 \
    PROTEUS_BIN="$ROOT/etc/proteus/bin" \
    bash "$TMP/vup-frag.sh" >/dev/null 2>&1
assert_eq "$(called '-n ns-proton-3 route add 172.16.1.0/24 via 172.31.3.1')" "1" "the pre-existing client route is untouched"
assert_eq "$(called '-n ns-proton-3 route replace')" "0" "no extra route — not the tunnel subnet either — when the feature is off"

echo "a malformed trusted.json cannot add a return route, not even the tunnel subnet"
: > "$TMP/calls.log"; reset_state
printf '%s' 'this is not json' > "$TMP/trusted.json"
env -i PATH="$PATH" FIX="$TMP" \
    NS=ns-proton-3 VETH_NS=v-proton-3-ns TRANSIT_MAIN=172.31.3.1 \
    INSTANCE=proton-3 CLIENT_VLAN_CIDR=172.16.1.0/24 \
    PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
    PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30 \
    PROTEUS_MGMT_CIDR=172.20.0.0/24 \
    PROTEUS_BIN="$ROOT/etc/proteus/bin" \
    bash "$TMP/vup-frag.sh" >/dev/null 2>&1
assert_eq "$(called '-n ns-proton-3 route replace')" "0" "nothing trusted from a broken file"

echo "a broken trusted.py (missing python3) cannot abort the bring-up"
# Under set -euo pipefail — the real script's own shebang discipline, which is
# why this scenario runs the fragment with the same flags — a bare
# '_trusted=$(...)' propagates a failed command substitution's exit status
# like any other simple command. A python3 that is missing (127) or a
# trusted.py that is missing/misplaced (2) must not kill a slot bring-up.
mkdir -p "$TMP/bin-no-python"
cat > "$TMP/bin-no-python/python3" <<'EOF'
#!/usr/bin/env bash
exit 127
EOF
chmod +x "$TMP/bin-no-python/python3"
: > "$TMP/calls.log"; reset_state
printf '%s' "$ONE" > "$TMP/trusted.json"
rc=0
env -i PATH="$TMP/bin-no-python:$PATH" FIX="$TMP" \
    NS=ns-proton-3 VETH_NS=v-proton-3-ns TRANSIT_MAIN=172.31.3.1 \
    INSTANCE=proton-3 CLIENT_VLAN_CIDR=172.16.1.0/24 \
    PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
    PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30 \
    PROTEUS_MGMT_CIDR=172.20.0.0/24 \
    PROTEUS_BIN="$ROOT/etc/proteus/bin" \
    bash -euo pipefail "$TMP/vup-frag.sh" >/dev/null 2>&1 || rc=$?
assert_eq "$rc" "0" "a missing python3 does not abort the fragment"
assert_eq "$(called '-n ns-proton-3 route add 172.16.1.0/24 via 172.31.3.1')" "1" "the client route still lands"
assert_eq "$(called '-n ns-proton-3 route replace')" "0" "no trusted route when the lookup itself failed"
rm -rf "$TMP/bin-no-python"

summary
