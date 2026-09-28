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
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/etc/proteus/bin/proteus-trusted-egress.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/keys"
export FIX="$TMP"

# Mocks record their argv so we can assert on intent rather than on kernel state.
for tool in nft ip wg; do
  cat > "$TMP/bin/$tool" <<EOF
#!/usr/bin/env bash
echo "$tool \$*" >> "\$FIX/calls.log"
case "\$*" in
  # 'nft -f -' carries the whole transaction on stdin, so argv alone would say
  # nothing about what landed in the set. Record the transaction itself — and
  # read it, or the script's writer takes a SIGPIPE and dies.
  "-f -") cat >> "\$FIX/calls.log";;
  # 'ip netns list' drives the per-namespace return-route loop.
  "netns list") printf 'ns-proton-1\nns-proton-2\n';;
  # The pref-90 rule is derived from our own address, so the mock has to have one.
  "-4 -o addr show") printf '2: ens18    inet 172.20.0.119/24 brd 172.20.0.255 scope global ens18\n';;
  # Interface presence must be stateful, or the script can never decide whether
  # to create the tunnel and the create/delete assertions below are vacuous.
  "link show wg-udm") [ -f "\$FIX/wg-udm.up" ] || exit 1;;
  "link add wg-udm type wireguard") touch "\$FIX/wg-udm.up";;
  "link del wg-udm") rm -f "\$FIX/wg-udm.up";;
  # Which peers the tunnel already carries. A scenario writes this fixture to
  # say a previous pairing is still configured.
  "show wg-udm peers") cat "\$FIX/peers" 2>/dev/null;;
  # A rule delete loop must terminate: succeed once per rule the fixture says
  # sits at that preference (one unless \$FIX/rules.<pref> says otherwise, which
  # is how a partially applied prior state is simulated), then fail.
  "rule del pref "*) pref="\$4"
                     want=\$(cat "\$FIX/rules.\$pref" 2>/dev/null || echo 1)
                     have=\$(grep -cF "DELETED \$*" "\$FIX/calls.log" 2>/dev/null)
                     [ "\${have:-0}" -ge "\$want" ] && exit 1
                     echo "DELETED \$*" >> "\$FIX/calls.log";;
  # Whether nftables holds the set at all; the flag file lets a scenario say the
  # ruleset has not loaded yet.
  "list set"*) [ -f "\$FIX/no-set" ] && exit 1;;
esac
exit 0
EOF
  chmod +x "$TMP/bin/$tool"
done
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

run() { # run <trusted-json-body>
  printf '%s' "$1" > "$TMP/trusted.json"
  : > "$TMP/calls.log"
  env -i PATH="$PATH" FIX="$TMP" \
      PROTEUS_ENV_FILE=/dev/null PROTEUS_LOCAL_ENV_FILE="${RUN_LOCAL_ENV:-/dev/null}" \
      PROTEUS_TRUSTED_FILE="$TMP/trusted.json" \
      PROTEUS_STATE_DIR="$TMP/state" \
      PROTEUS_UDM_KEY_DIR="$TMP/keys" \
      PROTEUS_MGMT_CIDR="$MGMT_CIDR" \
      PROTEUS_CLIENT_VLAN_CIDR=172.16.1.0/24 \
      PROTEUS_BIN="${RUN_BIN:-$ROOT/etc/proteus/bin}" \
      bash "$SCRIPT" >"$TMP/out.log" 2>&1
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
touch "$TMP/wg-udm.up"
run '{"trusted":[]}'
assert_eq "$(called 'flush set inet filter trusted_src')" "1" "set emptied"
assert_eq "$(called 'route flush table 110')" "1" "tunnel table emptied"
assert_eq "$(deleted 'rule del pref 100')" "1" "return rule removed"
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
assert_eq "$(deleted 'rule del pref 100')" "1" "as is the return rule it was paired with"
assert_eq "$(called 'route replace')" "0" "no route into table 110, and no namespace return route"
assert_eq "$(grep -c 'up for pairing verification' "$TMP/out.log")" "1" \
    "the log says the tunnel is up for verification"
assert_eq "$(grep -c 'NO trusted ranges are configured' "$TMP/out.log")" "1" \
    "and that nothing is routed through it yet"

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

echo "running twice changes nothing (deletes are unconditional, adds are not doubled)"
BEFORE=$(sort "$TMP/calls.log" | grep -c 'rule add\|route replace\|add element')
run "$ONE"
AFTER=$(sort "$TMP/calls.log" | grep -c 'rule add\|route replace\|add element')
assert_eq "$AFTER" "$BEFORE" "idempotent"

echo "two ranges get one scoped transit rule each, and nothing wider"
# The count is what pins the shape: a rule built per range can only ever divert
# the destinations the operator named, while a single rule covering "the client
# VLAN" diverts everything that VLAN sends anywhere.
run '{"trusted":[{"cidr":"192.168.7.0/24"},{"cidr":"192.168.8.0/24"}]}'
assert_eq "$(p95_all)" "2" "one pref-95 rule per configured range"
assert_eq "$(p95_scoped)" "2" "each naming both a source and a destination"
assert_eq "$(called 'rule add from 172.16.1.0/24 to 192.168.7.0/24 lookup main pref 95')" "1" "first range"
assert_eq "$(called 'rule add from 172.16.1.0/24 to 192.168.8.0/24 lookup main pref 95')" "1" "second range"
assert_eq "$(grep -c 'rule add to .* lookup 110 pref 100' "$TMP/calls.log")" "2" \
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
echo 2 > "$TMP/rules.100"   # two stale return rules survive from an earlier run
run "$ONE"
assert_eq "$(deleted 'rule del pref 100')" "2" "both stale return rules removed"
assert_eq "$(called 'rule add to 192.168.7.0/24 lookup 110 pref 100')" "1" "exactly one added back"
rm -f "$TMP/rules.100"

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
: > "$TMP/calls.log"
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
: > "$TMP/calls.log"
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
: > "$TMP/calls.log"
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
: > "$TMP/calls.log"
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
: > "$TMP/calls.log"
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
: > "$TMP/calls.log"
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
