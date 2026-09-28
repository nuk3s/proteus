#!/usr/bin/env bash
# tests/trusted_reconcile_netns_test.sh
#
# The routing half of trusted_egress_test.sh, on a real kernel. It runs the real
# proteus-trusted-egress.sh inside an unprivileged user, network and mount
# namespace, with a real wg-udm and a real slot namespace, and after EVERY ip(8)
# call that changes routing state it asks the kernel where three packets would
# go:
#
#   a slot's reply to a trusted host   from inside the slot, and if it crosses
#                                      back, from here. It may reach wg-udm,
#                                      stay in the slot's own tunnel, or be
#                                      dropped. Leaving by ens18 is the leak.
#   the web UI's reply to that host    from the management address. It must
#                                      never go to wg-udm.
#   a client-VLAN host's pivot to it   never to wg-udm either.
#
# Every step of a reconcile is also a point where systemd can stop the unit
# (the nft refill helper restarts it), so "fine at every step" is the property.
#
# Skips, and passes, where the environment cannot run it: no unprivileged user
# namespaces, no wireguard module, or a missing tool.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Another version of the script can be checked the same way, e.g. an older one,
# to watch these checks fail on it.
SCRIPT="${TRUSTED_EGRESS_SCRIPT:-$ROOT/etc/proteus/bin/proteus-trusted-egress.sh}"

if [[ "${1:-}" != --inner ]]; then
    for t in unshare ip wg nft python3 flock; do
        command -v "$t" >/dev/null 2>&1 || { echo "  - SKIPPED: $t not available"; exit 0; }
    done
    if ! unshare -rnm --propagation private true 2>/dev/null; then
        echo "  - SKIPPED: unprivileged user namespaces are not available here"
        exit 0
    fi
    W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
    # stdin from /dev/null: see run_killed in trusted_egress_test.sh for what a
    # socket there does to `bash` started with a cleared environment.
    unshare -rnm --propagation private bash "$0" --inner "$W" "$SCRIPT" </dev/null
    rc=$?
    if (( rc == 77 )); then
        echo "  - SKIPPED: $(cat "$W/skip" 2>/dev/null)"
        exit 0
    fi
    exit "$rc"
fi

# ---------------------------------------------------------------------------
# Inside: root of a private user+net+mount namespace.
# ---------------------------------------------------------------------------
W=$2 SCRIPT=$3
. "$ROOT/tests/_assert.sh"
skip() { echo "$*" > "$W/skip"; exit 77; }

mount -t tmpfs tmpfs /run 2>/dev/null || skip "cannot mount a private /run for ip netns"
REAL_IP=$(command -v ip)
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2 \
    || skip "cannot set sysctls in the namespace"
ip link set lo up

# The box: management uplink, client VLAN, one slot. Addresses as in the other
# tests; 203.0.113.10 stands for a server on the internet.
ip link add ens18 type dummy && ip addr add 172.20.0.119/24 dev ens18 && ip link set ens18 up
ip route add default via 172.20.0.1 dev ens18
ip link add ens19 type dummy && ip addr add 172.16.1.5/24 dev ens19 && ip link set ens19 up
ip link add wgprobe type wireguard 2>/dev/null || skip "no wireguard support in this kernel"
ip link del wgprobe
ip netns add ns-proton-1 || skip "ip netns add failed"
ip link add v-proton-1 type veth peer name v-proton-1-ns netns ns-proton-1
ip addr add 172.31.1.1/30 dev v-proton-1 && ip link set v-proton-1 up
ip -n ns-proton-1 link set lo up
ip -n ns-proton-1 addr add 172.31.1.2/30 dev v-proton-1-ns
ip -n ns-proton-1 link set v-proton-1-ns up
# wg0 stands for the slot's Proton tunnel: a reply the slot does not route back
# here leaves through it, as it did before trusted egress existed.
ip -n ns-proton-1 link add wg0 type dummy && ip -n ns-proton-1 link set wg0 up
ip -n ns-proton-1 route add default dev wg0
ip -n ns-proton-1 route add 172.16.1.0/24 via 172.31.1.1 dev v-proton-1-ns
ip netns exec ns-proton-1 sysctl -qw net.ipv4.ip_forward=1 \
    net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
nft -f - <<'EOF' || skip "nft cannot load a table here"
table inet filter {
    set trusted_src { type ipv4_addr; flags interval; auto-merge; }
}
EOF

mkdir -p "$W/bin" "$W/state" "$W/keys"
( umask 077; wg genkey > "$W/keys/server.key"; wg genkey | wg pubkey > "$W/keys/peer.pub" )
cp "$W/keys/peer.pub" "$W/peer.pub.saved"
cat > "$W/state/proton-1.state" <<'EOF'
INSTANCE=proton-1
NS=ns-proton-1
VETH_NS=v-proton-1-ns
TRANSIT_MAIN=172.31.1.1
EOF

# The probe. One line per routing change: the step, the command, and a verdict
# per host. 192.168.7.5 is in range A, 192.168.8.5 in range B, and 10.99.99.2
# is the tunnel address a masquerading UDM sends everything from (UI and pivot
# are not asked about it: the tunnel is the only way to it).
cat > "$W/probe.sh" <<EOF
#!/usr/bin/env bash
IP=$REAL_IP
EOF
cat >> "$W/probe.sh" <<'EOF'
reply() {   # where a slot's reply to $1 ends up
    local r
    r=$($IP -n ns-proton-1 route get "$1" from 203.0.113.10 iif wg0 2>&1)
    case "$r" in *"dev wg0"*) echo slot; return;; *"dev v-proton-1-ns"*) ;; *) echo "slot?$r"; return;; esac
    r=$($IP route get "$1" from 203.0.113.10 iif v-proton-1 2>&1)
    case "$r" in
        *"dev wg-udm"*) echo tunnel ;;
        *"dev ens18"*) echo LEAK ;;
        *"Invalid argument"*|*"No route to host"*|*"unreachable"*) echo drop ;;
        *) echo "other?$(echo "$r" | head -1)" ;;
    esac
}
ui() { case "$($IP route get "$1" from 172.20.0.119 2>&1)" in *"dev wg-udm"*) echo UI-TUNNEL;; *) echo ui-ok;; esac; }
pivot() { case "$($IP route get "$1" from 172.16.1.50 iif ens19 2>&1)" in *"dev wg-udm"*) echo PIVOT-TUNNEL;; *) echo pivot-ok;; esac; }
line="$1"
for h in 192.168.7.5 192.168.8.5; do line="$line	$h=$(reply $h)/$(ui $h)/$(pivot $h)"; done
line="$line	10.99.99.2=$(reply 10.99.99.2)"
echo "$line"
EOF
chmod +x "$W/probe.sh"

# ip for the script under test: the real one, followed by a probe whenever the
# call could have changed where a packet goes. With $W/ns-del-fail present, a
# route delete inside a namespace fails, the way it does when a slot rotates
# under a run.
cat > "$W/bin/ip" <<EOF
#!/usr/bin/env bash
if [ -e "$W/ns-del-fail" ]; then
    case " \$* " in *" -n "*" route del "*) echo "RTNETLINK answers: No such process" >&2; exit 2 ;; esac
fi
$REAL_IP "\$@"; rc=\$?
case " \$* " in
    *" rule add "*|*" rule del "*|*" route replace "*|*" route add "*|*" route del "*|*" route flush "*)
        "$W/probe.sh" "ip \$*" >> "$W/probes.log" ;;
    *" link del "*|*" link add "*|*" link set "*|*" addr replace "*|*" addr add "*|*" addr del "*)
        "$W/probe.sh" "ip \$*" >> "$W/probes.log" ;;
esac
exit \$rc
EOF
chmod +x "$W/bin/ip"

A='{"cidr":"192.168.7.0/24"}' B='{"cidr":"192.168.8.0/24"}'
# The client VLAN the script is told about. The slot was built for
# 172.16.1.0/24; one scenario changes it, as an installer apply would.
CLIENT=172.16.1.0/24
reconcile() { # reconcile <label> <trusted-json-body>
    printf '%s' "$2" > "$W/trusted.json"
    echo "== $1" >> "$W/probes.log"
    env -i PATH="$W/bin:$PATH" \
        PROTEUS_ENV_FILE=/dev/null PROTEUS_LOCAL_ENV_FILE=/dev/null \
        PROTEUS_TRUSTED_FILE="$W/trusted.json" PROTEUS_STATE_DIR="$W/state" \
        PROTEUS_UDM_KEY_DIR="$W/keys" PROTEUS_MGMT_CIDR=172.20.0.0/24 \
        PROTEUS_CLIENT_VLAN_CIDR="$CLIENT" PROTEUS_BIN="$ROOT/etc/proteus/bin" \
        bash "$SCRIPT" </dev/null >>"$W/script.log" 2>&1
    "$W/probe.sh" final >> "$W/probes.log"
}
# The probe lines of the last scenario, and what they say about one host.
last() { awk '/^== /{buf=""; next} {buf=buf $0 "\n"} END{printf "%s", buf}' "$W/probes.log"; }
bad() { last | grep -cE 'LEAK|UI-TUNNEL|PIVOT-TUNNEL|other\?|slot\?' || true; }
final() { last | grep '^final' | tr '\t' '\n' | sed -n "s/^$1=//p"; }
steps() { last | grep -vc '^final' || true; }
# Every routing change of the last scenario left no way out; the first few
# offending probe lines are shown when one did.
no_way_out() {
    local n; n=$(bad)
    assert_eq "$n" "0" "$(steps) routing changes, none with a way out"
    [ "$n" = 0 ] || last | grep -E 'LEAK|UI-TUNNEL|PIVOT-TUNNEL|other\?|slot\?' | head -3 | tr '\t' ' ' | sed 's/^/      /'
}

echo "first apply of range A: at no step does anything leave the wrong way"
reconcile "apply A" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(final 192.168.7.5)" "tunnel/ui-ok/pivot-ok" \
    "then: the slot's reply to A reaches wg-udm, the UI and the pivot use the uplink"
assert_eq "$(final 10.99.99.2)" "tunnel" "and a reply to the tunnel address reaches wg-udm"

echo "the same list again, the reconcile that used to open the gap every time"
reconcile "repeat A" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(final 192.168.7.5)" "tunnel/ui-ok/pivot-ok" "and A is still routed back through the tunnel"

echo "adding range B"
reconcile "add B" "{\"trusted\":[$A,$B]}"
no_way_out
assert_eq "$(final 192.168.8.5)" "tunnel/ui-ok/pivot-ok" "B is routed back through the tunnel"

echo "the probe can see a leak: A's return rule removed by hand"
echo "== by hand" >> "$W/probes.log"
PATH="$W/bin:$PATH" ip rule del pref 100 to 192.168.7.0/24 lookup 110
assert_eq "$(last | grep -c '192.168.7.5=LEAK')" "1" "a slot's reply to A then leaves by ens18"

echo "removing range A while its flows are in flight"
reconcile "repair" "{\"trusted\":[$A,$B]}"
reconcile "remove A" "{\"trusted\":[$B]}"
no_way_out
assert_eq "$(final 192.168.7.5)" "slot/ui-ok/pivot-ok" \
    "A's replies now stay in the slot's own tunnel instead of crossing back"
assert_eq "$(final 192.168.8.5)" "tunnel/ui-ok/pivot-ok" "and B is untouched"

echo "switching the feature off with the box still paired"
reconcile "off, paired" '{"trusted":[]}'
no_way_out
assert_eq "$(final 192.168.8.5)" "slot/ui-ok/pivot-ok" "B's replies stay in the slot"
assert_eq "$(final 10.99.99.2)" "slot" "and so do the tunnel address's"

echo "unpairing a box that routes range A"
reconcile "A again" "{\"trusted\":[$A]}"
rm -f "$W/keys/peer.pub"
reconcile "unpair" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(ip link show wg-udm >/dev/null 2>&1 && echo present || echo gone)" "gone" "wg-udm is gone"
assert_eq "$(final 10.99.99.2)" "slot" "and replies to the tunnel address stay in the slot"

echo "wg-udm deleted by something else while A is routed: the catch drops A's replies"
cp "$W/peer.pub.saved" "$W/keys/peer.pub"
reconcile "pair, A" "{\"trusted\":[$A]}"
echo "== link gone" >> "$W/probes.log"
PATH="$W/bin:$PATH" ip link del wg-udm
assert_eq "$(last | tr '\t' '\n' | sed -n 's/^192.168.7.5=//p')" "drop/ui-ok/pivot-ok" \
    "a slot's reply to A is dropped, not sent to main"
# wg-udm's connected route in main goes with the device too; the tunnel subnet's
# own return rule sends the reply to the catch instead of main's default route.
assert_eq "$(last | tr '\t' '\n' | sed -n 's/^10.99.99.2=//p')" "drop" \
    "and so is its reply to the tunnel address"

# "File exists" from `ip rule add` is not proof the rule is there: the kernel's
# duplicate test ignores a selector the new rule leaves out.
echo "a look-alike at pref 90 is not taken for the web UI's pin"
reconcile "off" '{"trusted":[]}'
$REAL_IP rule add from 172.20.0.119 to 8.8.8.8 lookup main pref 90
reconcile "look-alike 90" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(final 192.168.7.5)" "tunnel/ui-ok/pivot-ok" "then A is routed back and the UI still answers on the uplink"
assert_eq "$($REAL_IP rule show pref 90 | grep -c '8.8.8.8')/$($REAL_IP rule show pref 90 | wc -l)" "0/1" \
    "the pin replaced the look-alike"

echo "a look-alike at pref 100 is not taken for a range's return rule"
reconcile "off" '{"trusted":[]}'
$REAL_IP rule add from 198.51.100.4 to 192.168.7.0/24 lookup 110 pref 100
reconcile "look-alike 100" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(final 192.168.7.5)" "tunnel/ui-ok/pivot-ok" "A's replies reach wg-udm"

echo "a changed PROTEUS_CLIENT_VLAN_CIDR leaves the slot's client route alone"
slot_client() {
    case "$($REAL_IP -n ns-proton-1 route get 172.16.1.50 from 203.0.113.10 iif wg0 2>&1)" in
        *"dev v-proton-1-ns"*) echo back ;; *) echo LOST ;;
    esac
}
CLIENT=172.16.0.0/23
reconcile "client widened" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(slot_client)" "back" "a reconcile leaves it, so replies to a client still come back"
reconcile "client widened, off" '{"trusted":[]}'
assert_eq "$(slot_client)" "back" "and so does switching off"
CLIENT=172.16.1.0/24

echo "switching off while a slot cannot be cleaned keeps the rules until a retry can"
reconcile "A" "{\"trusted\":[$A]}"
touch "$W/ns-del-fail"
reconcile "off, slot stuck" '{"trusted":[]}'
no_way_out
assert_eq "$(final 192.168.7.5)" "tunnel/ui-ok/pivot-ok" \
    "the slot still routes A back, and the kept rules take it to wg-udm, not the uplink"
rm -f "$W/keys/peer.pub"
reconcile "unpair, slot stuck" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(final 192.168.7.5)" "drop/ui-ok/pivot-ok" "unpaired, wg-udm is gone and A's replies meet the catch"
assert_eq "$(final 10.99.99.2)" "drop" "as do the tunnel address's"
rm -f "$W/ns-del-fail"
reconcile "retry" "{\"trusted\":[$A]}"
no_way_out
assert_eq "$(final 192.168.7.5)/$(final 10.99.99.2)" "slot/ui-ok/pivot-ok/slot" \
    "the retry cleans the slot, and its replies stay in the slot's tunnel"
assert_eq "$($REAL_IP rule show | grep -cE '^(90|95|100):')" "0" "and removes the rules"
cp "$W/peer.pub.saved" "$W/keys/peer.pub"

summary
