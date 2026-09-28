#!/usr/bin/env bash
# tests/marked_egress_guard_test.sh
#
# VPN-bound traffic must never leave by any interface other than its slot veth.
# That used to fail open: vpnns-up.sh / vpnns-down.sh deleted the slot's fwmark
# rule and flushed its table, the rule walk fell through to `main` (default
# route = the uplink), and the forward chain accepted the packet on its mark
# with no output-interface check. A dispatched flow that lost its mark (trusted
# range removed, a dispatcher verdict that never reached conntrack, no ruleset
# at all) ended the same way. The fix has two layers, each pinned here:
#   1. routing (routeguard.sh): a blackhole sentinel in every slot table, rules
#      kept across rebuilds, a static `not fwmark 0x0/0xffffffff blackhole`
#      catch rule, and
#      an ingress sink keyed on the client interface and wg-udm;
#   2. firewall (nftables.conf + template): prerouting_ctsave, the chain forward
#      guards and unmarked-client-egress, and chain postrouting_guard.
# The end-to-end proof is tests/rebuild_leak_sim.sh, which is slow and needs
# kernel features; this file is the fast, always-on part.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$ROOT/etc/nftables.conf"
TMPL="$ROOT/install/templates/nftables.conf.tmpl"
UP="$ROOT/etc/proteus/bin/vpnns-up.sh"
DOWN="$ROOT/etc/proteus/bin/vpnns-down.sh"
RG="$ROOT/etc/proteus/bin/routeguard.sh"
APPLY="$ROOT/install/lib/apply.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

code_only() { grep -vE '^[[:space:]]*(#|$)' "$1" || true; }
line_of() {   # <file> <fixed string>: first line number of a non-comment match
    { grep -nF -- "$2" "$1" || true; } | { grep -vE '^[0-9]+:[[:space:]]*#' || true; } | head -1 | cut -d: -f1
}
before() {    # <file> <a> <b>: "yes" iff a's first line precedes b's
    local a b; a=$(line_of "$1" "$2"); b=$(line_of "$1" "$3")
    [[ -n "$a" && -n "$b" && "$a" -lt "$b" ]] && echo yes || echo no
}
cnt_re() { grep -cE -- "$1" || true; }   # count lines of stdin matching an ERE (0 is not an error)
cnt_fx() { grep -cF -- "$1" || true; }   # ... a fixed string
userns_ok() { command -v unshare >/dev/null 2>&1 && unshare -rn true 2>/dev/null; }

# ---------------------------------------------------------------------------
echo "layer 1 (routing): vpnns-up.sh never opens a fall-through window"
assert_eq "$(code_only "$UP" | cnt_re 'ip rule del')" "0" "vpnns-up.sh deletes no ip rule (a missing rule sends the mark to main)"
assert_eq "$(code_only "$UP" | cnt_re 'ip route flush')" "0" "vpnns-up.sh flushes no route table (an empty table falls through to main)"
assert_eq "$(code_only "$UP" | cnt_fx 'routeguard.sh')" "1" "vpnns-up.sh sources routeguard.sh"
assert_eq "$(before "$UP" 'rg_sentinel_ensure "$RT_TABLE"' 'ip netns del "$NS"')" yes \
    "the blackhole sentinel goes in BEFORE the teardown"
assert_eq "$(before "$UP" 'rg_sentinel_ensure "$RT_TABLE"' 'ip link del "$VETH_MAIN"')" yes \
    "... and before the old veth (and with it the tunnel route) is deleted"
assert_eq "$(code_only "$UP" | cnt_re '^[[:space:]]*rg_sentinel_ensure "\$RT_TABLE"[[:space:]]*$')" "1" \
    "the sentinel is fatal under set -e (no '|| true'): no sentinel, no teardown"
assert_eq "$(before "$UP" 'rg_sink_ensure' 'ip netns del "$NS"')" yes "the ingress sink is armed before the teardown"
assert_eq "$(code_only "$UP" | cnt_re '^rg_sink_ensure \|\| ')" "1" "... non-fatally (the sentinel already covers this slot)"
assert_eq "$(code_only "$UP" | cnt_re 'ip route del default via "\$TRANSIT_NS" table "\$RT_TABLE"')" "1" \
    "teardown removes the tunnel route specifically (a 'via' delete cannot hit the sentinel)"
assert_eq "$(code_only "$UP" | cnt_re '^[[:space:]]*ip rule add ')" "0" \
    "no bare 'ip rule add' (a surviving identical rule would abort the run under set -e)"
assert_eq "$(code_only "$UP" | cnt_fx 'rg_rule_ensure fwmark "$FWMARK" lookup "$RT_TABLE"')" "1" "fwmark rule is add-if-absent"
assert_eq "$(code_only "$UP" | cnt_fx 'rg_rule_ensure from "$TRANSIT_MAIN" lookup "$RT_TABLE"')" "1" "source rule is add-if-absent"
assert_eq "$(before "$UP" 'ip route replace default via "$TRANSIT_NS"' 'rg_rule_ensure fwmark')" yes \
    "the tunnel route goes in before the rule (a first bring-up never has a rule over an empty table)"

echo "layer 1 (routing): vpnns-down.sh leaves the slot failing closed"
assert_eq "$(code_only "$DOWN" | cnt_re 'ip rule del')" "0" "vpnns-down.sh keeps the rules (they now point at a sentinel-only table)"
assert_eq "$(code_only "$DOWN" | cnt_re 'ip route flush')" "0" "vpnns-down.sh flushes no table"
assert_eq "$(before "$DOWN" 'rg_sentinel_ensure "$RT_TABLE"' 'ip netns del "$NS"')" yes "sentinel before teardown"
assert_eq "$(before "$DOWN" 'rg_catch_ensure' 'ip route del default via')" yes "catch rule before the tunnel route goes"
assert_eq "$(before "$DOWN" 'rg_sink_ensure' 'ip route del default via')" yes "ingress sink before the tunnel route goes"

echo "layer 1 (routing): routeguard.sh constants"
rgvar() { bash -c '. "$1" && eval "echo \"\$$2\""' _ "$RG" "$1"; }
assert_eq "$(rgvar RG_SENTINEL_METRIC)" "4294967295" "sentinel metric is the maximum, so the real route always wins"
# Slot rules live at 400+idx and 500+idx, idx 1..200 -> 401..700.
CP=$(rgvar RG_CATCH_PREF); LP=$(rgvar RG_SINK_LAN_PREF); SP=$(rgvar RG_SINK_PREF); ST=$(rgvar RG_SINK_TABLE)
assert_eq "$([[ $CP -gt 700 && $CP -lt $LP && $LP -lt $SP && $SP -lt 32766 ]] && echo yes || echo no)" yes \
    "rule order: slot rules (<=700) < catch < sink LAN exemption < sink < main (32766)"
assert_eq "$([[ ( $ST -gt 300 ) && ( $ST -lt 253 || $ST -gt 255 ) ]] && echo yes || echo no)" yes \
    "sink table sits outside every slot/staging/DNS table (101..300) and the reserved 253..255"
assert_eq "$(rgvar RG_LAN_NETS)" "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16" "sink LAN exemption = nftables \$RFC1918"
assert_eq "$(cnt_re '^define RFC1918 = \{ 10\.0\.0\.0/8, 172\.16\.0\.0/12, 192\.168\.0\.0/16 \}$' < "$CONF")" "1" "... and \$RFC1918 still says so"
assert_eq "$(code_only "$RG" | cnt_re 'ip route replace blackhole default metric')" "1" "sentinel is blackhole (no ICMP to clients)"
assert_eq "$(code_only "$RG" | cnt_re '(route|rule).*unreachable')" "0" "no unreachable route or rule anywhere"
assert_eq "$(bash -c '. "$1"; echo "$-"' _ "$RG" | cnt_fx e)" "0" \
    "sourcing routeguard.sh does not switch on set -e in the caller"

# ---------------------------------------------------------------------------
echo "layer 1 (routing): behaviour in a private network namespace"
if command -v ip >/dev/null 2>&1 && userns_ok; then
  cat > "$WORK/netns.sh" <<'EOS'
set -u
RG=$1; ENVF=$2
. "$RG"
ip link set lo up
sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2
ip link add up0 type dummy; ip addr add 192.0.2.1/24 dev up0; ip link set up0 up
ip route add default via 192.0.2.254 dev up0          # "main" -> the uplink
ip link add v0 type dummy; ip addr add 198.51.100.1/30 dev v0; ip link set v0 up
ip link add cl0 type dummy; ip addr add 172.16.1.5/24 dev cl0; ip link set cl0 up
rt() { ip route get 203.0.113.9 "$@" 2>&1 | head -1; }
# The root cause, as the kernel sees it: a rule over an EMPTY table does not
# stop the walk; the packet carries on to main and leaves by the uplink.
ip rule add fwmark 0x9 lookup 109 pref 509
echo "empty_table=$(rt mark 0x9)"
# Sentinel: the walk ends. A blackhole answers EINVAL to a local sender.
rg_sentinel_ensure 109
echo "sentinel_only=$(rt mark 0x9)"
ip route replace default via 198.51.100.2 dev v0 table 109
echo "with_route=$(rt mark 0x9)"
ip route del default via 198.51.100.2 table 109
echo "route_deleted=$(rt mark 0x9)"
# Catch rule: a mark with no rule at all.
rg_catch_ensure
echo "no_rule=$(rt mark 0x7)"
echo "unmarked=$(rt)"
# An older unreachable sentinel is converted in place, not duplicated.
ip route replace unreachable default metric 4294967295 table 111
rg_sentinel_ensure 111
echo "converted=$(ip route show table 111 | tr '\n' ';')"
# Ingress sink, interface derived from the gateway address (no PROTEUS_CLIENT_IFACE).
unset PROTEUS_CLIENT_IFACE; PROTEUS_CLIENT_GW_IP=172.16.1.5
echo "derived_iface=$(rg_client_iface)"
rg_sink_ensure; echo "sink_rc=$?"
echo "sink_ipv6_off=$(cat /proc/sys/net/ipv6/conf/proteus-null/disable_ipv6 2>/dev/null || echo absent)"
ip route replace default via 198.51.100.2 dev v0 table 109
echo "fwd_unmarked=$(ip route get 203.0.113.9 from 172.16.1.50 iif cl0 2>&1 | head -1)"
echo "fwd_lan=$(ip route get 10.1.2.3 from 172.16.1.50 iif cl0 2>&1 | head -1)"
echo "fwd_marked=$(ip route get 203.0.113.9 from 172.16.1.50 iif cl0 mark 0x9 2>&1 | head -1)"
echo "rule_wg_udm=$(ip rule show pref 32020 | grep -cE 'iif wg-udm( \[detached\])? lookup 900')"
# rp_filter: a tunnel reply to a client must still validate.
echo "reply=$(ip route get 172.16.1.50 from 203.0.113.9 iif v0 2>&1 | head -1)"
# ... which is why the sink is a route to a device: a blackhole there kills it.
ip route replace blackhole default table 900
echo "reply_if_blackhole_sink=$(ip route get 172.16.1.50 from 203.0.113.9 iif v0 2>&1 | head -1)"
ip route replace default dev proteus-null table 900
# Idempotence: a second pass adds nothing, and an identical rule is success.
rg_sentinel_ensure 109; rg_catch_ensure; rg_sink_ensure; rg_rule_ensure fwmark 0x9 lookup 109 pref 509; echo "ensure_rc=$?"
echo "catch_rules=$(ip rule show pref 32000 | wc -l)"
echo "sink_rules=$(ip rule show pref 32020 | wc -l)"
echo "lan_rules=$(ip rule show pref 32010 | wc -l)"
echo "sentinels=$(ip route show table 109 | grep -c blackhole)"
echo "rules_509=$(ip rule show pref 509 | wc -l)"
rg_rule_ensure fwmark notanumber lookup 109 2>/dev/null; echo "bad_rule_rc=$?"
# No client interface known at all: sink covers wg-udm, and says so.
( unset PROTEUS_CLIENT_GW_IP PROTEUS_CLIENT_IFACE; PROTEUS_ENV_FILE=/nonexistent rg_sink_ensure 2>/dev/null; echo "unknown_iface_rc=$?" )
# Standalone entry point, as the dispatcher unit or an operator calls it.
( unset PROTEUS_CLIENT_GW_IP; PROTEUS_ENV_FILE=$ENVF bash "$RG" 150; echo "cli_rc=$?" )
echo "cli_sentinel=$(ip route show table 150 | grep -c blackhole)"
echo "cli_bad_table_rc=$(PROTEUS_ENV_FILE=$ENVF bash "$RG" 1x 2>/dev/null; echo $?)"
EOS
  printf 'PROTEUS_CLIENT_IFACE=cl0\n' > "$WORK/proteus.env"
  OUT=$(unshare -rn bash "$WORK/netns.sh" "$RG" "$WORK/proteus.env" 2>&1 || true)
  get() { sed -n "s/^$1=//p" <<<"$OUT" | head -1; }
  assert_eq "$(get empty_table | cnt_fx 'dev up0')" "1" "ROOT CAUSE: rule over an empty table falls through to main (uplink)"
  assert_eq "$(get sentinel_only | cnt_re '[Ii]nvalid argument')" "1" "with the sentinel the same lookup ends in the blackhole"
  assert_eq "$(get with_route | cnt_fx 'dev v0')" "1" "the real tunnel route still wins over the sentinel"
  assert_eq "$(get route_deleted | cnt_re '[Ii]nvalid argument')" "1" "deleting the tunnel route leaves the slot blackholed, not open"
  assert_eq "$(get no_rule | cnt_re '[Ii]nvalid argument')" "1" "a mark with no slot rule hits the catch rule"
  assert_eq "$(get unmarked | cnt_fx 'dev up0')" "1" "unmarked local traffic is untouched (main)"
  assert_eq "$(get converted)" "blackhole default metric 4294967295 ;" "an old unreachable sentinel is replaced by one blackhole"
  assert_eq "$(get derived_iface)" "cl0" "client interface derived from PROTEUS_CLIENT_GW_IP"
  assert_eq "$(get sink_rc)" "0" "ingress sink installs"
  assert_eq "$(get sink_ipv6_off | sed 's/^absent$/1/')" "1" "the sink device has IPv6 off (no RS/MLD moving its TX counter)"
  assert_eq "$(get fwd_unmarked | cnt_fx 'dev proteus-null')" "1" "unmarked client traffic to a public address is sunk, not sent to main"
  assert_eq "$(get fwd_lan | cnt_fx 'dev up0')" "1" "client traffic to an RFC1918 address still routes via main (LAN pivot)"
  assert_eq "$(get fwd_marked | cnt_fx 'dev v0')" "1" "marked client traffic still takes its slot"
  assert_eq "$(get rule_wg_udm)" "1" "wg-udm is covered too (a rule by name, before the tunnel exists)"
  assert_eq "$(get reply | cnt_fx 'dev cl0')" "1" "a tunnel reply to a client passes rp_filter with the sink in place"
  assert_eq "$(get reply_if_blackhole_sink | cnt_fx 'dev cl0')" "0" "(a blackhole sink would have dropped it: why it is a dummy route)"
  assert_eq "$(get ensure_rc)" "0" "an identical existing rule counts as success"
  assert_eq "$(get catch_rules)" "1" "exactly one catch rule after repeated ensures"
  assert_eq "$(get sink_rules)" "2" "exactly two sink rules (client iface + wg-udm)"
  assert_eq "$(get lan_rules)" "6" "exactly six LAN exemptions (3 ranges x 2 interfaces)"
  assert_eq "$(get sentinels)" "1" "exactly one sentinel after repeated ensures"
  assert_eq "$(get rules_509)" "1" "no duplicate slot rule after an ensure"
  assert_eq "$(get bad_rule_rc)" "1" "a rule add that really fails (bad argument) is reported as failure"
  assert_eq "$(get unknown_iface_rc)" "1" "an unknown client interface is reported, not ignored"
  assert_eq "$(get cli_rc)" "0" "routeguard.sh TABLE works standalone (reads the env file itself)"
  assert_eq "$(get cli_sentinel)" "1" "... and installs the sentinel"
  assert_eq "$(get cli_bad_table_rc)" "2" "routeguard.sh rejects a non-numeric table (exit 2)"
else
  echo "  - SKIPPED netns behaviour: unprivileged user+net namespaces (unshare -rn) not available"
fi

# ---------------------------------------------------------------------------
echo "layer 1 (routing): routeguard.sh takes slot tables only"
# A sentinel is a blackhole default. In 255 (local) it cuts the box off; 0 and
# 254 are main, 253 the kernel's default table, 900 the sink's. vpnns-up.sh can
# create 101..300, and its range would reach 253..255 at idx 153..155.
tok() { bash -c '. "$1"; rg_table_ok "$2" && echo ok || echo refused' _ "$RG" "$1"; }
for t in 101 106 110 199 201 252 256 300; do
  assert_eq "$(tok "$t")" ok "rg_table_ok accepts $t"
done
for t in 0 100 253 254 255 301 900 0101 1x "" -5 1e3 99999999999999999999; do
  assert_eq "$(tok "$t")" refused "rg_table_ok refuses '$t'"
done
if command -v ip >/dev/null 2>&1 && userns_ok; then
  cat > "$WORK/tables.sh" <<'EOS'
set -u
RG=$1
# A client interface that checks out, so the table message is the only one.
export PROTEUS_ENV_FILE=/nonexistent PROTEUS_CLIENT_IFACE=cl0 PROTEUS_CLIENT_GW_IP=172.16.1.5
ip link set lo up
sysctl -q -w net.ipv4.ip_forward=1
ip link add up0 type dummy; ip addr add 192.0.2.1/24 dev up0; ip link set up0 up
ip route add default via 192.0.2.254 dev up0
ip link add cl0 type dummy; ip addr add 172.16.1.5/24 dev cl0; ip link set cl0 up
rcs=""
for t in 0 253 254 255 900 100 301 0101 99999999999999999999; do
  bash "$RG" "$t" 2>/dev/null; rcs+="$t:$? "
done
echo "bad_rcs=$rcs"
echo "bad_blackholes=$(ip route show table all | grep -c '^blackhole')"
# The catch rule and the sink depend on no table: a bad one does not stop them.
echo "bad_catch=$(ip route get 203.0.113.9 mark 0x7 2>&1 | head -1)"
echo "bad_fwd=$(ip route get 203.0.113.9 from 172.16.1.50 iif cl0 2>&1 | head -1)"
echo "bad_msg=$(bash "$RG" 255 2>&1 | tr '\n' ';')"
# The installer's shape: one RT_TABLE per state file, one of them bad. The
# others, before and after it, still get their sentinel.
bash "$RG" 150 255 151 2>/dev/null; echo "mixed_rc=$?"
# Both at once: a bad table AND something left unarmed (here the client
# interface cannot be found). 1 must win: 2 would read as "all else armed".
( unset PROTEUS_CLIENT_IFACE; PROTEUS_CLIENT_GW_IP=198.51.100.99 bash "$RG" 255 2>/dev/null; echo "both_rc=$?" )
echo "mixed_sentinels=$(for t in 150 151; do ip route show table "$t" | grep -c 'blackhole default metric 4294967295'; done | tr -d '\n')"
echo "blackholes=$(ip route show table all | grep -c '^blackhole')"
echo "uplink_route=$(ip route get 203.0.113.9 2>&1 | head -1)"
# The sourced function refuses too: vpnns-down.sh passes it the RT_TABLE of a
# state file, and vpnns-up.sh relies on it before its teardown.
. "$RG"
rg_sentinel_ensure 255 2>/dev/null; echo "src_rc=$?"
echo "src_msg=$(rg_sentinel_ensure 254 2>&1)"
echo "local_blackholes=$(ip route show table local | grep -c blackhole)"
echo "main_blackholes=$(ip route show table main | grep -c blackhole)"
for t in 101 252 256 300; do bash "$RG" "$t" 2>/dev/null; done
echo "edge_sentinels=$(for t in 101 252 256 300; do ip route show table "$t" | grep -c 'blackhole default metric 4294967295'; done | tr -d '\n')"
EOS
  OUT=$(unshare -rn bash "$WORK/tables.sh" "$RG" 2>&1 || true)
  get() { sed -n "s/^$1=//p" <<<"$OUT" | head -1; }
  assert_eq "$(get bad_rcs)" "0:2 253:2 254:2 255:2 900:2 100:2 301:2 0101:2 99999999999999999999:2 " \
    "routeguard.sh exits 2 for 0, the reserved 253..255, the sink table, out-of-range, leading-zero and overlong tables"
  assert_eq "$(get bad_blackholes)" "0" "... and puts a blackhole in none of them"
  assert_eq "$(get bad_catch | cnt_re '[Ii]nvalid argument')" "1" "... but still arms the catch rule"
  assert_eq "$(get bad_fwd | cnt_fx 'dev proteus-null')" "1" "... and the ingress sink"
  assert_eq "$(get bad_msg)" "routeguard: table 255 is not a slot table (101..300 except 253..255); left alone;" \
    "... and names the value it refused, and nothing else"
  assert_eq "$(get mixed_rc)" "2" "a bad table anywhere in the list still exits 2"
  assert_eq "$(get both_rc)" "1" "a bad table plus something unarmed exits 1, not 2"
  assert_eq "$(get mixed_sentinels)/$(get blackholes)" "11/2" \
    "... and the valid tables either side of it get their sentinel, the bad one nothing"
  assert_eq "$(get uplink_route | cnt_fx 'dev up0')" "1" "the box still routes (local and main untouched)"
  assert_eq "$(get src_rc)" "1" "sourced rg_sentinel_ensure refuses 255"
  assert_eq "$(get src_msg)" "routeguard: refusing table 254: not a slot table (101..300 except 253..255)" "... and says which table"
  assert_eq "$(get local_blackholes)/$(get main_blackholes)" "0/0" "... and local and main stay free of blackholes"
  assert_eq "$(get edge_sentinels)" "1111" "the edges 101, 252, 256 and 300 are accepted and get their sentinel"
else
  echo "  - SKIPPED table validation in a netns: unprivileged user+net namespaces (unshare -rn) not available"
fi

# ---------------------------------------------------------------------------
echo "layer 1 (routing): a PROTEUS_CLIENT_IFACE that is wrong is reported, and armed anyway"
if command -v ip >/dev/null 2>&1 && userns_ok; then
  cat > "$WORK/iface.sh" <<'EOS'
set -u
RG=$1; ENVF=$2
unset PROTEUS_CLIENT_IFACE PROTEUS_CLIENT_GW_IP RG_BEFORE_NETWORK
export PROTEUS_ENV_FILE=/nonexistent
. "$RG"
ip link set lo up
ip link add cl0 type dummy; ip addr add 172.16.1.5/24 dev cl0; ip link set cl0 up
ip link add other0 type dummy; ip link set other0 up
# <key> <iface> <gw>: "stdout|rc|stderr" of rg_client_iface
ci() {
  local out rc err
  out=$(PROTEUS_CLIENT_IFACE=$2 PROTEUS_CLIENT_GW_IP=$3 rg_client_iface 2>/dev/null); rc=$?
  err=$(PROTEUS_CLIENT_IFACE=$2 PROTEUS_CLIENT_GW_IP=$3 rg_client_iface 2>&1 >/dev/null)
  echo "$1=$out|$rc|$err"
}
ci right cl0 172.16.1.5
ci typo cl9 172.16.1.5
ci wrong other0 172.16.1.5
ci nowhere cl0 172.16.1.99
ci nogw_ok cl0 ""
ci nogw_typo cl9 ""
RG_BEFORE_NETWORK=1 ci early_typo cl9 172.16.1.5
RG_BEFORE_NETWORK=1 ci early_wrong other0 172.16.1.5
# An altname finds the device, yet it is the wrong name to configure: nft
# iifname never matches it, and a rule armed on it before the NIC existed
# never attaches.
if ip link property add dev cl0 altname clalt 2>/dev/null; then
  ci alt clalt 172.16.1.5
  ci alt_nogw clalt ""
fi
# ip prints a veth or VLAN as name@peer; that is still the primary name.
if ip link add vc0 type veth peer name vc1 2>/dev/null; then
  ci veth vc0 ""
fi
PROTEUS_CLIENT_IFACE=cl9 PROTEUS_CLIENT_GW_IP=172.16.1.5 rg_sink_ensure 2>/dev/null; echo "sink_typo_rc=$?"
echo "sink_typo_rule=$(ip rule show pref 32020 | grep -cE 'iif cl9 \[detached\] lookup 900')"
echo "sink_typo_lan=$(ip rule show pref 32010 | grep -c 'iif cl9')"
PROTEUS_CLIENT_IFACE=other0 PROTEUS_CLIENT_GW_IP=172.16.1.5 bash "$RG" 2>/dev/null; echo "cli_wrong_rc=$?"
echo "cli_wrong_rule=$(ip rule show pref 32020 | grep -c 'iif other0 lookup 900')"
RG_BEFORE_NETWORK=1 PROTEUS_CLIENT_IFACE=other0 PROTEUS_CLIENT_GW_IP=172.16.1.5 bash "$RG" 2>/dev/null; echo "cli_early_rc=$?"
PROTEUS_CLIENT_IFACE=cl0 PROTEUS_CLIENT_GW_IP=172.16.1.5 bash "$RG" 2>/dev/null; echo "cli_right_rc=$?"
# The name read from the env file is checked the same way.
PROTEUS_ENV_FILE=$ENVF bash "$RG" 2>/dev/null; echo "cli_envfile_rc=$?"
echo "cli_envfile_msg=$(PROTEUS_ENV_FILE=$ENVF bash "$RG" 2>&1 | head -1)"
EOS
  printf 'PROTEUS_CLIENT_IFACE=ens91\nPROTEUS_CLIENT_GW_IP=172.16.1.5\n' > "$WORK/typo.env"
  OUT=$(unshare -rn bash "$WORK/iface.sh" "$RG" "$WORK/typo.env" 2>&1 || true)
  assert_eq "$(get right)" "cl0|0|" "the right interface: printed, rc 0, no warning"
  assert_eq "$(get typo)" "cl9|2|routeguard: PROTEUS_CLIENT_IFACE=cl9: no such interface; ingress sink armed on that name anyway" \
    "a name no interface has: still printed, rc 2, warned"
  assert_eq "$(get wrong)" "other0|2|routeguard: PROTEUS_CLIENT_IFACE=other0 does not hold PROTEUS_CLIENT_GW_IP 172.16.1.5 (it is on cl0); ingress sink armed on other0 anyway" \
    "an interface without the gateway address: rc 2, and the warning names the one that has it"
  assert_eq "$(get nowhere | cut -d'|' -f2)" "2" "a gateway address no interface holds: rc 2"
  assert_eq "$(get nowhere | cnt_fx '(no interface holds it)')" "1" "... and says so"
  assert_eq "$(get nogw_ok)/$(get nogw_typo | cut -d'|' -f1,2)" "cl0|0|/cl9|2" "with no PROTEUS_CLIENT_GW_IP only existence is checked"
  if [[ -n "$(get alt)" ]]; then
    assert_eq "$(get alt)" "clalt|2|routeguard: PROTEUS_CLIENT_IFACE=clalt is an altname of cl0, which nftables iifname never matches and an ip rule armed before the NIC appeared never attaches to; set it to cl0. Ingress sink armed on clalt anyway" \
      "an altname: still printed, rc 2, and the warning names the primary name (not 'it is on cl0')"
    assert_eq "$(get alt_nogw | cut -d'|' -f1,2)" "clalt|2" "... with no PROTEUS_CLIENT_GW_IP as well"
  else
    echo "  - SKIPPED altname check: this ip or kernel cannot add an altname"
  fi
  if [[ -n "$(get veth)" ]]; then
    assert_eq "$(get veth)" "vc0|0|" "a name ip prints as name@peer is not taken for an altname"
  else
    echo "  - SKIPPED name@peer check: cannot create a veth here"
  fi
  assert_eq "$(get early_typo)/$(get early_wrong)" "cl9|0|/other0|0|" \
    "RG_BEFORE_NETWORK=1: no check at all (the NIC may not have its name or address yet)"
  assert_eq "$(get sink_typo_rc)" "1" "rg_sink_ensure reports the bad name (rc 1)"
  assert_eq "$(get sink_typo_rule)/$(get sink_typo_lan)" "1/3" "... and still arms the sink and the LAN exemptions on it, by name"
  assert_eq "$(get cli_wrong_rc)/$(get cli_wrong_rule)" "1/1" "routeguard.sh exits 1 for a wrong interface, with the rule armed"
  assert_eq "$(get cli_early_rc)" "0" "... and 0 before the network is up"
  assert_eq "$(get cli_right_rc)" "0" "... and 0 for the right one"
  assert_eq "$(get cli_envfile_rc)" "1" "a typo read from the env file is caught too"
  assert_eq "$(get cli_envfile_msg | cnt_fx 'PROTEUS_CLIENT_IFACE=ens91: no such interface')" "1" "... and named"
else
  echo "  - SKIPPED interface check in a netns: unprivileged user+net namespaces (unshare -rn) not available"
fi

echo "layer 1 (routing): who arms it"
for u in "$ROOT/etc/systemd/system/proteus-dispatcher.service" "$ROOT/install/templates/proteus-dispatcher.service.tmpl"; do
  assert_eq "$(cnt_re '^ExecStartPre=-\+/etc/proteus/bin/routeguard\.sh$' < "$u")" "1" "$(basename "$u"): routeguard runs before the dispatcher hands out marks"
  assert_eq "$(before "$u" 'ExecStartPre=-+/etc/proteus/bin/routeguard.sh' 'ExecStart=/etc/proteus/bin/dispatcher.py')" yes "$(basename "$u"): ... before ExecStart"
done
assert_eq "$(cnt_fx 'PROTEUS_CLIENT_IFACE=${CLIENT_IFACE}' < "$ROOT/install/templates/proteus.env.tmpl")" "1" "the installer renders PROTEUS_CLIENT_IFACE"
assert_eq "$(code_only "$APPLY" | cnt_re '/etc/proteus/bin/routeguard\.sh \$\(awk')" "1" "apply_network arms routeguard for every slot state file"

echo "layer 1 (routing): proteus-routeguard.service arms it before the network comes up"
# Without it, the first arming at boot is the first slot's vpnns-up.sh or the
# dispatcher's ExecStartPre, both after network-online. If nftables.service
# fails to load the ruleset, client traffic forwarded before then routes via
# main and out the uplink.
UNIT="$ROOT/etc/systemd/system/proteus-routeguard.service"
UNIT_T="$ROOT/install/templates/proteus-routeguard.service.tmpl"
unit_key() { grep -E "^$2=" "$1" 2>/dev/null | sed "s/^$2=//" | tr '\n' ';' || true; }
for u in "$UNIT" "$UNIT_T"; do
  n=$(basename "$u")
  assert_eq "$(unit_key "$u" DefaultDependencies)" "no;" "$n: DefaultDependencies=no (the defaults would order it after basic.target)"
  assert_eq "$(unit_key "$u" After)" "systemd-sysctl.service;" \
    "$n: After=systemd-sysctl.service only (never after nftables or the network: it must run when they fail)"
  assert_eq "$(unit_key "$u" Before)/$(unit_key "$u" Wants)" "network-pre.target;/network-pre.target;" \
    "$n: Before= and Wants=network-pre.target (the target is passive: without Wants the ordering may not apply)"
  assert_eq "$(unit_key "$u" Requires)$(unit_key "$u" BindsTo)$(unit_key "$u" Requisite)" "" "$n: no hard dependency that could stop it running"
  assert_eq "$(unit_key "$u" Type)/$(unit_key "$u" RemainAfterExit)" "oneshot;/yes;" "$n: a oneshot that stays active"
  assert_eq "$(unit_key "$u" EnvironmentFile)" "-/etc/proteus/proteus.env;" "$n: reads PROTEUS_CLIENT_IFACE from proteus.env (optional file)"
  assert_eq "$(unit_key "$u" Environment)" "RG_BEFORE_NETWORK=1;" "$n: tells routeguard.sh the network is not up yet"
  assert_eq "$(unit_key "$u" ExecStart)" "-/etc/proteus/bin/routeguard.sh;" "$n: routeguard.sh with no table argument, failure logged not fatal"
  assert_eq "$(unit_key "$u" WantedBy)" "sysinit.target;" "$n: WantedBy=sysinit.target (pulled in on every boot, nftables enabled or not)"
  # The unit names systemd-networkd among the managers it is ordered before,
  # which reads as networkd being covered. It is not, with networkd's defaults.
  assert_eq "$(cnt_fx 'ManageForeignRoutingPolicyRules=no' < "$u")/$(cnt_fx 'ManageForeignRoutes=no' < "$u")" "1/1" \
    "$n: says systemd-networkd deletes these rules unless told not to"
done
# The operator-facing account of the same, and of what covers a box without
# PROTEUS_CLIENT_IFACE after the early run (the first slot's vpnns-up.sh comes
# before the dispatcher).
GOT="$ROOT/gotchas.md"
assert_eq "$(cnt_fx 'set `ManageForeignRoutingPolicyRules=no` and `ManageForeignRoutes=no`' < "$GOT")" "1" \
  "gotchas.md: the networkd settings the routing layer needs"
assert_eq "$(cnt_fx '`wg-udm` alone until the first slot comes up or the dispatcher starts' < "$GOT")" "1" \
  "gotchas.md: the early run without PROTEUS_CLIENT_IFACE is followed by the first slot, then the dispatcher"
assert_eq "$(cnt_fx 'primary name, not one of its altnames' < "$GOT")" "1" "gotchas.md: PROTEUS_CLIENT_IFACE must be the primary name"
assert_eq "$(cnt_re '^[[:space:]]+systemctl enable --now proteus-routeguard\.service' < "$ROOT/install/install.sh")" "1" \
  "install.sh enables it"
# enable_services with systemctl stubbed: what it enables, in what order, and
# that a failed enable of this unit warns and carries on.
enable_calls() {  # <exit status for the routeguard enable>
  ( cd "$ROOT" && . install/install.sh && set +e
    SLOT_COUNT=1
    systemctl() { echo "systemctl $*"; [[ "$*" == *proteus-routeguard* ]] && return "$RG_ENABLE_RC"; return 0; }
    RG_ENABLE_RC=$1 enable_services 2>&1 ) || true
}
CALLS=$(enable_calls 0)
assert_eq "$(sed -n 2p <<<"$CALLS")" "systemctl enable --now proteus-routeguard.service" \
  "enable_services: enable --now proteus-routeguard.service right after daemon-reload, before any slot or the dispatcher"
CALLS=$(enable_calls 1)
assert_eq "$(cnt_fx 'WARN: proteus-routeguard.service not enabled' <<<"$CALLS")" "1" "a failed enable warns"
assert_eq "$(cnt_fx 'proteus-dispatcher.service' <<<"$CALLS")" "1" "... and enable_services carries on (the dispatcher is still enabled)"

if command -v ip >/dev/null 2>&1 && userns_ok; then
  # The unit's own command line and environment, with the script path moved to
  # this checkout. EnvironmentFile= is stood in for by the two variables it
  # would set: an installer-rendered name, and a gateway address that no
  # interface holds yet.
  exec_cmd=$(unit_key "$UNIT" ExecStart | sed -e 's/;$//' -e 's/^-//' -e "s#^/etc/proteus/bin/#$ROOT/etc/proteus/bin/#")
  unit_env=$(unit_key "$UNIT" Environment | sed 's/;$//')
  cat > "$WORK/early.sh" <<'EOS'
set -u
CMD=$1; UNIT_ENV=$2
ip link set lo up
sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2
ip link add up0 type dummy; ip addr add 192.0.2.1/24 dev up0; ip link set up0 up
ip route add default via 192.0.2.254 dev up0
fwd() { ip route get 203.0.113.9 from 172.16.1.50 iif "$1" 2>&1 | head -1; }
# The unit runs before udev has renamed the NIC and before any address.
# shellcheck disable=SC2086
err=$(env -i PATH="$PATH" PROTEUS_ENV_FILE=/nonexistent PROTEUS_CLIENT_IFACE=ens19 PROTEUS_CLIENT_GW_IP=172.16.1.5 $UNIT_ENV "$CMD" 2>&1); rc=$?
echo "unit_rc=$rc"
echo "unit_err=$err"
echo "detached=$(ip rule show pref 32020 | grep -cE 'iif ens19 \[detached\] lookup 900')"
echo "catch=$(ip route get 203.0.113.9 mark 0x7 2>&1 | head -1)"
# Now the network comes up: the NIC appears under its kernel name, udev renames
# it, ifupdown gives it its address.
ip link add eth1 type dummy
ip link set eth1 name ens19
ip addr add 172.16.1.5/24 dev ens19; ip link set ens19 up
echo "attached=$(ip rule show pref 32020 | grep -cE 'iif ens19 lookup 900')"
echo "fwd_client=$(fwd ens19)"
echo "fwd_lan=$(ip route get 10.1.2.3 from 172.16.1.50 iif ens19 2>&1 | head -1)"
# Control: an interface the sink does not name routes via main. That is what
# the client interface did before this unit, until the first slot came up.
ip link add ens20 type dummy; ip addr add 172.16.2.5/24 dev ens20; ip link set ens20 up
echo "fwd_uncovered=$(ip route get 203.0.113.9 from 172.16.2.50 iif ens20 2>&1 | head -1)"
EOS
  OUT=$(unshare -rn bash "$WORK/early.sh" "$exec_cmd" "$unit_env" 2>&1 || true)
  get() { sed -n "s/^$1=//p" <<<"$OUT" | head -1; }
  assert_eq "$(get unit_rc)/$(get unit_err)" "0/" \
    "the unit's command exits 0 and warns nothing before the NIC exists or has an address"
  assert_eq "$(get detached)" "1" "the client sink rule is stored by name, detached until the NIC appears"
  assert_eq "$(get catch | cnt_re '[Ii]nvalid argument')" "1" "the catch rule is armed"
  assert_eq "$(get attached)" "1" "once udev renames a NIC to that name the rule attaches"
  assert_eq "$(get fwd_client | cnt_fx 'dev proteus-null')" "1" "client traffic to a public address is sunk from then on, with no slot up and no ruleset"
  assert_eq "$(get fwd_lan | cnt_fx 'dev up0')" "1" "client traffic to an RFC1918 address still routes via main"
  assert_eq "$(get fwd_uncovered | cnt_fx 'dev up0')" "1" "(control: an interface the sink does not cover routes via main)"
else
  echo "  - SKIPPED early-boot behaviour: unprivileged user+net namespaces (unshare -rn) not available"
fi

echo "systemd-analyze verify: proteus-routeguard.service"
if [[ ! -f "$UNIT" ]]; then
  assert_eq missing present "proteus-routeguard.service exists"
elif command -v systemd-analyze >/dev/null 2>&1; then
  mkdir -p "$WORK/units"
  # ExecStart points at this checkout, so the check that the command exists
  # means something here.
  sed "s#/etc/proteus/bin/#$ROOT/etc/proteus/bin/#" "$UNIT" > "$WORK/units/proteus-routeguard.service"
  # Control first: a bad key must draw a complaint, or a clean result proves nothing.
  { cat "$WORK/units/proteus-routeguard.service"; echo "ProteusBogusKey=1"; } > "$WORK/units/zz-control.service"
  ctl=$(systemd-analyze verify --man=no "$WORK/units/zz-control.service" 2>&1 || true)
  if grep -q 'ProteusBogusKey' <<<"$ctl"; then
    out=$(systemd-analyze verify --man=no "$WORK/units/proteus-routeguard.service" 2>&1) && vrc=0 || vrc=$?
    assert_eq "$vrc" "0" "verify exits 0"
    assert_eq "$(grep -F 'proteus-routeguard' <<<"$out" || true)" "" "no warning about the unit"
  else
    echo "  - SKIPPED: this systemd-analyze did not flag a bogus key; a clean result would prove nothing"
  fi
else
  echo "  - SKIPPED: systemd-analyze not available"
fi

echo "installer: the nft auto-revert really reverts"
# Behaviour (failed listing, empty listing, the file restore) is in
# install/tests/apply_revert_test.sh; these pin the two lines that matter here.
assert_eq "$(code_only "$APPLY" | cnt_fx "{ echo 'flush ruleset'; nft list ruleset; } > \"\$snap_tmp\"")" "1" \
    "snapshot starts with flush ruleset (without it the revert only appends)"
assert_eq "$(code_only "$APPLY" | cnt_fx 'nft -f $NFT_SNAPSHOT && { $REPOPULATE_CMD; }')" "1" "revert repopulates like an apply"
for step in repopulate-wg-peers.sh proteus-proton-api-whitelist.service proteus-client-isolation.service proteus-trusted-egress.sh; do
  assert_eq "$(grep -E '^REPOPULATE_CMD=' "$APPLY" | cnt_fx "$step")" "1" "REPOPULATE_CMD includes $step"
done
assert_eq "$(code_only "$APPLY" | cnt_fx 'net.ipv4.fwmark_reflect=0')" "2" "fwmark_reflect pinned to 0 (runtime + 99-proteus.conf)"
if command -v nft >/dev/null 2>&1 && userns_ok; then
  # The mechanism: an un-prefixed snapshot reload is additive, a flush-prefixed one is not.
  cat > "$WORK/revert.sh" <<'EOS'
set -u
printf 'table inet filter {\n chain forward { type filter hook forward priority filter; policy drop; ct state established accept; }\n}\n' > "$1/old.nft"
nft -f "$1/old.nft"; nft list ruleset > "$1/snap-plain.nft"
{ echo 'flush ruleset'; nft list ruleset; } > "$1/snap-flush.nft"
printf 'flush ruleset\ntable inet filter {\n chain forward { type filter hook forward priority filter; policy drop; meta mark != 0x0 drop; ct state established accept; }\n chain postrouting_guard { type filter hook postrouting priority filter; policy accept; }\n}\n' > "$1/new.nft"
nft -f "$1/new.nft"; nft -f "$1/snap-plain.nft"; echo "plain_guard=$(nft list ruleset | grep -cE 'meta mark != 0x00000000 drop|chain postrouting_guard')"
nft -f "$1/new.nft"; nft -f "$1/snap-flush.nft"; echo "flush_guard=$(nft list ruleset | grep -cE 'meta mark != 0x00000000 drop|chain postrouting_guard')"
EOS
  OUT=$(unshare -rn bash "$WORK/revert.sh" "$WORK" 2>&1 || true)
  assert_eq "$(sed -n 's/^plain_guard=//p' <<<"$OUT")" "2" "(an un-prefixed snapshot leaves the new rule and chain in place)"
  assert_eq "$(sed -n 's/^flush_guard=//p' <<<"$OUT")" "0" "a flush-prefixed snapshot restores the old ruleset exactly"
fi

# ---------------------------------------------------------------------------
chain_of() {  # <file> <chain>: chain body without comments/blank lines
  awk -v c="$2" '$0 ~ "^    chain " c " \\{" {on=1} on {print} on && /^    \}/ {exit}' "$1" | { grep -vE '^[[:space:]]*(#|$)' || true; }
}
for f in "$CONF" "$TMPL"; do
  n=$(basename "$f")
  if [[ "$f" == "$TMPL" ]]; then CI='${CLIENT_IFACE}'; M6='${DNS_FWMARK_HEX}'; else CI=ens19; M6=0x6; fi
  echo "layer 2 (prerouting_ctsave) in $n"
  cts=$(chain_of "$f" prerouting_ctsave)
  assert_eq "$(cnt_fx 'type filter hook prerouting priority mangle + 1; policy accept;' <<<"$cts")" "1" "$n: runs right after prerouting_mangle (the NFQUEUE verdict re-enters here)"
  assert_eq "$(cnt_fx "iifname { \"$CI\", \"wg-udm\" } meta mark != 0x0 ct mark 0x0 ct mark set meta mark" <<<"$cts")" "1" "$n: saves the verdict mark into conntrack, dispatch origins only"
  assert_eq "$(before "$f" 'chain prerouting_mangle {' 'chain prerouting_ctsave {')" yes "$n: declared after prerouting_mangle"

  echo "layer 2 (chain forward) in $n"
  fwd=$(chain_of "$f" forward)
  num() { { grep -nF -- "$1" <<<"$fwd" || true; } | head -1 | cut -d: -f1; }
  g1=$(num 'comment "marked-off-tunnel"'); g2=$(num 'comment "ctmarked-off-tunnel"'); um=$(num 'comment "unmarked-client-egress"')
  est=$(num 'ct state established,related accept'); piv=$(num 'comment "client-to-private"')
  assert_eq "$([[ -n $g1 && -n $g2 && -n $um ]] && echo yes || echo no)" yes "$n: both mark guards and the unmarked-egress drop present"
  assert_eq "$([[ -n $g1 && -n $g2 && -n $um && $g1 -lt $est && $g2 -lt $est && $um -lt $est && $g1 -lt $piv && $g2 -lt $piv && $um -lt $piv ]] && echo yes || echo no)" yes \
      "$n: all three precede the ct-established accept and the pivot accept"
  assert_eq "$(cnt_re '^[[:space:]]*meta mark != 0x0 oifname != "v-proton-\*" counter name "marked_leak_fwd" drop comment "marked-off-tunnel"$' <<<"$fwd")" "1" \
      "$n: meta-mark guard drops anything not headed into v-proton-*"
  assert_eq "$(cnt_re '^[[:space:]]*ct direction original ct mark != 0x0 oifname != "v-proton-\*" counter name "marked_leak_fwd" drop comment "ctmarked-off-tunnel"$' <<<"$fwd")" "1" \
      "$n: ct-mark guard is ORIGINAL-direction only (replies to clients carry the ct mark)"
  assert_eq "$(cnt_re 'limit rate 5/second burst 20 packets log prefix "nft-marked-leak " level warn comment "(ct)?marked-off-tunnel-log"$' <<<"$fwd")" "2" \
      "$n: guard logging is rate-limited, in its own rules"
  assert_eq "$(grep -E 'drop comment "(ct)?marked-off-tunnel"' <<<"$fwd" | cnt_fx ' log ')" "0" "$n: the drops themselves never log"
  assert_eq "$(cnt_fx "iifname { \"$CI\", \"wg-udm\" } meta mark 0x0 ip daddr != \$RFC1918 counter drop comment \"unmarked-client-egress\"" <<<"$fwd")" "1" \
      "$n: unmarked client/trusted traffic to a public address is dropped"
  assert_eq "$(cnt_re 'meta mark != 0x0 oifname "v-proton-\*" counter accept comment "client-marked-to-vpn"' <<<"$fwd")" "1" \
      "$n: client-marked-to-vpn is oifname-scoped"
  assert_eq "$(cnt_re 'meta mark != 0x0 oifname "v-proton-\*" counter accept comment "trusted-marked-to-vpn"' <<<"$fwd")" "1" \
      "$n: trusted-marked-to-vpn is oifname-scoped"
  assert_eq "$(cnt_re 'meta mark != 0x0 counter accept' <<<"$fwd")" "0" "$n: no unscoped marked accept left"

  echo "layer 2 (chain postrouting_guard) in $n"
  post=$(chain_of "$f" postrouting_guard)
  assert_eq "$(cnt_fx 'type filter hook postrouting priority filter; policy accept;' <<<"$post")" "1" "$n: postrouting filter hook, policy accept"
  assert_eq "$(cnt_fx 'oifname "v-proton-*" accept' <<<"$post")" "1" "$n: rotating slots (and staging twins) allowed"
  assert_eq "$(cnt_re 'oifname "v-(dns-6|\$\{DNS_INSTANCE\})" accept' <<<"$post")" "1" "$n: the DNS tunnel veth allowed (unbound's own mark)"
  assert_eq "$(cnt_re '^[[:space:]]*meta mark != 0x0 counter name "marked_leak_post" drop' <<<"$post")" "1" "$n: any other marked egress dropped + counted"
  assert_eq "$(cnt_re '^[[:space:]]*ct direction original ct mark != 0x0 counter name "marked_leak_post" drop' <<<"$post")" "1" "$n: original-direction ct-marked egress dropped + counted"
  assert_eq "$(cnt_fx 'limit rate 5/second burst 20 packets log prefix "nft-marked-leak-post "' <<<"$post")" "2" "$n: post-guard logging rate-limited too"
  assert_eq "$(cnt_re '^    counter (marked_leak_fwd|marked_leak_post) \{' < "$f")" "2" "$n: both named counters declared"

  echo "unbound's route mark in $n"
  assert_eq "$(chain_of "$f" output_route | cnt_fx "meta skuid \"unbound\" ct direction original meta mark set $M6")" "1" \
      "$n: only what unbound originates is marked (its TCP answers to clients are not)"
done

echo "the guards' interface pattern matches how the scripts name the slot veths"
# The guards allow marked egress only via "v-proton-*". vpnns-up.sh names the
# main-side veth v-<instance>, and the rotating slots are proton-N (staging
# proton-N-s). Rename either side alone and every client packet is dropped.
assert_eq "$(code_only "$UP" | cnt_fx 'VETH_MAIN="v-${INSTANCE}"')" "1" "vpnns-up.sh names the main-side veth v-<instance>"
assert_eq "$(cnt_re '^ExecStart=/etc/proteus/bin/vpnns-up.sh %i ' < "$ROOT/etc/systemd/system/proteus-proton@.service")" "1" \
    "slot units pass their instance name (proton-N) straight through"
assert_eq "$(cnt_fx 'STAGE_NAME="${SLOT}-s"' < "$ROOT/etc/proteus/bin/rotate-slot.sh")" "1" "staging instances are proton-N-s"
assert_eq "$(cnt_re '^ExecStart=/etc/proteus/bin/vpnns-up.sh dns-6 ' < "$ROOT/etc/systemd/system/proteus-dns-tunnel.service")" "1" \
    "the DNS tunnel instance is dns-6, matching v-dns-6 in etc/nftables.conf"

# The box's own ICMP errors about the reply leg of a dispatched flow are
# RELATED/original with the flow's ct mark but meta mark 0: with the default
# icmp_errors_use_inbound_ifaddr=0 they route via main to the uplink, and
# routeguard.sh never sees them. Chain output must drop them before its
# established,related accept, and only them: an error routed into a slot veth
# (icmp_errors_use_inbound_ifaddr=1) reaches the remote and must pass.
ICMP_RULE='ct state related ct direction original ct mark != 0x0 meta l4proto icmp oifname != "v-proton-*" counter name "own_icmp_err_tunnelled" drop comment "own-icmp-error-for-tunnelled-flow"'
for f in "$CONF" "$TMPL"; do
  n=$(basename "$f")
  echo "chain output drops the box's own ICMP errors about a tunnelled flow ($n)"
  out=$(chain_of "$f" output)
  assert_eq "$(cnt_fx "$ICMP_RULE" <<<"$out")" "1" "$n: the drop is in chain output"
  a=$({ grep -nF -- 'own-icmp-error-for-tunnelled-flow' <<<"$out" || true; } | head -1 | cut -d: -f1)
  b=$({ grep -nF -- 'ct state established,related accept' <<<"$out" || true; } | head -1 | cut -d: -f1)
  assert_eq "$([[ -n "$a" && -n "$b" && "$a" -lt "$b" ]] && echo yes || echo no)" yes "$n: ahead of the established,related accept"
  assert_eq "$(cnt_re '^    counter own_icmp_err_tunnelled \{' < "$f")" "1" "$n: counter own_icmp_err_tunnelled declared"
done

echo "the live ruleset and the installer template carry the SAME guards"
# The installer renders the template and never copies etc/nftables.conf, so a
# guard in only one of them ships a fresh gateway without it.
norm() {   # <file> <chain>: chain body, comments/spacing removed, placeholders resolved
  chain_of "$1" "$2" \
    | sed -e 's/\${CLIENT_IFACE}/ens19/g' -e 's/\${MGMT_IFACE}/ens18/g' -e 's/v-\${DNS_INSTANCE}/v-dns-6/g' \
          -e 's/\${DNS_FWMARK_HEX}/0x6/g' -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//'
}
for c in prerouting_mangle prerouting_ctsave forward output output_route postrouting_guard; do
  assert_eq "$(diff <(norm "$CONF" "$c") <(norm "$TMPL" "$c") || true)" "" "chain $c: identical in both copies"
done
cnt() { grep -A2 -E '^    counter (marked_leak_|own_icmp_err_)' "$1" | { grep -vE '^[[:space:]]*#' || true; }; }
assert_eq "$(diff <(cnt "$CONF") <(cnt "$TMPL") || true)" "" "counter declarations identical in both copies"
assert_eq "$(grep -vE '^\s*#' "$TMPL" | cnt_re 'ens1[89]')" "0" "template: still no site NIC name in any rule"

echo "both rulesets still parse (unprivileged nft -c)"
nft_check() {  # <file> <label>
  local tmp err
  tmp=$(mktemp -p "$WORK"); err=$(mktemp -p "$WORK")
  # skuid names -> 0: the users need not exist here. The include is a bracket
  # glob, a no-op when nothing matches, but drop it anyway.
  sed -e 's/^flush ruleset$//' -e '/^include /d' -e 's/meta skuid "[^"]*"/meta skuid 0/g' "$1" > "$tmp"
  if unshare -rn nft -c -f "$tmp" 2>"$err"; then
    assert_eq ok ok "$2: nft -c accepts it"
  elif grep -qi 'cache initialization' "$err"; then
    echo "  - SKIPPED nft -c ($2): no netlink cache in this environment"
  else
    assert_eq "fail: $(tr '\n' ' ' <"$err" | cut -c1-200)" ok "$2: nft -c accepts it"
  fi
}
if command -v nft >/dev/null 2>&1 && userns_ok; then
  nft_check "$CONF" "etc/nftables.conf"
  # Rendered exactly as the installer does it, from the test fixture. render_all
  # refuses to run without envsubst (gettext-base), which is a gap in this
  # environment, not a broken template.
  if ! command -v envsubst >/dev/null 2>&1; then
    echo "  - SKIPPED nft -c (rendered installer template): envsubst not available in this environment"
  elif (cd "$ROOT" && . install/lib/common.sh && . install/lib/render.sh \
        && load_config install/tests/fixtures/good.conf && validate_config \
        && render_all "$WORK/stage") >/dev/null 2>&1 && [[ -s "$WORK/stage/nftables.conf" ]]; then
    nft_check "$WORK/stage/nftables.conf" "rendered installer template"
  else
    assert_eq "render failed" ok "installer template renders for nft -c"
  fi
else
  echo "  - SKIPPED nft -c: nft missing or unprivileged user+net namespaces not available"
fi

echo "a client that leaves mid-flow: the box's ICMP errors do not reach the uplink"
# Router netns = the box (ens18 uplink, ens19 client, v-proton-1 slot), with
# the real ruleset loaded. The client's UDP flow is pinned to slot 1; the client
# then vanishes while the remote keeps sending, so the box answers the remote
# with host-unreachable. U (the uplink peer) and S (the slot's far end, which
# stands in for the remote) count every ICMP they receive.
# Two controls: without the drop rule, postrouting_guard still stops them but
# marked_leak_post moves (the false alarm the rule exists to prevent); without
# the rule AND the postrouting ct-mark drop (the pre-fix state), they leak.
# A fourth run sets net.ipv4.icmp_errors_use_inbound_ifaddr=1, which sources
# the error from the slot's transit address: it routes into v-proton-1 and must
# reach the remote with neither counter moving.
# Exit 90 and 91 are the environment (no tmpfs /run, no nft in a peer
# namespace) and skip. 92 and 93 mean the ruleset under test did not load, and
# fail like any other broken run.
cat > "$WORK/icmp.sh" <<'EOS'
set -u
RULES=$1; INBOUND=${2:-0}
mount -t tmpfs tmpfs /run && mkdir -p /run/netns || exit 90
ip link set lo up
sysctl -qw net.ipv4.fwmark_reflect=0 net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2 net.ipv4.ip_forward=1 \
    net.ipv4.icmp_errors_use_inbound_ifaddr="$INBOUND"
for ns in C S U; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add ens19 type veth peer name c0 netns C
ip link add v-proton-1 type veth peer name s0 netns S
ip link add ens18 type veth peer name u0 netns U
ip addr add 172.16.1.5/24 dev ens19; ip link set ens19 up
ip addr add 172.31.1.1/30 dev v-proton-1; ip link set v-proton-1 up
ip addr add 10.0.0.2/24 dev ens18; ip link set ens18 up
ip route add default via 10.0.0.1
ip route add default via 172.31.1.2 dev v-proton-1 table 101
ip rule add from 172.31.1.1 lookup 101 pref 401
ip rule add fwmark 0x1 lookup 101 pref 501
sysctl -qw net.ipv4.neigh.ens19.mcast_solicit=1 net.ipv4.neigh.ens19.ucast_solicit=1 net.ipv4.neigh.ens19.retrans_time_ms=100
ip -n C addr add 172.16.1.10/24 dev c0; ip -n C link set c0 up; ip -n C route add default via 172.16.1.5
ip -n S addr add 172.31.1.2/30 dev s0; ip -n S link set s0 up
ip -n S addr add 203.0.113.10/32 dev lo; ip -n S route add 172.16.1.0/24 via 172.31.1.1
ip -n U addr add 10.0.0.1/24 dev u0; ip -n U link set u0 up
for ns in U S; do
  ip netns exec $ns nft -f - <<'EON' || exit 91
table ip t { chain c { type filter hook prerouting priority 0; policy accept; ip protocol icmp counter comment "icmp-in"; }; }
EON
done
nft -f "$RULES" || exit 92
nft add element inet filter source_pin '{ 172.16.1.10 : 0x1 }' || exit 93
ip netns exec S python3 - <<'PY' &
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("203.0.113.10", 5002)); s.settimeout(5)
try:
    _, a = s.recvfrom(100); time.sleep(0.5)
    for i in range(6): s.sendto(b"push", a); time.sleep(0.2)
except OSError:
    pass
PY
sleep 0.3
ip netns exec C python3 -c 'import socket; c=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.bind(("172.16.1.10", 4005)); c.sendto(b"hi", ("203.0.113.10", 5002))'
sleep 0.2
ip -n C addr del 172.16.1.10/24 dev c0; ip neigh flush dev ens19
wait; sleep 1
echo "uplink_icmp=$(ip netns exec U nft list chain ip t c | sed -n 's/.*counter packets \([0-9]*\).*/\1/p')"
echo "slot_icmp=$(ip netns exec S nft list chain ip t c | sed -n 's/.*counter packets \([0-9]*\).*/\1/p')"
echo "dropped=$(nft list counter inet filter own_icmp_err_tunnelled 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p')"
echo "leak_post=$(nft list counter inet filter marked_leak_post 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p')"
EOS
if command -v nft >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
   && unshare -rnm --propagation private true 2>/dev/null; then
  sanitize() { sed -e 's/^flush ruleset$//' -e '/^include /d' -e 's/meta skuid "[^"]*"/meta skuid 4242/g' "$1"; }
  sanitize "$CONF" > "$WORK/icmp-fixed.nft"
  grep -vF 'own-icmp-error-for-tunnelled-flow"' "$WORK/icmp-fixed.nft" > "$WORK/icmp-norule.nft"
  grep -vF 'comment "ctmarked-egress-guard"' "$WORK/icmp-norule.nft" > "$WORK/icmp-prefix.nft"
  # Every run ends with its exit status as rc=N, so a run that failed half way
  # is told apart from one that ran and counted nothing.
  run_icmp() { local rc=0; unshare -rnm --propagation private bash "$WORK/icmp.sh" "$@" 2>&1 || rc=$?; echo "rc=$rc"; }
  FIXED=$(run_icmp "$WORK/icmp-fixed.nft"); NORULE=$(run_icmp "$WORK/icmp-norule.nft")
  PREFIX=$(run_icmp "$WORK/icmp-prefix.nft"); INBOUND=$(run_icmp "$WORK/icmp-fixed.nft" 1)
  val() { sed -n "s/^$1=//p" <<<"$2"; }
  env_failed() {  # the environment, not the ruleset: see the exit codes above
    local rc; rc=$(val rc "$1")
    [[ "$rc" == 90 || "$rc" == 91 ]] || grep -q '^unshare: ' <<<"$1"
  }
  ran() {         # "ok", or the exit status and the start of the output
    [[ "$(val rc "$1")" == 0 ]] && echo ok || echo "rc=$(val rc "$1"): $(grep -v '^rc=' <<<"$1" | tr '\n' ' ' | cut -c1-200)"
  }
  if env_failed "$FIXED" || env_failed "$NORULE" || env_failed "$PREFIX" || env_failed "$INBOUND"; then
    echo "  - SKIPPED icmp scenario: namespace setup failed here ($(tr '\n' ' ' <<<"$FIXED$NORULE$PREFIX$INBOUND" | cut -c1-160))"
  else
    for run in FIXED NORULE PREFIX INBOUND; do
      assert_eq "$(ran "${!run}")" ok "icmp scenario, $run run: the ruleset loaded and the run finished"
    done
    f_up=$(val uplink_icmp "$FIXED"); f_dr=$(val dropped "$FIXED"); f_lp=$(val leak_post "$FIXED")
    n_up=$(val uplink_icmp "$NORULE"); n_lp=$(val leak_post "$NORULE"); p_up=$(val uplink_icmp "$PREFIX")
    i_up=$(val uplink_icmp "$INBOUND"); i_sl=$(val slot_icmp "$INBOUND"); i_dr=$(val dropped "$INBOUND"); i_lp=$(val leak_post "$INBOUND")
    assert_eq "$([[ "$p_up" -gt 0 ]] && echo leaks || echo "no leak ($p_up)")" leaks \
      "pre-fix control (no drop rule, no postrouting ct-mark drop): host-unreachable reaches the uplink ($p_up)"
    assert_eq "$n_up/$([[ "${n_lp:-0}" -gt 0 ]] && echo moved || echo "still ${n_lp:-none}")" "0/moved" \
      "control without the drop rule: postrouting_guard stops them, but marked_leak_post moves ($n_lp)"
    assert_eq "$f_up" "0" "with the rule: no ICMP reaches the uplink"
    assert_eq "${f_lp:-none}" "0" "with the rule: marked_leak_post stays 0"
    assert_eq "$([[ "${f_dr:-0}" -gt 0 ]] && echo counted || echo "not exercised (${f_dr:-none})")" counted \
      "with the rule: own_icmp_err_tunnelled counted them ($f_dr), so the path was exercised"
    assert_eq "$([[ "${i_sl:-0}" -gt 0 ]] && echo reached || echo "not reached (${i_sl:-none})")" reached \
      "icmp_errors_use_inbound_ifaddr=1: the error goes into the slot veth and reaches the remote ($i_sl)"
    assert_eq "${i_up:-none}/${i_dr:-none}/${i_lp:-none}" "0/0/0" \
      "... and nothing reaches the uplink, and neither own_icmp_err_tunnelled nor marked_leak_post moves"
  fi
else
  echo "  - SKIPPED icmp scenario: nft, python3 or unprivileged user+net+mount namespaces missing"
fi
summary
