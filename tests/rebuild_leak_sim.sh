#!/usr/bin/env bash
# tests/rebuild_leak_sim.sh: an unprivileged network-namespace reproduction of
# the slot-rebuild fall-through leak, and of the paths the fix must keep working.
#
# THE LEAK. A slot's marked traffic is policy-routed by `ip rule fwmark N lookup
# 100+N` into a table holding one route through the slot veth. vpnns-up.sh used
# to delete that rule and flush that table before rebuilding, and vpnns-down.sh
# deleted both. In between, the rule walk fell through to `main`, whose default
# route is the uplink, and the forward chain accepted the packet on its mark
# (or as ct-established) with no check on the output interface. So client
# packets left the uplink un-tunnelled, with their client-VLAN source address.
# This happened on every promotion and restart, for the whole of a failed
# rebuild, and for as long as a slot stayed stopped. Three more paths ended the
# same way because they left a dispatched flow with no mark at all: a trusted
# range removed under an established flow, a dispatcher verdict whose map entry
# never landed (the verdict set only the packet mark), and no ruleset loaded.
#
# WHAT RUNS HERE IS THE REAL THING. It loads the real etc/nftables.conf (the
# boot-seed include included) and runs the real vpnns-up.sh / vpnns-down.sh /
# trusted.py, at their real /etc paths and exactly as the systemd units invoke
# them. An overlay mount inside a private mount namespace provides those
# paths, and real WireGuard tunnels run to a stand-in VPN server. Nothing is
# mocked. The only thing that is not the production box is the network:
#
#   client ns (172.16.1.50 pinned to proton-1, .51 pinned to proton-2,
#              .52 unpinned)
#     |  ens19 172.16.1.5
#   PROTEUS-MAIN (this unshared netns): nftables, policy routing, slot netns
#     |  ens18 10.0.0.2 (default via 10.0.0.1)          wg-udm 10.99.99.1
#     |                                                   | trusted ns 10.99.99.2
#   upstream ns: the router plus "the internet"
#     lan0 10.0.0.1       <- LEAK RECORDER: counts every packet from Proteus
#                            whose source is a client/trusted/transit address
#                            (never legitimate on the uplink, except the LAN
#                            pivot to an RFC1918 destination, counted apart)
#     wgsrv: WireGuard server for every slot, 10.2.0.1 (the in-tunnel resolver)
#     203.0.113.10 public echo server (has an @vpn_dispatch entry),
#     203.0.113.20 public echo server (has none), 192.0.2.x WireGuard endpoints
#
# Scenarios: steady state, promotion rebuild, restart (down+up), a FAILED
# rebuild (vpnns-up aborts under set -e after teardown), a stopped slot, a
# trusted range removed under an established flow, a DNS-slot rotation, a
# staging slot, a dispatcher verdict with no map entry (S8, emulated: no
# dispatcher runs here) and a ruleset flush-and-reload (S9, what `systemctl
# restart nftables` does). Each one drives ESTABLISHED flows plus a stream of
# NEW flows, and counts what reaches the uplink.
# Legitimate paths checked: client egress per slot, trusted egress, client DNS
# redirect to the local resolver over UDP and TCP (the TCP answer comes from a
# socket owned by uid unbound, as unbound's own are), unbound-through-dns-6,
# management SSH, the client->LAN pivot (open vs isolated), and staging egress.
#
# Usage (one command, no root):
#   tests/rebuild_leak_sim.sh                  # this checkout
#   tests/rebuild_leak_sim.sh --ref <gitref>   # e.g. the pre-fix commit: shows the leak
#   tests/rebuild_leak_sim.sh --code <dir>     # another tree
# Layer isolation (each defence on its own):
#   --bin-from <ref|dir>   take etc/proteus/bin from here (routing layer)
#   --nft-from <ref|dir>   take etc/nftables.conf from here (firewall layer)
#   --fwd-bypass           after loading, insert `meta mark != 0 accept` at the
#                          top of chain forward: models a broken forward chain,
#                          so only chain postrouting_guard stands
#   --matrix <baseline>    run fixed, baseline, routing-only, firewall-only and
#                          postrouting-only, and print a summary table that
#                          compares each row with the failures it should have
#                          (exit 1 on any difference)
#   --template             load the INSTALLER TEMPLATE (rendered the way
#                          install/lib/render.sh does it) instead of
#                          etc/nftables.conf, so a fresh install is proven too
#   --keep                 keep the scratch dir
# Exit: 0 every check PASSed, 1 some check FAILed, 77 environment cannot run it.
#
# Needs: util-linux unshare with --map-users plus a subuid range for this user
# (newuidmap), overlayfs in user namespaces, the wireguard module, and ip, nft,
# wg, python3, setpriv. Never uses sudo; touches nothing outside its own
# namespaces and a scratch dir under $TMPDIR.

set -uo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SELF=$(readlink -f "$0")
ROOT=$(cd "$(dirname "$SELF")/.." && pwd)

# --------------------------------------------------------------------------
# inner half: runs as root of a private user+net+mount namespace
# --------------------------------------------------------------------------
if [[ "${1:-}" == "--inner" ]]; then
SIM=$2; FWD_BYPASS=$3
OUT=$SIM/out
TOOL=$SIM/simtool.py
NPASS=0; NFAIL=0
pass() { NPASS=$((NPASS+1)); printf 'PASS  %s\n' "$*" | tee -a "$SIM/results.txt"; }
fail() { NFAIL=$((NFAIL+1)); printf 'FAIL  %s\n' "$*" | tee -a "$SIM/results.txt"; }
info() { printf 'INFO  %s\n' "$*" | tee -a "$SIM/results.txt"; }
check() { local ok=$1; shift; if [[ "$ok" == 1 ]]; then pass "$@"; else fail "$@"; fi; }
die() { echo "SIM SETUP ERROR: $*" >&2; exit 2; }

BG=()
cleanup_inner() { local p; for p in "${BG[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup_inner EXIT

mount --make-rprivate / || die "make-rprivate"
mount -t overlay overlay \
    -o "lowerdir=$SIM/etc-top:/etc,upperdir=$SIM/etc-upper,workdir=$SIM/etc-work,userxattr" /etc \
    || die "overlay on /etc (needs overlayfs in user namespaces)"
mount -t tmpfs tmpfs /run || die "tmpfs /run"
# `ip netns exec` bind-mounts /etc/netns/<ns>/resolv.conf over /etc/resolv.conf;
# where that is a symlink into /run (systemd-resolved), give it a target.
_rc=$(readlink -m /etc/resolv.conf 2>/dev/null || true)
if [[ -n "$_rc" && ! -e "$_rc" && "$_rc" == /run/* ]]; then mkdir -p "$(dirname "$_rc")"; : > "$_rc"; fi

UNBOUND_UID=$(getent passwd unbound | cut -d: -f3)
UNBOUND_GID=$(getent passwd unbound | cut -d: -f4)

# ---- PROTEUS-MAIN (this netns) -------------------------------------------
ip link set lo up
sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2 \
    || die "sysctl in main"

for ns in client upstream trusted; do ip netns add "$ns" || die "netns add $ns"; ip -n "$ns" link set lo up; done

ip link add ens19 type veth peer name eth0 netns client
ip addr add 172.16.1.5/24 dev ens19; ip link set ens19 up
ip -n client addr add 172.16.1.50/24 dev eth0
ip -n client addr add 172.16.1.51/24 dev eth0
ip -n client addr add 172.16.1.52/24 dev eth0
ip -n client link set eth0 up
ip -n client route add default via 172.16.1.5

ip link add ens18 type veth peer name lan0 netns upstream
ip addr add 10.0.0.2/24 dev ens18; ip link set ens18 up
ip route add default via 10.0.0.1 dev ens18
ip -n upstream addr add 10.0.0.1/24 dev lan0; ip -n upstream link set lan0 up

ip link add wg-udm type veth peer name tun0 netns trusted
ip addr add 10.99.99.1/30 dev wg-udm; ip link set wg-udm up
ip -n trusted addr add 10.99.99.2/30 dev tun0; ip -n trusted link set tun0 up
ip -n trusted route add default via 10.99.99.1

# ---- upstream: router, recorder, WireGuard server, public echo -----------
ip -n upstream link add inet0 type dummy
for a in 192.0.2.11 192.0.2.12 192.0.2.16 192.0.2.21 192.0.2.111 203.0.113.10 203.0.113.20; do
    ip -n upstream addr add "$a/32" dev inet0
done
ip -n upstream link set inet0 up
ip -n upstream route add 172.16.1.0/24 via 10.0.0.2    # LAN-pivot replies
ip -n upstream link add wgsrv type wireguard
ip -n upstream addr add 10.2.0.1/24 dev wgsrv
ip netns exec upstream wg setconf wgsrv "$SIM/wgsrv.conf" || die "wg server"
ip -n upstream link set wgsrv up
ip netns exec upstream nft -f - <<'EOF' || die "recorder ruleset"
table ip rec {
    counter leak_client  {}
    counter leak_trusted {}
    counter leak_dns     {}
    counter leak_other   {}
    counter pivot_in     {}
    chain pre {
        type filter hook prerouting priority -300; policy accept;
        iifname != "lan0" return
        ip saddr 10.0.0.2 ip daddr != 10.2.0.1 return
        ip saddr 172.16.1.0/24 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } ip daddr != 10.2.0.1 counter name pivot_in return
        ip saddr 172.16.1.0/24 counter name leak_client drop
        ip saddr 10.99.99.0/30 counter name leak_trusted drop
        ip saddr 172.31.0.0/16 counter name leak_dns drop
        ip daddr 10.2.0.1 counter name leak_dns drop
        counter name leak_other drop
    }
}
EOF

# ---- the REAL firewall -----------------------------------------------------
fwd_bypass() {
    # Both mark kinds, first in the chain: models a forward chain that lets
    # every marked packet through, whatever the guard rules below it say.
    nft insert rule inet filter forward ct direction original ct mark != 0x0 accept comment '"sim-fwd-bypass"' \
        && nft insert rule inet filter forward meta mark != 0x0 accept comment '"sim-fwd-bypass"'
}
# What proteus-trusted-egress.sh would reconcile: operator range + tunnel subnet.
TRUSTED_ELEMS="192.168.77.0/24, 10.99.99.0/30"
seed_sets() {
    nft add element inet filter trusted_src "{ $TRUSTED_ELEMS }"
    # What the dispatcher would have recorded: two pinned client hosts, and the
    # destination entry that trusted (per-destination) dispatch uses.
    nft add element inet filter source_pin '{ 172.16.1.50 timeout 1h : 0x1, 172.16.1.51 timeout 1h : 0x2 }'
    nft add element inet filter vpn_dispatch '{ 203.0.113.10 timeout 1h : 0x1 }'
}
nft -f "$SIM/nftables.conf" || die "loading the ruleset under test"
if [[ "$FWD_BYPASS" == 1 ]]; then
    fwd_bypass || die "fwd bypass"
    info "forward chain bypassed for marked traffic (--fwd-bypass): only postrouting_guard stands"
fi
seed_sets

HAVE_GUARD=0
nft list counter inet filter marked_leak_fwd >/dev/null 2>&1 && HAVE_GUARD=1

# ---- servers -------------------------------------------------------------
# One socket per address: a wildcard-bound echo would answer from whatever
# address the route picks, the reply would miss the tunnel's NAT entry, and
# every "no reply" would be the harness, not the gateway.
ip netns exec upstream python3 "$TOOL" udp-echo --bind 203.0.113.10 --port 5007 & BG+=($!)
ip netns exec upstream python3 "$TOOL" udp-echo --bind 203.0.113.20 --port 5007 & BG+=($!)
ip netns exec upstream python3 "$TOOL" udp-echo --bind 10.0.0.1 --port 5007 & BG+=($!)
ip netns exec upstream python3 "$TOOL" udp-echo --bind 10.2.0.1 --port 53 & BG+=($!)
python3 "$TOOL" udp-echo --bind 172.16.1.5 --port 53 & BG+=($!)     # local resolver, root-owned like unbound's listeners
python3 "$TOOL" tcp-listen --bind 10.0.0.2 --port 22 & BG+=($!)     # stand-in sshd
# Local resolver over TCP, the way unbound does it: bind and listen as root,
# then accept() and answer as uid unbound, and hold the connection open.
python3 "$TOOL" tcp-dns-server --bind 172.16.1.5 --port 53 --uid "$UNBOUND_UID" --gid "$UNBOUND_GID" & BG+=($!)
sleep 0.3

VUP=/etc/proteus/bin/vpnns-up.sh
VDOWN=/etc/proteus/bin/vpnns-down.sh
AUTO=/etc/proteus/wg/proton/auto
run_script() {   # the way systemd runs them: clean environment
    env -i PATH="$PATH" "$@" >>"$SIM/scripts.log" 2>&1
}

run_script "$VUP" proton-1 "$AUTO/proton-1.conf" || die "vpnns-up proton-1 (see $SIM/scripts.log)"
run_script "$VUP" proton-2 "$AUTO/proton-2.conf" || die "vpnns-up proton-2"
run_script "$VUP" dns-6    "$AUTO/dns-6.conf"    || die "vpnns-up dns-6"

# Debugging aid: PROTEUS_SIM_HOOK=<file> is sourced here, inside the fully
# built topology, INSTEAD of the scenarios (e.g. to poke at it by hand).
if [[ -n "${PROTEUS_SIM_HOOK:-}" ]]; then
    # shellcheck disable=SC1090
    . "$PROTEUS_SIM_HOOK"; exit $?
fi

# ---- helpers ---------------------------------------------------------------
ctr() { ip netns exec upstream nft list counter ip rec "$1" | awk '/packets/{print $2; exit}'; }
gctr() {
    if [[ $HAVE_GUARD == 1 ]]; then nft list counter inet filter "$1" | awk '/packets/{print $2; exit}'; else echo 0; fi
}
snap() {   # prints all counters, space separated
    echo "$(ctr leak_client) $(ctr leak_trusted) $(ctr leak_dns) $(ctr leak_other) $(gctr marked_leak_fwd) $(gctr marked_leak_post)"
}
declare -A D
delta() {  # <before> <after>: fills D[client] D[trusted] D[dns] D[other] D[fwd] D[post]
    local -a b a
    read -r -a b <<<"$1"; read -r -a a <<<"$2"
    D[client]=$(( a[0]-b[0] )); D[trusted]=$(( a[1]-b[1] )); D[dns]=$(( a[2]-b[2] ))
    D[other]=$(( a[3]-b[3] )); D[fwd]=$(( a[4]-b[4] )); D[post]=$(( a[5]-b[5] ))
    D[leak]=$(( D[client]+D[trusted]+D[dns]+D[other] ))
}
guards() {
    if [[ $HAVE_GUARD != 1 ]]; then echo "no guard counters in this ruleset"
    elif (( D[fwd] < 0 || D[post] < 0 )); then echo "guard counters were reset by a reload during the scenario"
    else echo "fwd-guard dropped ${D[fwd]}, post-guard dropped ${D[post]}"; fi
}
icmp_unreach() {   # ICMP destination-unreachables this netns has sent
    awk '/^Icmp:/ { if (!h) { for (i = 1; i <= NF; i++) if ($i == "OutDestUnreachs") c = i; h = 1 } else print $c }' /proc/net/snmp
}
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2], 0))' "$1" "$2"; }

gen() {   # <tag> <ns> <src> <dur> [est-sport] [dst]: background traffic generator
    ip netns exec "$2" python3 "$TOOL" gen --src "$3" --dst "${6:-203.0.113.10}" --port 5007 \
        --duration "$4" --est-sport "${5:-40001}" --out "$OUT/$1.json" &
    GEN_PIDS+=($!)
}
gen_wait() { local p; for p in "${GEN_PIDS[@]}"; do wait "$p"; done; GEN_PIDS=(); }
GEN_PIDS=()

probe() {  # <ns> <src> <sport>: does a short burst get echoes? prints 1/0
    ip netns exec "$1" python3 "$TOOL" gen --src "$2" --dst 203.0.113.10 --port 5007 \
        --duration 0.4 --est-sport "$3" --out "$OUT/probe.json" >/dev/null 2>&1
    [[ $(jget "$OUT/probe.json" recv_est) -gt 0 && $(jget "$OUT/probe.json" recv_new) -gt 0 ]] && echo 1 || echo 0
}
summ() { echo "est $(jget "$1" recv_est)/$(jget "$1" sent_est) new $(jget "$1" recv_new)/$(jget "$1" sent_new)"; }

# A leak scenario: traffic from both pinned clients and the trusted host, a
# lead-in so the pinned flow is ESTABLISHED, the action, then the tail.
scenario() {   # <id> <label> <duration> <lead> <action...>
    local id=$1 label=$2 dur=$3 lead=$4; shift 4
    local before after rc
    before=$(snap)
    gen "$id-a" client 172.16.1.50 "$dur" 40001
    gen "$id-b" client 172.16.1.51 "$dur" 40002
    gen "$id-t" trusted 10.99.99.2 "$dur" 40003
    sleep "$lead"
    "$@"; rc=$?
    gen_wait
    after=$(snap); delta "$before" "$after"
    SC_RC=$rc
    check "$([[ ${D[leak]} -eq 0 ]] && echo 1 || echo 0)" \
        "$id $label: ${D[leak]} packets leaked to the uplink (client-src ${D[client]}, trusted-src ${D[trusted]}, transit/dns ${D[dns]}, other ${D[other]}); $(guards); pinned client A $(summ "$OUT/$id-a.json")"
}

# ---- L: legitimate paths at steady state -----------------------------------
legit_paths() {   # <phase>
    local ph=$1 r
    r=$(probe client 172.16.1.50 40011); check "$r" "L1[$ph] client A pinned to proton-1 reaches the internet through the tunnel"
    r=$(probe client 172.16.1.51 40012); check "$r" "L2[$ph] client B pinned to proton-2 reaches the internet through the tunnel"
    r=$(probe trusted 10.99.99.2 40013); check "$r" "L3[$ph] trusted host (via wg-udm) reaches the internet through the tunnel"
    r=$(ip netns exec client python3 "$TOOL" udp-check --src 172.16.1.50 --dst 203.0.113.53 --port 53)
    check "$r" "L4[$ph] client DNS to an arbitrary resolver is redirected to the local resolver and answered"
    r=$(ip netns exec client python3 "$TOOL" tcp-query --src 172.16.1.50 --dst 203.0.113.53 --port 53)
    check "$r" "L8[$ph] client DNS over TCP is redirected and the answer (from a uid-unbound socket) arrives"
    r=$(setpriv --reuid="$UNBOUND_UID" --regid="$UNBOUND_GID" --clear-groups \
            python3 "$TOOL" udp-check --src 172.31.6.1 --dst 10.2.0.1 --port 53)
    check "$r" "L5[$ph] unbound (uid unbound, from the dns-6 transit IP) reaches the in-tunnel resolver via dns-6"
    r=$(ip netns exec upstream python3 "$TOOL" tcp-check --src 10.0.0.1 --dst 10.0.0.2 --port 22)
    check "$r" "L6[$ph] management SSH from the mgmt LAN to the gateway"
    r=$(ip netns exec client python3 "$TOOL" udp-check --src 172.16.1.50 --dst 10.0.0.1 --port 5007)
    check "$r" "L7[$ph] client -> LAN pivot works while @client_pivot is open"
    nft flush set inet filter client_pivot
    r=$(ip netns exec client python3 "$TOOL" udp-check --src 172.16.1.50 --dst 10.0.0.1 --port 5007)
    check "$([[ $r == 0 ]] && echo 1 || echo 0)" "L7[$ph] client -> LAN pivot is dropped once isolated (@client_pivot empty)"
    nft add element inet filter client_pivot '{ 172.16.1.0/24 }'
}

echo "== rebuild_leak_sim: ruleset=$(cat "$SIM/label-nft")  scripts=$(cat "$SIM/label-bin")"
legit_paths steady

# S0: nothing happens; baseline must be clean or every later number is noise.
scenario S0 "steady state, no rebuild" 1.0 0.3 true

# S1: promotion, exactly as rotate-slot.sh:425 does it (vpnns-up over the live
# slot, onto a different server). Client B on proton-2 must not notice.
u0=$(icmp_unreach)
scenario S1 "promotion rebuild (vpnns-up over the live slot)" 1.6 0.4 \
    run_script "$VUP" proton-1 "$AUTO/proton-1-next.conf"
u1=$(icmp_unreach)
check "$([[ $((u1-u0)) -eq 0 ]] && echo 1 || echo 0)" \
    "S1 no ICMP unreachable sent to clients during the promotion ($((u1-u0)) sent; a blackhole sentinel drops silently, so client connects retry instead of failing)"
check "$([[ $SC_RC -eq 0 ]] && echo 1 || echo 0)" "S1 promotion vpnns-up exited 0"
b_ok=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(1 if d["sent_est"] and d["recv_est"]/d["sent_est"]>=0.8 else 0)' "$OUT/S1-b.json")
check "$b_ok" "S1 client B on proton-2 unaffected by proton-1's rebuild ($(summ "$OUT/S1-b.json"))"
check "$(probe client 172.16.1.50 40021)" "S1 client A flows again through proton-1 after the promotion"

# S2: `systemctl restart proteus-proton@proton-1` = ExecStop then ExecStart.
restart_slot() { run_script "$VDOWN" proton-1 && run_script "$VUP" proton-1 "$AUTO/proton-1.conf"; }
scenario S2 "restart (vpnns-down + vpnns-up)" 1.6 0.4 restart_slot
check "$(probe client 172.16.1.50 40022)" "S2 client A flows again after the restart"

# S3: a rebuild that aborts half way (set -e): wg setconf rejects the config
# AFTER teardown. The gap stays open until the next good run, so hold it 1s.
failed_rebuild() {
    run_script "$VUP" proton-1 "$AUTO/proton-1-broken.conf"; local rc=$?
    echo "$rc" > "$OUT/S3.rc"; sleep 1.0; return 0
}
scenario S3 "FAILED rebuild (vpnns-up aborted after teardown), held 1s" 1.8 0.4 failed_rebuild
check "$([[ $(cat "$OUT/S3.rc") -ne 0 ]] && echo 1 || echo 0)" "S3 the broken rebuild really did abort (vpnns-up exit $(cat "$OUT/S3.rc"))"
run_script "$VUP" proton-1 "$AUTO/proton-1.conf"
check "$(probe client 172.16.1.50 40023)" "S3 a good rebuild afterwards restores client A"

# S4: the slot is stopped (ExecStop) while pins and conntrack still carry its mark.
stop_slot() { run_script "$VDOWN" proton-1; sleep 1.0; }
scenario S4 "stopped slot (vpnns-down), held 1s" 1.8 0.4 stop_slot
info "S4 routing for mark 0x1 while stopped: $(ip route get 203.0.113.10 from 172.16.1.50 iif ens19 mark 0x1 2>&1 | head -1)"
run_script "$VUP" proton-1 "$AUTO/proton-1.conf"
check "$(probe client 172.16.1.50 40024)" "S4 restarting the slot restores client A"

# S5: an operator removes a trusted range while a trusted flow is established.
# prerouting_mangle returns before restoring the mark for a source that is no
# longer trusted, so that flow's packets arrive UNMARKED but keep their ct mark.
untrust() { nft flush set inet filter trusted_src; sleep 0.8; }
scenario S5 "trusted range removed under an established trusted flow" 1.4 0.4 untrust
nft add element inet filter trusted_src "{ $TRUSTED_ELEMS }"
check "$(probe trusted 10.99.99.2 40025)" "S5 re-adding the range restores trusted egress"

# S6: DNS tunnel rotation, as rotate-dns.sh does it (down + up), with a
# stand-in unbound querying continuously as uid unbound from the transit IP.
before=$(snap)
setpriv --reuid="$UNBOUND_UID" --regid="$UNBOUND_GID" --clear-groups \
    python3 "$TOOL" dnsq --src 172.31.6.1 --dst 10.2.0.1 --duration 2.0 --out "$OUT/S6-dns.json" &
dq=$!
sleep 0.4
run_script "$VDOWN" dns-6; run_script "$VUP" dns-6 "$AUTO/dns-6.conf"; s6rc=$?
wait "$dq"; after=$(snap); delta "$before" "$after"
check "$([[ ${D[leak]} -eq 0 ]] && echo 1 || echo 0)" \
    "S6 DNS-slot rotation: ${D[leak]} packets leaked to the uplink (transit/dns ${D[dns]}); $(guards); stand-in unbound ok=$(jget "$OUT/S6-dns.json" ok) errors=$(jget "$OUT/S6-dns.json" errors)"
info "S6 stand-in unbound errno histogram during the rotation: $(jget "$OUT/S6-dns.json" errno)"
check "$([[ $s6rc -eq 0 ]] && echo 1 || echo 0)" "S6 DNS vpnns-up exited 0"
r=$(setpriv --reuid="$UNBOUND_UID" --regid="$UNBOUND_GID" --clear-groups \
        python3 "$TOOL" udp-check --src 172.31.6.1 --dst 10.2.0.1 --port 53)
check "$r" "S6 unbound resolves through the rotated dns-6 tunnel"

# S7: staging, as rotate-slot.sh does it: a parallel instance at index 100+N,
# probed from inside its own namespace, then torn down.
staging() {
    run_script "$VUP" proton-1-s "$AUTO/proton-1-s.conf" 101 || { echo 0 > "$OUT/S7.ok"; return 0; }
    ip netns exec ns-proton-1-s python3 "$TOOL" udp-check --src 0.0.0.0 --dst 203.0.113.10 --port 5007 > "$OUT/S7.ok"
    ip route show table 201 > "$OUT/S7.table201"
    run_script "$VDOWN" proton-1-s
}
scenario S7 "staging slot up, probe, down (live slots running)" 1.8 0.3 staging
check "$(cat "$OUT/S7.ok")" "S7 staging slot proton-1-s has working egress from inside its namespace"
info "S7 staging table 201 while up: $(tr '\n' ';' < "$OUT/S7.table201")"
check "$(probe client 172.16.1.50 40027)" "S7 live proton-1 unaffected after staging teardown"

# S8: a flow the NFQUEUE dispatcher placed, whose map entry never landed (the
# insert failed or timed out, the map was full, or an eviction or reload came
# in between). No dispatcher runs here, so the verdict is emulated: the queue
# rule becomes `ct state new meta mark set 0x1`, which sets the packet mark and
# nothing else, exactly what pkt.set_mark() + accept() does. An unpinned client
# (.52) and the trusted host talk to a destination with no @vpn_dispatch entry.
# Once the flow is established it never matches `ct state new` again.
qh=$(nft -a list chain inet filter prerouting_mangle | awk '/ queue / && /ct state new/ {print $NF; exit}')
nft replace rule inet filter prerouting_mangle handle "$qh" ct state new counter meta mark set 0x1 comment '"sim-emulated-verdict"' \
    || die "S8 verdict emulation"
before=$(snap)
gen S8-u client 172.16.1.52 1.2 40031 203.0.113.20
gen S8-t trusted 10.99.99.2 1.2 40032 203.0.113.20
gen_wait
after=$(snap); delta "$before" "$after"
check "$([[ ${D[leak]} -eq 0 ]] && echo 1 || echo 0)" \
    "S8 dispatcher verdict with no map entry: ${D[leak]} packets leaked to the uplink (client-src ${D[client]}, trusted-src ${D[trusted]}); $(guards); unpinned client $(summ "$OUT/S8-u.json"), trusted $(summ "$OUT/S8-t.json")"
s8_ok=$(python3 -c 'import json,sys; d=[json.load(open(f)) for f in sys.argv[1:]]; print(1 if all(x["sent_est"] and x["recv_est"]/x["sent_est"]>=0.8 for x in d) else 0)' "$OUT/S8-u.json" "$OUT/S8-t.json")
check "$s8_ok" "S8-flow the dispatched flows stay on their tunnel once established (the verdict mark reached conntrack)"
qh=$(nft -a list chain inet filter prerouting_mangle | awk '/sim-emulated-verdict/ {print $NF; exit}')
nft replace rule inet filter prerouting_mangle handle "$qh" ct state new counter queue num 0 bypass || die "S8 restore"

# S9: no ruleset for a moment. Debian's stock `systemctl restart nftables` runs
# ExecStop=`nft flush ruleset` and then reloads; `stop` leaves it flushed. The
# proteus drop-in removes that ExecStop, but a box without it, a hand-run flush
# or a failed boot load still ends here, and the routing layer must hold. The
# pinned flows are established, and with no ruleset nothing restores their
# mark. Afterwards the sets are refilled as a real reload has to.
reload_ruleset() {
    nft flush ruleset; sleep 0.3
    nft -f "$SIM/nftables.conf" || return 1
    if [[ "$FWD_BYPASS" == 1 ]]; then fwd_bypass || return 1; fi
    seed_sets
    run_script /etc/proteus/bin/repopulate-wg-peers.sh
}
scenario S9 "ruleset flushed for 0.3s, then reloaded (stock systemctl restart nftables)" 1.6 0.4 reload_ruleset
check "$([[ $SC_RC -eq 0 ]] && echo 1 || echo 0)" "S9 the ruleset reloaded"
check "$(probe client 172.16.1.50 40029)" "S9 client A flows again after the reload"

legit_paths final

info "final policy routing: $(ip rule | tr '\n' ';' | tr -s '\t ' ' ')"
info "final table 101: $(ip route show table 101 | tr '\n' ';')"
echo "RESULT: $NPASS passed, $NFAIL failed"
[[ $NFAIL -eq 0 ]]
exit $?
fi

# --------------------------------------------------------------------------
# outer half: unprivileged setup, then re-exec into the namespaces
# --------------------------------------------------------------------------
REF=""; CODE=""; BIN_FROM=""; NFT_FROM=""; FWD_BYPASS=0; KEEP=0; MATRIX=""; TEMPLATE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ref) REF=$2; shift 2 ;;
        --code) CODE=$2; shift 2 ;;
        --bin-from) BIN_FROM=$2; shift 2 ;;
        --nft-from) NFT_FROM=$2; shift 2 ;;
        --fwd-bypass) FWD_BYPASS=1; shift ;;
        --keep) KEEP=1; shift ;;
        --template) TEMPLATE=1; shift ;;
        --matrix) MATRIX=$2; shift 2 ;;
        -h|--help) sed -n '2,60p' "$SELF"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done

if [[ -n "$MATRIX" ]]; then
    # Each row is a full independent run; the table is the defence-in-depth claim.
    # Each row: name | arguments | the check IDs it is EXPECTED to fail.
    #  - baseline: every leak scenario, and L8 (its ruleset marks unbound's TCP
    #    answers into the DNS tunnel);
    #  - routing only: L8 (baseline ruleset), and S8-flow: without the verdict
    #    saved to conntrack the flow cannot continue, though the sink keeps it
    #    off the uplink;
    #  - firewall only / postrouting only: S9, because a firewall cannot cover
    #    its own absence. That case is the routing layer's alone.
    declare -a rows=(
        "fixed (this tree)||"
        "fixed, installer template rendered instead of etc/nftables.conf|--template|"
        "baseline|--code-or-ref $MATRIX|L8 S1 S2 S3 S4 S5 S8 S8-flow S9"
        "routing layer only (fixed scripts, baseline ruleset)|--nft-from $MATRIX|L8 S8-flow"
        "firewall layer only (baseline scripts, fixed ruleset)|--bin-from $MATRIX|S9"
        "postrouting guard only (baseline scripts, fixed ruleset, forward bypassed)|--bin-from $MATRIX --fwd-bypass|S9"
    )
    mrc=0
    printf '\n%-76s %-28s %s\n' "configuration" "result" "failed checks vs expected"
    for row in "${rows[@]}"; do
        IFS='|' read -r name args expect <<<"$row"
        [[ "$args" == "--code-or-ref $MATRIX" ]] && { if [[ -d "$MATRIX" ]]; then args="--code $MATRIX"; else args="--ref $MATRIX"; fi; }
        # shellcheck disable=SC2086
        out=$("$SELF" $args 2>&1); rc=$?
        echo "$out" > "${TMPDIR:-/tmp}/rebuild_leak_sim.$(echo "$name" | tr -c 'a-z0-9' '_' | cut -c1-40).log"
        res=$(echo "$out" | grep -E '^RESULT:' | tail -1 | sed 's/^RESULT: //')
        fails=$(echo "$out" | grep -E '^FAIL' | awk '{print $2}' | sed 's/\[.*//' | sort -u | tr '\n' ' ' | sed 's/ $//')
        want=$(tr ' ' '\n' <<<"$expect" | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ $//')
        if [[ $rc -eq 77 ]]; then res="SKIP (environment)"; verdict="-"
        elif [[ -z "$res" ]]; then res="no result (rc=$rc)"; verdict="UNEXPECTED: setup failed"; mrc=1
        elif [[ "$fails" == "$want" ]]; then verdict="as expected${want:+ (fails: $want)}"
        else verdict="UNEXPECTED: failed [${fails}], expected [${want}]"; mrc=1
        fi
        printf '%-76s %-28s %s\n' "$name" "$res" "$verdict"
    done
    echo "(full logs: ${TMPDIR:-/tmp}/rebuild_leak_sim.*.log)"
    exit "$mrc"
fi

skip() { echo "SKIP  rebuild_leak_sim: $*"; exit 77; }
for c in unshare ip nft wg python3 setpriv newuidmap newgidmap getent; do
    command -v "$c" >/dev/null 2>&1 || skip "missing $c"
done
ME=$(id -un)
SUBUID=$(awk -F: -v u="$ME" '$1==u{print $2":"$3; exit}' /etc/subuid 2>/dev/null)
SUBGID=$(awk -F: -v u="$ME" '$1==u{print $2":"$3; exit}' /etc/subgid 2>/dev/null)
[[ -n "$SUBUID" && -n "$SUBGID" ]] || skip "no /etc/subuid or /etc/subgid range for $ME (needed to run the stand-in unbound as its own uid)"
su_start=${SUBUID%%:*}; su_cnt=${SUBUID##*:}; sg_start=${SUBGID%%:*}; sg_cnt=${SUBGID##*:}
(( su_cnt > 65535 )) && su_cnt=65535; (( sg_cnt > 65535 )) && sg_cnt=65535

SIM=$(mktemp -d "${TMPDIR:-/tmp}/proteus-leak-sim.XXXXXX")
chmod 755 "$SIM"
cleanup_outer() { [[ $KEEP == 1 ]] && echo "(kept $SIM)" || rm -rf "$SIM"; }
trap cleanup_outer EXIT
mkdir -p "$SIM"/{etc-top,etc-upper,etc-work,out,code}
chmod 777 "$SIM/out"

# resolve <ref|dir> -> a directory containing etc/...
resolve_tree() {
    local src=$1 dest
    if [[ -d "$src" ]]; then readlink -f "$src"; return 0; fi
    dest="$SIM/code/$(echo "$src" | tr -c 'A-Za-z0-9._-' '_')"
    mkdir -p "$dest"
    git -C "$ROOT" archive "$src" etc install 2>/dev/null | tar -x -C "$dest" 2>/dev/null \
        || { echo "cannot resolve '$src' as a directory or a git ref of $ROOT" >&2; exit 64; }
    echo "$dest"
}
BASE=$ROOT
[[ -n "$CODE" ]] && BASE=$(resolve_tree "$CODE")
[[ -n "$REF" ]] && BASE=$(resolve_tree "$REF")
BIN_TREE=$BASE; NFT_TREE=$BASE
[[ -n "$BIN_FROM" ]] && BIN_TREE=$(resolve_tree "$BIN_FROM")
[[ -n "$NFT_FROM" ]] && NFT_TREE=$(resolve_tree "$NFT_FROM")
label() { local t=$1; if [[ "$t" == "$ROOT" ]]; then echo "this-tree"; else echo "${t##*/}"; fi; }
label "$BIN_TREE" > "$SIM/label-bin"; label "$NFT_TREE" > "$SIM/label-nft"

if [[ $TEMPLATE == 1 ]]; then
    # Render exactly as install/lib/render.sh does: envsubst restricted to
    # INSTALLER_VARS, so nftables' own $DEFINES survive. Values = this sim's
    # topology, with the DNS instance named as on a migrated gateway (dns-6).
    command -v envsubst >/dev/null 2>&1 || skip "--template needs envsubst"
    VARLIST=$(sed -n "s/^INSTALLER_VARS='\(.*\)'$/\1/p" "$NFT_TREE/install/lib/render.sh")
    [[ -n "$VARLIST" ]] || { echo "INSTALLER_VARS not found in $NFT_TREE/install/lib/render.sh" >&2; exit 64; }
    MGMT_IFACE=ens18 CLIENT_IFACE=ens19 MGMT_CIDR=10.0.0.0/24 CLIENT_VLAN_CIDR=172.16.1.0/24 \
    CLIENT_GW_IP=172.16.1.5 DNS_UPSTREAMS=9.9.9.9 UNBOUND_UPSTREAM=10.2.0.1 STREAMING_MIN_MBPS=25 \
    PROTON_COUNTRY=US DNS_INSTANCE=dns-6 DNS_INDEX=6 DNS_TABLE=106 DNS_TRANSIT_MAIN=172.31.6.1 \
    DNS_FWMARK_HEX=0x6 UI_PORT=8443 UI_MGMT_EXTRA=127.0.0.1/32 \
    UI_CLIENT_RULE="        # client-VLAN access to the UI is disabled" \
    UNBOUND_FORWARD_ADDRS="" UNBOUND_TLS_UPSTREAM=no UNBOUND_MODULE_CONFIG="" UNBOUND_TLS_CERT_BUNDLE="" \
        envsubst "$VARLIST" < "$NFT_TREE/install/templates/nftables.conf.tmpl" > "$SIM/nftables.conf"
    echo "template:$(label "$NFT_TREE")" > "$SIM/label-nft"
else
    cp "$NFT_TREE/etc/nftables.conf" "$SIM/nftables.conf"
fi

# --- /etc overlay top layer ---------------------------------------------------
T=$SIM/etc-top
mkdir -p "$T/proteus/bin" "$T/proteus/state" "$T/proteus/wg/proton/auto" "$T/proteus/nft" "$T/netns"
cp -a "$BIN_TREE/etc/proteus/bin/." "$T/proteus/bin/"
chmod +x "$T/proteus/bin/"* 2>/dev/null
# The ruleset names system users at load time (meta skuid "..."). Reuse the
# host's if it has them; otherwise give them a uid inside the mapped range.
getent passwd > "$T/passwd"; getent group > "$T/group"
add_user() {   # <name> <uid>
    grep -q "^$1:" "$T/passwd" || { echo "$1:x:$2:$2::/nonexistent:/usr/sbin/nologin" >> "$T/passwd"; echo "$1:x:$2:" >> "$T/group"; }
}
add_user unbound 60101; add_user _apt 60042; add_user systemd-timesync 60123
ub=$(awk -F: '$1=="unbound"{print $3}' "$T/passwd")
(( ub >= 1 && ub <= su_cnt )) || skip "host uid for 'unbound' ($ub) is outside the mappable range 1..$su_cnt"

cat > "$T/proteus/proteus.env" <<'EOF'
PROTEUS_CLIENT_VLAN_CIDR=172.16.1.0/24
PROTEUS_CLIENT_GW_IP=172.16.1.5
PROTEUS_MGMT_CIDR=10.0.0.0/24
PROTEUS_DNS_UPSTREAMS="9.9.9.9"
PROTEUS_DNS_INSTANCE=dns-6
PROTEUS_DNS_INDEX=6
PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30
EOF
echo '{"trusted":[{"cidr":"192.168.77.0/24"}]}' > "$T/proteus/trusted.json"
# Boot seed, exactly what proteus-client-isolation.sh writes for "open".
echo 'add element inet filter client_pivot { 172.16.1.0/24 }' > "$T/proteus/nft/client-pivot-seed.nft"

# --- WireGuard material (throwaway keys, never printed) ----------------------
srv_priv=$(wg genkey); srv_pub=$(echo "$srv_priv" | wg pubkey)
{ echo "[Interface]"; echo "PrivateKey = $srv_priv"; echo "ListenPort = 51820"; } > "$SIM/wgsrv.conf"
mkconf() {   # <file> <endpoint> <tunnel-addr> [bad]
    local priv pub
    priv=$(wg genkey); pub=$(echo "$priv" | wg pubkey)
    {
        echo "# logical=SIM#1"
        echo "[Interface]"; echo "PrivateKey = $priv"; echo "Address = $3/32"; echo "DNS = 10.2.0.1"
        echo "[Peer]"
        if [[ "${4:-}" == bad ]]; then echo "PublicKey = not-a-valid-key"; else echo "PublicKey = $srv_pub"; fi
        echo "AllowedIPs = 0.0.0.0/0"; echo "Endpoint = $2:51820"
    } > "$T/proteus/wg/proton/auto/$1"
    { echo; echo "[Peer]"; echo "PublicKey = $pub"; echo "AllowedIPs = $3/32"; } >> "$SIM/wgsrv.conf"
}
mkconf proton-1.conf      192.0.2.11  10.2.0.11
mkconf proton-1-next.conf 192.0.2.21  10.2.0.21
mkconf proton-1-broken.conf 192.0.2.21 10.2.0.31 bad
mkconf proton-2.conf      192.0.2.12  10.2.0.12
mkconf dns-6.conf         192.0.2.16  10.2.0.16
mkconf proton-1-s.conf    192.0.2.111 10.2.0.111
chmod 600 "$T/proteus/wg/proton/auto/"*.conf "$SIM/wgsrv.conf"

# --- traffic tools -------------------------------------------------------------
cat > "$SIM/simtool.py" <<'PY'
#!/usr/bin/env python3
"""Traffic helpers for rebuild_leak_sim.sh. Pure stdlib, UDP/TCP only."""
import argparse, errno, json, select, socket, sys, time

def udp_echo(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port))
    while True:
        data, peer = s.recvfrom(2048)
        try:
            s.sendto(data, peer)
        except OSError:
            pass

def tcp_listen(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port)); s.listen(16)
    while True:
        c, _ = s.accept(); c.close()

def tcp_dns_server(a):
    """unbound's TCP pattern: bind + listen as root, drop to the unbound uid,
    then accept() and answer. The accepted socket is owned by that uid, which
    is what nftables' `meta skuid` sees on the answer. Holds each connection
    open for a while after answering, as unbound does."""
    import os, threading
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port)); s.listen(16)
    os.setgroups([]); os.setgid(a.gid); os.setuid(a.uid)
    def serve(c):
        try:
            c.settimeout(3); c.recv(512); c.sendall(b"answer"); time.sleep(2)
        except OSError:
            pass
        finally:
            c.close()
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()

def tcp_query(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5)
    try:
        s.bind((a.src, 0)); s.connect((a.dst, a.port)); s.sendall(b"q")
        print(1 if s.recv(64) else 0)
    except OSError:
        print(0)
    finally:
        s.close()

def tcp_check(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5)
    try:
        s.bind((a.src, 0)); s.connect((a.dst, a.port)); print(1)
    except OSError:
        print(0)

def udp_check(a):
    """Up to 5 tries; 1 if any reply comes back."""
    for _ in range(5):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.4)
        try:
            s.bind((a.src, 0)); s.sendto(b"check", (a.dst, a.port)); s.recvfrom(2048)
            print(1); return
        except OSError:
            time.sleep(0.05)
        finally:
            s.close()
    print(0)

def gen(a):
    """A pinned ESTABLISHED flow (fixed source port, one packet per est-interval)
    plus a NEW flow (fresh source port) every new-interval. Unconnected sockets,
    so ICMP errors never turn into exceptions and the send rate never stalls."""
    est = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    est.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    est.bind((a.src, a.est_sport)); est.setblocking(False)
    dst = (a.dst, a.port)
    st = dict(sent_est=0, recv_est=0, sent_new=0, recv_new=0, send_err=0)
    news = []   # (socket, created)
    t0 = time.monotonic(); end = t0 + a.duration
    nxt_e = nxt_n = t0
    while True:
        now = time.monotonic()
        if now >= end + 0.35:
            break
        if now < end:
            if now >= nxt_e:
                try:
                    est.sendto(b"e", dst); st["sent_est"] += 1
                except OSError:
                    st["send_err"] += 1
                nxt_e += a.est_interval
            if now >= nxt_n:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
                s.bind((a.src, 0))
                try:
                    s.sendto(b"n", dst); st["sent_new"] += 1
                except OSError:
                    st["send_err"] += 1
                news.append((s, now)); nxt_n += a.new_interval
        news = [(s, c) for (s, c) in news if now - c < 1.5 or s.close()]
        socks = [est] + [s for s, _ in news]
        r, _, _ = select.select(socks, [], [], 0.001)
        for s in r:
            while True:
                try:
                    s.recvfrom(64)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                st["recv_est" if s is est else "recv_new"] += 1
    json.dump(st, open(a.out, "w"))

def dnsq(a):
    """unbound's upstream pattern: a fresh socket per query, bound to the
    dns-tunnel transit address (outgoing-interface), one query every 20 ms."""
    st = dict(ok=0, errors=0, errno={})
    end = time.monotonic() + a.duration
    while time.monotonic() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.1)
        try:
            s.bind((a.src, 0)); s.sendto(b"q", (a.dst, 53)); s.recvfrom(512); st["ok"] += 1
        except socket.timeout:
            st["errors"] += 1; st["errno"]["timeout"] = st["errno"].get("timeout", 0) + 1
        except OSError as e:
            n = errno.errorcode.get(e.errno, str(e.errno))
            st["errors"] += 1; st["errno"][n] = st["errno"].get(n, 0) + 1
        finally:
            s.close()
        time.sleep(0.02)
    json.dump(st, open(a.out, "w"))

p = argparse.ArgumentParser()
sp = p.add_subparsers(dest="cmd", required=True)
x = sp.add_parser("udp-echo"); x.add_argument("--bind"); x.add_argument("--port", type=int)
x = sp.add_parser("tcp-listen"); x.add_argument("--bind"); x.add_argument("--port", type=int)
x = sp.add_parser("tcp-check"); x.add_argument("--src"); x.add_argument("--dst"); x.add_argument("--port", type=int)
x = sp.add_parser("tcp-query"); x.add_argument("--src"); x.add_argument("--dst"); x.add_argument("--port", type=int)
x = sp.add_parser("tcp-dns-server"); x.add_argument("--bind"); x.add_argument("--port", type=int)
x.add_argument("--uid", type=int); x.add_argument("--gid", type=int)
x = sp.add_parser("udp-check"); x.add_argument("--src"); x.add_argument("--dst"); x.add_argument("--port", type=int)
x = sp.add_parser("gen")
for k in ("--src", "--dst", "--out"): x.add_argument(k, required=True)
x.add_argument("--port", type=int, required=True); x.add_argument("--duration", type=float, required=True)
x.add_argument("--est-sport", type=int, default=40001)
x.add_argument("--est-interval", type=float, default=0.002)
x.add_argument("--new-interval", type=float, default=0.01)
x = sp.add_parser("dnsq")
for k in ("--src", "--dst", "--out"): x.add_argument(k, required=True)
x.add_argument("--duration", type=float, required=True)
a = p.parse_args()
{"udp-echo": udp_echo, "tcp-listen": tcp_listen, "tcp-check": tcp_check,
 "udp-check": udp_check, "gen": gen, "dnsq": dnsq,
 "tcp-query": tcp_query, "tcp-dns-server": tcp_dns_server}[a.cmd](a)
PY
[[ "$(cat "$SIM/label-bin")" == this-tree ]] || true

echo "sim dir: $SIM"
unshare --map-users="0:$(id -u):1" --map-users="1:$su_start:$su_cnt" \
        --map-groups="0:$(id -g):1" --map-groups="1:$sg_start:$sg_cnt" \
        --setuid 0 --setgid 0 --net --mount \
        bash "$SELF" --inner "$SIM" "$FWD_BYPASS"
rc=$?
[[ $rc -eq 2 ]] && { echo "setup failed; scripts log:"; tail -20 "$SIM/scripts.log" 2>/dev/null; }
exit $rc
