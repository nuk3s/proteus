#!/usr/bin/env bash
# routeguard.sh — fail-closed policy routing for VPN-bound traffic.
#
# Sourced by vpnns-up.sh and vpnns-down.sh. Also runnable on its own, which is
# how proteus-dispatcher.service (ExecStartPre) and the installer arm it:
#   routeguard.sh [TABLE...]   install the catch rule and the ingress sink,
#                              plus a sentinel in each TABLE
#
# THE INVARIANT: a packet carrying a nonzero fwmark belongs to a VPN slot and
# may leave the box ONLY through that slot's veth. Policy routing gets it there
# with `ip rule fwmark N lookup 100+N`, and table 100+N holds a single default
# route through the veth.
#
# That used to fail OPEN, and every failure ended in table `main`, whose
# default route is the management uplink. The packet left the box un-tunnelled
# with its client source address intact:
#   - An EMPTY slot table. When no route in a table matches, the kernel does not
#     stop; it moves on to the next rule, and eventually to `main`. The table
#     empties every time the slot's veth is deleted (every rebuild, promotion or
#     restart), and it stays empty if a rebuild aborts half way through.
#   - NO RULE for the mark. This happens while a slot is stopped, and during a
#     rebuild between the old rule delete and the new rule add.
#   - NO MARK AT ALL on a flow that was dispatched. The mark lives in nftables:
#     prerouting_mangle restores it from conntrack on every packet. With the
#     ruleset flushed (by hand, by a load that failed at boot, or by Debian's
#     stock nftables.service, whose restart and stop run `nft flush ruleset`
#     on a box without the proteus drop-in), or a dispatched flow whose mark
#     never reached conntrack, the packet arrives unmarked and routes via
#     `main`.
#
# Three routing fixes, each independent of nftables:
#   1. Every slot table ends in `blackhole default metric 4294967295`, the
#      largest metric there is, so the real route wins whenever it exists. A
#      blackhole route ENDS the rule walk instead of falling through.
#   2. One static rule sits after every slot rule and before `main`:
#      `not fwmark 0x0/0xffffffff blackhole`. It catches a mark that has no
#      slot rule at all. The mask is not optional: `not fwmark 0` stores
#      mark 0/mask 0, which matches nothing.
#   3. The INGRESS SINK. Forwarded traffic that arrives on the client interface
#      or the trusted tunnel (wg-udm) and reaches pref 32020 without having
#      matched a slot rule is routed to a dummy device, never to `main`. An
#      RFC1918 destination is exempt at pref 32010 (the client LAN pivot, and
#      the trusted-to-LAN log-and-drop). This rule keys on the ingress
#      interface, not on the mark, so it holds with no ruleset loaded at all.
#
# Why blackhole and not unreachable (1 and 2): an unreachable route answers a
# forwarded packet with ICMP host-unreachable, and a client TCP stack aborts a
# connect() on that at once. A blackhole drops silently, so the client simply
# retransmits the SYN a second later, by which time a rebuild is long done.
# Either one stops the leak; only blackhole is invisible to clients.
#
# Why a dummy device and not a blackhole (3): the reverse-path filter. With
# rp_filter on, a tunnel's reply to a client is validated by a lookup of its
# (public) source address as if it had arrived on the client interface, so
# that lookup lands on the pref-32020 rule too. It must find a real unicast
# route there or the kernel drops every tunnel reply. A route to a dummy
# device satisfies loose mode and still delivers nothing: the dummy discards
# whatever it is given.
#
# The firewall is the separate layer: chain forward and chain
# postrouting_guard in nftables.conf drop VPN-bound traffic headed for any
# interface other than a slot veth. Keep both layers, because each covers a
# failure the other cannot see.

# The largest route metric. The real `default via <veth>` route is added with
# metric 0, so it always wins while it exists.
RG_SENTINEL_METRIC=4294967295

# Must sort AFTER every slot rule and BEFORE `main` (32766). Slot rules sit at
# 400+idx and 500+idx with idx <= 200, so all of them fall in 401..700.
RG_CATCH_PREF=32000

# The ingress sink. Table number: outside every slot, staging and DNS table
# (100+idx, idx 1..200, so 101..300) and the trusted-egress table (110), and
# not one of the kernel's reserved 253..255.
RG_SINK_DEV=proteus-null
RG_SINK_TABLE=900
RG_SINK_LAN_PREF=32010
RG_SINK_PREF=32020
# Mirrors `define RFC1918` in nftables.conf: the destinations prerouting_mangle
# never marks, which therefore legitimately route via `main`.
RG_LAN_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
# The trusted tunnel's interface name is fixed (proteus-trusted-egress.sh).
# A rule naming an interface that does not exist is valid and matches nothing.
RG_TRUSTED_IFACE=wg-udm

# rg_rule_ensure [-4|-6] <ip-rule args...>
# Adds an ip rule unless an identical one is already installed. The kernel
# refuses an exact duplicate with EEXIST, and for us that counts as success.
# This lets a rebuild leave its rules in place instead of deleting and
# re-adding them (the delete is what opened the gap).
rg_rule_ensure() {
    local fam=-4 err
    case "${1:-}" in -4|-6) fam=$1; shift ;; esac
    # LC_ALL=C: the EEXIST test below matches iproute2's strerror() text,
    # which is localized.
    if err=$(LC_ALL=C ip "$fam" rule add "$@" 2>&1); then
        return 0
    fi
    case "$err" in *"File exists"*) return 0 ;; esac
    printf 'routeguard: ip %s rule add %s: %s\n' "$fam" "$*" "$err" >&2
    return 1
}

# rg_sentinel_ensure <table>
# Idempotent. `replace` keys on (prefix, tos, metric), so this never touches the
# real metric-0 default route in the same table. It also converts an older
# `unreachable` sentinel in place.
rg_sentinel_ensure() {
    local table=${1:?table required}
    ip route replace blackhole default metric "$RG_SENTINEL_METRIC" table "$table"
}

# rg_catch_ensure
# The static catch rule. IPv6 is best-effort: nothing marks v6 on purpose, and
# a host with IPv6 disabled has no v6 rule table to write to.
rg_catch_ensure() {
    rg_rule_ensure -4 not fwmark 0x0/0xffffffff pref "$RG_CATCH_PREF" blackhole || return 1
    rg_rule_ensure -6 not fwmark 0x0/0xffffffff pref "$RG_CATCH_PREF" blackhole 2>/dev/null || true
}

# rg_client_iface
# Prints the client-VLAN interface: PROTEUS_CLIENT_IFACE when set (the
# installer renders it), otherwise the interface holding PROTEUS_CLIENT_GW_IP.
# Reads the env file itself when the caller has not sourced it.
rg_client_iface() {
    local ifc=${PROTEUS_CLIENT_IFACE:-} gw=${PROTEUS_CLIENT_GW_IP:-}
    local env=${PROTEUS_ENV_FILE:-/etc/proteus/proteus.env}
    if [[ -z "$ifc" && -z "$gw" && -r "$env" ]]; then
        # shellcheck disable=SC1090
        ifc=$(. "$env" >/dev/null 2>&1; printf '%s' "${PROTEUS_CLIENT_IFACE:-}")
        # shellcheck disable=SC1090
        gw=$(. "$env" >/dev/null 2>&1; printf '%s' "${PROTEUS_CLIENT_GW_IP:-}")
    fi
    if [[ -z "$ifc" && -n "$gw" ]]; then
        ifc=$(ip -o -4 addr show to "$gw/32" 2>/dev/null | awk '{print $2; exit}')
    fi
    [[ -n "$ifc" ]] || return 1
    printf '%s\n' "$ifc"
}

# rg_sink_ensure
# Idempotent. The RFC1918 exemptions go in before the sink rule, so there is
# never a moment where LAN-bound traffic from the client VLAN is sunk.
rg_sink_ensure() {
    local ifc p rc=0 ifaces=()
    if ifc=$(rg_client_iface); then
        ifaces+=("$ifc")
    else
        printf 'routeguard: client interface unknown (set PROTEUS_CLIENT_IFACE in proteus.env); ingress sink covers %s only\n' \
            "$RG_TRUSTED_IFACE" >&2
        rc=1
    fi
    ifaces+=("$RG_TRUSTED_IFACE")
    if ! ip link show dev "$RG_SINK_DEV" >/dev/null 2>&1; then
        # A concurrent run may win the race to create it; the `set up` below
        # is the real check.
        ip link add "$RG_SINK_DEV" type dummy 2>/dev/null || true
    fi
    # No IPv6 on the sink. With it, the kernel sends router solicitations and
    # MLD reports out of the device when it comes up, so its TX counter moves
    # with no client traffic at all, and that counter is what operations.md's
    # health check reads (as a delta) to see whether anything reached the
    # sink. Before `up`, so not even the first RS goes out. A device created
    # before this write existed keeps the packets it already sent, which is
    # why the check is a delta. The knob is absent on a box booted with IPv6
    # disabled; nothing to do then.
    if [[ -e /proc/sys/net/ipv6/conf/$RG_SINK_DEV/disable_ipv6 ]]; then
        echo 1 > "/proc/sys/net/ipv6/conf/$RG_SINK_DEV/disable_ipv6" || true
    fi
    ip link set dev "$RG_SINK_DEV" up || return 1
    ip route replace default dev "$RG_SINK_DEV" table "$RG_SINK_TABLE" || return 1
    for ifc in "${ifaces[@]}"; do
        for p in $RG_LAN_NETS; do
            rg_rule_ensure iif "$ifc" to "$p" lookup main pref "$RG_SINK_LAN_PREF" || rc=1
        done
        rg_rule_ensure iif "$ifc" lookup "$RG_SINK_TABLE" pref "$RG_SINK_PREF" || rc=1
    done
    return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -euo pipefail
    for _t in "$@"; do
        [[ "$_t" =~ ^[0-9]+$ ]] || { echo "routeguard: table must be numeric: $_t" >&2; exit 1; }
    done
    _rc=0
    rg_catch_ensure || _rc=1
    rg_sink_ensure || _rc=1
    for _t in "$@"; do
        rg_sentinel_ensure "$_t" || _rc=1
    done
    exit "$_rc"
fi
