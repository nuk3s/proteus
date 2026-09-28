#!/usr/bin/env bash
# Bring up a VPN instance in its own network namespace.
# Usage: vpnns-up.sh <instance-name> <wg-conf-path> [index-override]
#
# Without index-override: instance must end with -N; that N controls transit
# /30, fwmark, routing table.
# With index-override: <instance-name> can be anything (e.g. proton-1-new);
# the supplied integer is used as the index — required when staging a rotation
# under a non-numeric suffix.

set -euo pipefail

# Deployment-specific values (client VLAN CIDR, DNS upstreams) come from the
# installer-rendered env; fall back to the historical production values so an
# un-migrated box still works.
[[ -r /etc/proteus/proteus.env ]] && source /etc/proteus/proteus.env
# UI-set overrides survive installer re-runs
[ -f /etc/proteus/proteus-local.env ] && . /etc/proteus/proteus-local.env
CLIENT_VLAN_CIDR="${PROTEUS_CLIENT_VLAN_CIDR:-172.16.1.0/24}"
# Default spreads across distinct Quad9 service IPs (secured 9.9.9.9 plus the
# unsecured-tier 9.9.9.10 / 149.112.112.10): separate anycast service addresses
# rate-limit independently, so one throttled path no longer blacks out all
# in-netns resolution (the ECS variants are avoided — they leak client subnet).
DNS_UPSTREAMS="${PROTEUS_DNS_UPSTREAMS:-9.9.9.9 9.9.9.10 149.112.112.10}"

INSTANCE="${1:?instance name required (e.g. proton-1)}"
WG_CONF="${2:?wg config path required}"
INDEX_OVERRIDE="${3:-}"

if [[ -n "$INDEX_OVERRIDE" ]]; then
    NAME_IDX="$INDEX_OVERRIDE"
else
    NAME_IDX="${INSTANCE##*-}"
fi
[[ "$NAME_IDX" =~ ^[0-9]+$ ]] || { echo "Index must be numeric (instance name tail or override arg)" >&2; exit 1; }
(( NAME_IDX >= 1 && NAME_IDX <= 200 )) || { echo "Index out of range 1-200" >&2; exit 1; }

NS="ns-${INSTANCE}"
VETH_MAIN="v-${INSTANCE}"
VETH_NS="v-${INSTANCE}-ns"
# WireGuard link is created in the main ns under a per-instance-unique name
# (see the create/move step below for why "wg0" would race at boot), then
# renamed to wg0 inside the target ns.
WG_TMP="wg-${INSTANCE}"
# Interface name length limit is 15
(( ${#VETH_NS} <= 15 )) || { echo "veth name too long: ${VETH_NS}" >&2; exit 1; }
(( ${#WG_TMP}  <= 15 )) || { echo "wg name too long: ${WG_TMP}" >&2; exit 1; }

TRANSIT_MAIN="172.31.${NAME_IDX}.1"
TRANSIT_NS="172.31.${NAME_IDX}.2"
FWMARK="$(printf '0x%x' "$NAME_IDX")"
RT_TABLE="$((100 + NAME_IDX))"

STATE_FILE="/etc/proteus/state/${INSTANCE}.state"
RUN_DIR="/run/proteus"
NETNS_CONF_DIR="/etc/netns/${NS}"
mkdir -p "$RUN_DIR" "$NETNS_CONF_DIR" "$(dirname "$STATE_FILE")"

TMP_CONF=$(mktemp "${RUN_DIR}/wg-XXXXXX.conf")
chmod 600 "$TMP_CONF"
trap 'rm -f "$TMP_CONF"' EXIT

ADDRS=$(awk -F'= *' '/^Address/ {print $2}' "$WG_CONF" | tr -d ' ')
# Endpoint IPv4 — used to whitelist outbound WG handshake in the main-ns kill-switch.
WG_ENDPOINT_IP=$(awk -F'= *' '
    /^Endpoint[[:space:]]*=/ {
        ep=$2; gsub(/[[:space:]]/,"",ep)
        # Skip IPv6 bracketed form.
        if (ep ~ /^\[/) next
        sub(/:[0-9]+$/, "", ep)
        print ep; exit
    }
' "$WG_CONF")
[[ -n "$WG_ENDPOINT_IP" ]] || { echo "no IPv4 Endpoint in $WG_CONF" >&2; exit 1; }

awk '
    /^#/      { next }
    /^[[:space:]]*$/ { next }
    /^(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=/ { next }
    { print }
' "$WG_CONF" > "$TMP_CONF"

# Fail closed BEFORE tearing anything down (see routeguard.sh for the whole
# argument). From here until the default route is re-added near the end of
# this script, this slot's marked traffic has no way out. It used to fall
# through to `main` and leave by the uplink un-tunnelled. It now hits a
# blackhole route instead and is dropped silently (a client retransmits into
# the rebuilt tunnel). That holds for a successful rebuild's sub-second gap,
# and just as well for a rebuild that `set -e` aborts somewhere below, which
# leaves the gap open until the next successful run.
#   - The sentinel is fatal: if it cannot be installed, stop here with the
#     incumbent tunnel still intact rather than open a gap with nothing
#     behind it.
#   - The catch rule and the ingress sink are only warnings: the sentinel
#     already covers this slot, and the firewall still drops the packet.
# shellcheck source=/dev/null
. "$(dirname "${BASH_SOURCE[0]}")/routeguard.sh"
rg_sentinel_ensure "$RT_TABLE"
rg_catch_ensure || echo "WARN: catch rule not installed; per-table sentinel and firewall still apply" >&2
rg_sink_ensure || echo "WARN: ingress sink incomplete; per-table sentinel and firewall still apply" >&2

# Idempotent teardown of any existing instance.
# The tunnel route is removed explicitly first, so the table state after
# teardown does not depend on the kernel pruning routes when the veth dies.
# `via` makes the delete specific: it can never match the blackhole sentinel.
# The fwmark and source rules are deliberately NOT deleted. They stay in place
# for the whole rebuild and point at a table that routes this slot's traffic
# either through the tunnel or nowhere. Deleting them was half of the leak:
# with no rule for the mark, the lookup went straight to `main`.
ip route del default via "$TRANSIT_NS" table "$RT_TABLE" 2>/dev/null || true
ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_MAIN" 2>/dev/null || true
# Clean up a main-ns WG link orphaned by a prior run that died after
# `ip link add` but before the move into the netns.
ip link del "$WG_TMP" 2>/dev/null || true

# Whitelist the WG peer in the main-ns kill-switch BEFORE any handshake can fire.
# (`add element` is idempotent on duplicate values.)
nft "add element inet filter wg_peers { ${WG_ENDPOINT_IP} }" 2>/dev/null || true

# Namespace + loopback
ip netns add "$NS"
ip -n "$NS" link set lo up

# veth pair: main ns <-> target ns
ip link add "$VETH_MAIN" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"
ip addr add "${TRANSIT_MAIN}/30" dev "$VETH_MAIN"
ip link set "$VETH_MAIN" up
ip -n "$NS" addr add "${TRANSIT_NS}/30" dev "$VETH_NS"
ip -n "$NS" link set "$VETH_NS" up

# WireGuard: create in main ns so UDP socket binds here, then move.
# Use a per-instance-unique name ($WG_TMP), NOT the shared "wg0": at boot all
# five proteus-proton@proton-N units run this script in the main ns in
# parallel, so two concurrent `ip link add wg0` calls collide — the loser gets
# "RTNETLINK answers: File exists" and `set -e` aborts, leaving a zombie netns
# with no wg0 and unconfigured routing (the every-boot race + orphaned proton-3/
# proton-4 in the design notes).
# Unique names never collide; the interface is renamed to wg0 inside the ns.
ip link add "$WG_TMP" type wireguard
ip link set "$WG_TMP" netns "$NS"
ip -n "$NS" link set "$WG_TMP" name wg0

# Addresses (v4 and v6 from config)
IFS=','
for addr in $ADDRS; do
    addr=$(echo "$addr" | tr -d ' ')
    [[ -z "$addr" ]] && continue
    if [[ "$addr" == *:* ]]; then
        ip -n "$NS" -6 addr add "$addr" dev wg0 2>/dev/null || true
    else
        ip -n "$NS" addr add "$addr" dev wg0
    fi
done
unset IFS

ip netns exec "$NS" wg setconf wg0 "$TMP_CONF"
ip -n "$NS" link set wg0 up
# Return path for the client subnet back to main ns.
ip -n "$NS" route add "$CLIENT_VLAN_CIDR" via "$TRANSIT_MAIN" dev "$VETH_NS"
# Same for every trusted range and for the UDM tunnel itself, so a slot that has
# just rotated can answer trusted hosts immediately rather than waiting for the
# reconcile service. `route replace` rather than `add`: only the client route
# above is guaranteed unique, and a range may legitimately already be present.
# Rotating-pool slots only — the DNS namespace carries resolver traffic, which
# never has a trusted-VLAN source. The tunnel subnet is only added alongside at
# least one trusted range: with the feature off (no trusted.json, an empty one,
# or one that fails validation) this namespace must come up with exactly the
# return routes it had before this feature existed — the same gate
# proteus-trusted-egress.sh applies before it will touch a slot namespace.
#
# Always reset _trusted first: with no assignment here at all, a value this
# variable happened to hold in the *caller's* environment would survive into a
# non-proton instance (the DNS namespace, which must never get one of these
# routes) since the `if` below would simply not run.
#
# Under `set -euo pipefail` a bare `_trusted=$(...)` propagates the command
# substitution's exit status like any other simple command, so a missing
# python3 (127) or a missing/misplaced trusted.py (2) would abort this script
# right here — before the default route, the intra-namespace firewall, DNS and
# the state file are ever written, leaving a dead, firewall-less slot on every
# rotation and boot. `|| _trusted=""` keeps that failure from being anything
# more than "no trusted ranges this time"; `timeout` keeps a hung trusted.py
# from stalling the bring-up indefinitely.
_trusted=""
if [[ "$INSTANCE" =~ ^proton-[0-9]+$ ]]; then
    _trusted=$(timeout 5 python3 "${PROTEUS_BIN:-/etc/proteus/bin}"/trusted.py list \
                   --file "${PROTEUS_TRUSTED_FILE:-/etc/proteus/trusted.json}" \
                   --mgmt-cidr "${PROTEUS_MGMT_CIDR:-}" \
                   --client-cidr "${CLIENT_VLAN_CIDR:-}" 2>/dev/null) || _trusted=""
fi
for _tc in ${_trusted:+$_trusted "${PROTEUS_UDM_TUNNEL_CIDR:-10.99.99.0/30}"}; do
    [ -n "$_tc" ] || continue
    ip -n "$NS" route replace "$_tc" via "$TRANSIT_MAIN" dev "$VETH_NS" || true
done
ip -n "$NS" route add default dev wg0
ip -n "$NS" -6 route add default dev wg0 2>/dev/null || true

# Intra-ns firewall: MASQUERADE out wg0; drop anything out non-wg0 (per-ns kill-switch)
ip netns exec "$NS" nft -f - << NFT_EOF
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        iifname "${VETH_NS}" accept
        iifname "wg0" accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        ct state established,related accept
        iifname "${VETH_NS}" oifname "wg0" accept
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wg0" masquerade
    }
}
NFT_EOF

# Enable forwarding inside ns
ip netns exec "$NS" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true

# Per-ns DNS — the main ns's resolv.conf points at the LAN router (10.0.0.22)
# which isn't reachable from inside the tunnel ns. Write a netns-scoped
# resolv.conf: `ip netns exec` bind-mounts this over /etc/resolv.conf for any
# process it spawns. Queries to Quad9 exit via the default route (wg0), so
# DNS traffic transits the VPN — no leak of user's real IP, and no reliance
# on the mgmt network resolver that the kill-switch doesn't permit anyway.
{
  for ns in $DNS_UPSTREAMS; do echo "nameserver $ns"; done
  echo "options edns0 timeout:2 attempts:2"
} > "${NETNS_CONF_DIR}/resolv.conf"
chmod 644 "${NETNS_CONF_DIR}/resolv.conf"

# Main-ns: fwmark -> dedicated table -> veth to ns.
# The route goes in first, then the rules. On a rebuild the rules never went
# away, so adding the route is the moment this slot's traffic flows again. On
# a first bring-up, the rule appears only once the table can route. Both rule
# adds are add-if-absent: an identical rule left by the previous run counts
# as success.
ip route replace default via "$TRANSIT_NS" dev "$VETH_MAIN" table "$RT_TABLE"
rg_rule_ensure fwmark "$FWMARK" lookup "$RT_TABLE" pref $((500 + NAME_IDX))

# Source-IP rule: packets originating from the main-ns side of the veth
# (i.e. bound to $TRANSIT_MAIN) take the same route table. Used by unbound
# on the dns-6 tunnel where `outgoing-interface: 172.31.6.1` pins the
# source address — this rule steers those packets to the dedicated tunnel.
# Harmless for slots where nothing binds to the transit IP.
# (Tried `type route hook output priority mangle` with mark-set: mangle fires
# but the reroute is unreliable on this kernel, so we use a deterministic
# source-based rule instead.)
rg_rule_ensure from "$TRANSIT_MAIN" lookup "$RT_TABLE" pref $((400 + NAME_IDX))

cat > "$STATE_FILE" << EOF
INSTANCE=${INSTANCE}
NS=${NS}
VETH_MAIN=${VETH_MAIN}
VETH_NS=${VETH_NS}
TRANSIT_MAIN=${TRANSIT_MAIN}
TRANSIT_NS=${TRANSIT_NS}
FWMARK=${FWMARK}
RT_TABLE=${RT_TABLE}
WG_CONF=${WG_CONF}
WG_ENDPOINT_IP=${WG_ENDPOINT_IP}
UP_TIME=$(date -Iseconds)
EOF

# Tell the dispatcher, now that the state file is complete. vpnns-down.sh
# signalled when this slot stopped, and the reload that followed dropped it
# from the list; on a one-slot box, or when every slot restarts, that emptied
# the list, and new flows are dropped while it stays empty. Without this the
# slot would wait for one of the dispatcher's own re-reads. Same rules as in
# vpnns-down.sh: live slots only (a staging copy is not in the list, and after
# a promotion rotate-slot.sh's own SIGHUP is a harmless second reload), silent
# and never fatal (at boot the slots come up before the dispatcher starts).
if [[ "$INSTANCE" =~ ^proton-[0-9]+$ ]]; then
    systemctl kill --kill-who=main --signal=HUP proteus-dispatcher.service >/dev/null 2>&1 || true
fi

echo "UP: ${INSTANCE}  ns=${NS}  transit=${TRANSIT_NS}  fwmark=${FWMARK}  table=${RT_TABLE}  peer=${WG_ENDPOINT_IP}"
