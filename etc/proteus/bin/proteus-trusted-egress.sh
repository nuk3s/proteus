#!/bin/bash
# Reconcile the trusted-egress data path with /etc/proteus/trusted.json.
#
# Idempotent, and safe to run at any time including when the feature is off.
# There are two "off" states and they are deliberately not the same:
#
#   no pairing        A COMPLETE teardown, the interface included. This is the
#                     shipped default, so a box that never pairs a UDM behaves
#                     exactly as it did before this feature existed.
#   paired, no ranges The tunnel comes up and NOTHING else does. The documented
#                     rollout is: pair, confirm the peer handshakes, watch which
#                     source addresses arrive on the tunnel, and only then
#                     configure a range. Tearing the interface down for an empty
#                     list would make every one of those steps impossible and
#                     leave the operator guessing the answer the tunnel exists to
#                     provide. Nothing is forwarded in this state either — an
#                     empty @trusted_src gates everything, and no rule or route
#                     is installed.
#
# What this does NOT do is create key material. Pairing mints a private key and
# is a deliberate operator action through the web UI (broker cmd=udm-peer); this
# script only applies what pairing left behind. An unpaired box therefore stays
# inert no matter what the list says.
#
# The state it owns, and nothing else:
#   @trusted_src            the nft set the dispatch gate consults
#   wg-udm                  the tunnel interface, address, MTU and peer
#   ip rule pref 90         proteus' own traffic -> main table
#   ip rule pref 95         client VLAN -> a trusted range, on the main table
#   ip rule pref 100        replies to trusted ranges -> the tunnel table
#   ip route table 110      the tunnel table itself
#   ns-proton-*             a return route per trusted range
set -euo pipefail

log() { printf '[%(%FT%T%z)T] proteus-trusted-egress: %s\n' -1 "$*" >&2; }

# Base env then the UI overlay, matching proteus-client-isolation.sh: the config
# files are the source of truth, so an inherited variable must not be able to
# apply a shape the operator never configured. The path overrides exist only so
# the tests can run hermetically.
PROTEUS_ENV_FILE="${PROTEUS_ENV_FILE:-/etc/proteus/proteus.env}"
PROTEUS_LOCAL_ENV_FILE="${PROTEUS_LOCAL_ENV_FILE:-/etc/proteus/proteus-local.env}"
# shellcheck disable=SC1090
[ -r "$PROTEUS_ENV_FILE" ]       && . "$PROTEUS_ENV_FILE"
# shellcheck disable=SC1090
[ -r "$PROTEUS_LOCAL_ENV_FILE" ] && . "$PROTEUS_LOCAL_ENV_FILE"

BIN="${PROTEUS_BIN:-/etc/proteus/bin}"
STATE_DIR="${PROTEUS_STATE_DIR:-/etc/proteus/state}"
TRUSTED_FILE="${PROTEUS_TRUSTED_FILE:-/etc/proteus/trusted.json}"
KEY_DIR="${PROTEUS_UDM_KEY_DIR:-/etc/proteus/wg/udm}"
MGMT_CIDR="${PROTEUS_MGMT_CIDR:-10.0.0.0/24}"
CLIENT_VLAN_CIDR="${PROTEUS_CLIENT_VLAN_CIDR:-172.16.1.0/24}"
# TUNNEL_CIDR and TUNNEL_MTU are genuinely site-settable: set either in
# proteus.env or in the proteus-local.env overlay (both sourced above, overlay
# last) and this script and the broker's pairing renderer follow.
TUNNEL_CIDR="${PROTEUS_UDM_TUNNEL_CIDR:-10.99.99.0/30}"
# The port is NOT: it is FIXED, in lockstep with `define UDM_TUNNEL_PORT` in
# etc/nftables.conf and install/templates/nftables.conf.tmpl: the input chain
# accepts the handshake on that port and nothing renders one of the three from
# another. Setting the variable alone moves the listener to a port the firewall
# drops, which looks exactly like a UDM that will not connect. Change all three
# or none; a test asserts they agree.
TUNNEL_PORT="${PROTEUS_UDM_TUNNEL_PORT:-51821}"
TUNNEL_MTU="${PROTEUS_UDM_TUNNEL_MTU:-1420}"
RT_TABLE="${PROTEUS_TRUSTED_TABLE:-110}"
IFACE=wg-udm
NFT_TABLE="inet filter"
SET=trusted_src
PREF_SELF=90
PREF_CLIENT=95
PREF_RETURN=100

# Delete every rule at a preference. `ip rule del pref N` removes one at a time
# and fails once none are left, which is the loop's exit condition. Capped so a
# spuriously succeeding delete cannot spin here forever.
del_rules() {
    local n=0
    while [ "$n" -lt 16 ] && ip rule del pref "$1" 2>/dev/null; do n=$((n+1)); done
}

# Every step is attempted even when an earlier one fails, and a failure is named
# rather than swallowed. "Off means off" is a promise, so a teardown that only
# half happened has to be visible in the log instead of passing for success —
# and must not abort the steps after it, which is exactly what an unguarded
# AND-list would do under `set -e`. Both functions below keep to that.
#
# teardown_routing() is everything that CARRIES traffic: the gate, the policy
# rules and the tunnel table. It is separate from teardown() because a paired
# box with an empty list must lose exactly this much and keep its interface.
teardown_routing() {
    local rc=0
    del_rules "$PREF_RETURN"
    del_rules "$PREF_CLIENT"
    del_rules "$PREF_SELF"
    ip route flush table "$RT_TABLE" 2>/dev/null || true
    if nft list set $NFT_TABLE "$SET" >/dev/null 2>&1; then
        nft flush set $NFT_TABLE "$SET" || { rc=1
            log "WARN: could not flush $NFT_TABLE $SET — the gate may still admit stale ranges"; }
    fi
    return "$rc"
}

teardown() {
    local rc=0
    teardown_routing || rc=1
    if ip link show "$IFACE" >/dev/null 2>&1; then
        ip link del "$IFACE" || { rc=1
            log "WARN: could not delete $IFACE — the tunnel may still be carrying traffic"; }
    fi
    return "$rc"
}

# Serialise. The broker restarts this unit on every list save and it is also
# WantedBy=multi-user.target, so two copies can overlap. That is not merely
# wasteful: copy B's `del_rules 90` can land between copy A's pref-90 add and
# its pref-100 loop, leaving precisely the pref-100-without-pref-90 lockout the
# ordering below exists to prevent.
LOCKFILE="$STATE_DIR/.trusted-egress.lock"
if [ -d "$STATE_DIR" ]; then
    exec 9>"$LOCKFILE"
    # A bounded wait, not an unbounded one: whoever holds the lock is applying
    # the same file this copy would, so the ranges themselves are never lost —
    # but THIS invocation's save still goes unapplied if the wait runs out, and
    # a dropped save stays dropped until a human reads `systemctl status`. Exit
    # 1, not 0, so that happens instead of a silent no-op; the unit's
    # Restart=on-failure gives the other copy a second chance to let this one
    # through before anyone has to look.
    if ! flock -w 30 9; then
        log "ERROR: another copy is still reconciling (lock $LOCKFILE) after 30s" \
            "— this save was NOT applied. Run" \
            "'systemctl start proteus-trusted-egress.service' once the other copy finishes."
        exit 1
    fi
else
    log "WARN: state dir $STATE_DIR is missing — running without the serialising lock"
fi

# A malformed PROTEUS_MGMT_CIDR would otherwise reach trusted.py, which treats
# an unparseable guard the same as "no ranges configured" (see validate()'s
# "management or client subnet is unconfigured or unparseable" branch) — and
# this script would then report "feature off", misstating a broken config as
# an operator choice. Catch it here, before trusted.py is even invoked, so the
# log names the real cause.
#
# A regex only checks shape, not validity: `172.20.0.0/33` and `999.1.1.1/24`
# both look like a CIDR to a pattern but are not valid networks, so ask
# Python's ipaddress module instead — the same library trusted.py itself uses
# to parse this value, so "valid here" and "valid there" cannot disagree.
if ! python3 -c '
import ipaddress, sys
try:
    ipaddress.IPv4Network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)' "$MGMT_CIDR" >/dev/null 2>&1; then
    teardown || true
    log "ERROR: PROTEUS_MGMT_CIDR '$MGMT_CIDR' is not a valid IPv4 CIDR (expected e.g. 10.0.0.0/24)." \
        "Leaving trusted-egress routing off until it is fixed."
    exit 0
fi

# Pass the guard subnets: with them, trusted.py applies the SAME rules the web
# UI enforces, so a hand-edited trusted.json cannot name the management subnet
# or the client VLAN and have this script route it.
#
# The exit status is captured separately from the output, because the two mean
# different things. trusted.py returns 0 and an empty list for a file that is
# absent, malformed or invalid — those genuinely are "the feature is off". A
# non-zero status means the tool itself could not run, and tearing a working
# tunnel down over a transient python failure would invent an operator decision
# nobody made: losing the configuration is not the same as being told there is
# none.
CIDRS=$(python3 "$BIN/trusted.py" list --file "$TRUSTED_FILE" \
            --mgmt-cidr "$MGMT_CIDR" --client-cidr "$CLIENT_VLAN_CIDR" \
            2>/dev/null) && LIST_RC=0 || LIST_RC=$?

if [ "$LIST_RC" -ne 0 ]; then
    # Non-zero, unlike the states below: this is a broken tool rather than a
    # configuration choice, and it should be visible in `systemctl status`.
    log "ERROR: could not read $TRUSTED_FILE — trusted.py exited $LIST_RC." \
        "Leaving the data path exactly as it is; nothing was changed."
    exit 1
fi

# A pairing is BOTH halves — our own private key and the UDM's public key — and
# without both there is nothing for an interface to do: no peer means no
# handshake, so a tunnel would sit there looking live and pass nothing. This is
# also the only state that removes the interface, which is what makes deleting
# peer.pub a working revocation: the link goes, and every peer it carried with
# it.
#
# -s, not -r: a zero-byte key passes a readability test and then dies inside
# `wg set` after the interface already exists, leaving an address-less, down
# interface and no explanation.
if [ ! -s "$KEY_DIR/server.key" ] || [ ! -s "$KEY_DIR/peer.pub" ]; then
    teardown || true
    if [ -n "$CIDRS" ]; then
        log "trusted ranges are configured but this box is not paired with a UDM yet" \
            "— generate a pairing in the web UI (Settings -> UDM tunnel). Data path left off."
    else
        log "no trusted ranges configured and no UDM pairing — feature off, data path torn down"
    fi
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    log "must run as root (writes the live ruleset, routes and the tunnel)"
    exit 1
fi

PROTEUS_TUNNEL_IP=$(python3 "$BIN/trusted.py" addr --cidr "$TUNNEL_CIDR" --which proteus)
TUNNEL_PREFIX="${TUNNEL_CIDR##*/}"

# ---------------------------------------------------------------------------
# 1. The tunnel interface. Created if absent, otherwise reconfigured in place so
#    a list edit never bounces a working tunnel.
#
#    The peer's allowed-ips is the argument because it is the one part that
#    differs between a box with ranges and one still being verified. It is a
#    second, independent gate on accepted sources: WireGuard's cryptokey routing
#    drops anything outside it before nftables ever sees the packet, so both must
#    permit a range for it to work.
# ---------------------------------------------------------------------------
bring_up_tunnel() {
    local allowed=${1:?allowed-ips required} peer p
    ip link show "$IFACE" >/dev/null 2>&1 || ip link add "$IFACE" type wireguard
    wg set "$IFACE" listen-port "$TUNNEL_PORT" private-key "$KEY_DIR/server.key"

    peer=$(cat "$KEY_DIR/peer.pub")
    wg set "$IFACE" peer "$peer" allowed-ips "$allowed"
    # `wg set ... peer` adds or updates ONLY the peer it names; it never removes
    # the others. Without this loop, re-pairing would leave the PREVIOUS peer
    # configured, and because @trusted_src still admits its ranges the supposedly
    # revoked key would keep working forever — the opposite of what the UI
    # promises when it says a new pairing invalidates the old one.
    for p in $(wg show "$IFACE" peers 2>/dev/null || true); do
        if [ "$p" != "$peer" ]; then
            log "revoking superseded tunnel peer $p"
            wg set "$IFACE" peer "$p" remove || log "WARN: could not remove peer $p"
        fi
    done

    ip addr replace "$PROTEUS_TUNNEL_IP/$TUNNEL_PREFIX" dev "$IFACE"
    # 1420 to match the Proton tunnels, so the forward chain's existing `rt mtu`
    # MSS clamp yields the right value in the return direction. It also sidesteps
    # a known UniFi bug: wgclt interfaces are not MSS-clamped by the UDM, and the
    # usual workaround needs SSH, which this UDM does not expose.
    ip link set mtu "$TUNNEL_MTU" dev "$IFACE"
    ip link set "$IFACE" up
}

# Paired, but nothing to route yet: bring the tunnel up and stop there. This is
# the state the rollout runs in — pair, confirm the handshake, watch what
# arrives, THEN configure a range — and it forwards exactly as much as an
# unpaired box does, which is nothing: the gate set stays empty, no policy rule
# is installed, table 110 stays empty and no namespace gets a return route.
if [ -z "$CIDRS" ]; then
    teardown_routing || true
    bring_up_tunnel "$TUNNEL_CIDR"
    log "$IFACE is up for pairing verification, but NO trusted ranges are configured," \
        "so nothing is routed through it yet. Confirm the peer with 'wg show $IFACE'," \
        "then watch what arrives with 'tcpdump -ni $IFACE'. Only $TUNNEL_CIDR is" \
        "admitted until a range is configured, so a UDM that does NOT masquerade" \
        "shows rising rx counters and no packets — that answer is the one that" \
        "decides which range to add in the web UI (Settings -> Trusted ranges)."
    exit 0
fi

# proteus' own address inside the management subnet, which the pref-90 rule is
# built from. Determined here, before a single piece of routing state is
# written, because that rule is the ONLY thing keeping this box's own replies —
# the web UI answering a browser on a trusted VLAN among them — out of the
# tunnel. Installing the pref-100 return rules without it produces exactly the
# lockout pref 90 exists to prevent, so "no address" means the whole feature
# stays off rather than half-applied.
MGMT_IP=$(ip -4 -o addr show 2>/dev/null | PYTHONPATH="$BIN" python3 -c '
import sys, trusted
print(trusted.mgmt_ip_from(sys.stdin.read(), sys.argv[1]) or "")' "$MGMT_CIDR" 2>/dev/null || true)

if [ -z "$MGMT_IP" ]; then
    teardown || true
    log "no address found inside $MGMT_CIDR — leaving trusted-egress routing off." \
        "That address is what pins this box's own replies to the main table;" \
        "installing the return rules without it would make the web UI unreachable" \
        "from a trusted VLAN. Check PROTEUS_MGMT_CIDR against this box's addresses."
    # Exit 0: this is a configuration state, not a crash, and a oneshot that
    # fails at boot is noisier than it is useful.
    exit 0
fi

ALLOWED="$TUNNEL_CIDR"
for c in $CIDRS; do ALLOWED="$ALLOWED,$c"; done
bring_up_tunnel "$ALLOWED"

# ---------------------------------------------------------------------------
# 2. The nft set. Flush and repopulate in one transaction so the gate is never
#    momentarily open on a stale range or shut on a live one.
# ---------------------------------------------------------------------------
if nft list set $NFT_TABLE "$SET" >/dev/null 2>&1; then
    {
        printf 'flush set %s %s\n' "$NFT_TABLE" "$SET"
        # The tunnel subnet is added by us, not by the operator: if the UDM
        # masquerades into the tunnel every trusted host arrives as the tunnel
        # address, and without this the feature would silently do nothing.
        printf 'add element %s %s { %s }\n' "$NFT_TABLE" "$SET" "$TUNNEL_CIDR"
        for c in $CIDRS; do
            printf 'add element %s %s { %s }\n' "$NFT_TABLE" "$SET" "$c"
        done
    } | nft -f -
else
    log "set $NFT_TABLE $SET not present (nftables not loaded?) — tunnel up, gate not applied"
fi

# ---------------------------------------------------------------------------
# 3. Return routing.
#
# The ordering here is the whole trick. A plain `route add <trusted> dev wg-udm`
# in the main table would also capture proteus' OWN replies to a trusted host —
# including the web UI answering the admin desktop — and send them down a tunnel
# the request never came from. So the tunnel route lives in its own table, and
# pref 90 pins everything proteus originates to the main table first. Reaching
# this point at all means MGMT_IP is known: the gate above refuses to route
# anything when it is not.
# ---------------------------------------------------------------------------
del_rules "$PREF_RETURN"
del_rules "$PREF_CLIENT"
del_rules "$PREF_SELF"
ip route flush table "$RT_TABLE" 2>/dev/null || true

ip rule add from "$MGMT_IP" lookup main pref "$PREF_SELF"

for c in $CIDRS; do
    ip route replace "$c" dev "$IFACE" table "$RT_TABLE"
    # The pref-100 rule below matches on DESTINATION alone, so it captures any
    # source headed for this range — the client VLAN included. That would push a
    # client-VLAN host talking to a trusted host into the tunnel instead of out
    # the management interface, breaking the transit @client_pivot exists to
    # allow when isolation is open (and dropping it outright when it is closed,
    # since the tunnel has no route back to the client VLAN). So pin that pair,
    # and only that pair, to the main table ahead of it.
    #
    # `to "$c"` is load-bearing, not decoration. `from $CLIENT_VLAN_CIDR lookup
    # main` on its own matches EVERY packet the client VLAN sends anywhere, and
    # main's own default route resolves it — so rule evaluation stops at this
    # priority and never reaches the `fwmark N lookup 10N` rules at 500+N where
    # each slot's default route lives. The packet keeps its mark, the forward
    # chain accepts it on that mark alone, and client egress leaves over the
    # management interface with the VPN bypassed entirely: the kill-switch
    # failure this system exists to prevent, reached by failing open. Scoped by
    # destination it can only divert traffic aimed at a range the operator
    # named, and those are RFC1918, which prerouting_mangle returns on before
    # marking anything — so it cannot collide with dispatch either.
    ip rule add from "$CLIENT_VLAN_CIDR" to "$c" lookup main pref "$PREF_CLIENT"
    ip rule add to "$c" lookup "$RT_TABLE" pref "$PREF_RETURN"
done

# ---------------------------------------------------------------------------
# 4. Return routes inside the slot namespaces, so a list edit takes effect
#    without waiting for each slot's next rotation. vpnns-up.sh does the same
#    for a slot it is bringing up.
# ---------------------------------------------------------------------------
for state in "$STATE_DIR"/proton-*.state; do
    [ -r "$state" ] || continue
    (
        # shellcheck disable=SC1090
        . "$state"
        # Any of these missing would trip `set -u` inside this subshell, and the
        # `|| true` below would swallow it — that slot would silently never get
        # a return route. Name the file instead.
        if [ -z "${NS:-}" ] || [ -z "${VETH_NS:-}" ] || [ -z "${TRANSIT_MAIN:-}" ]; then
            log "skipping $state: no NS, VETH_NS or TRANSIT_MAIN in it"
            exit 0
        fi
        ip netns list | awk '{print $1}' | grep -qxF "$NS" || exit 0
        for c in $CIDRS $TUNNEL_CIDR; do
            ip -n "$NS" route replace "$c" via "$TRANSIT_MAIN" dev "$VETH_NS" || true
        done
    ) || true
done

log "applied: $(echo "$CIDRS" | tr '\n' ' ')(+$TUNNEL_CIDR) via $IFACE, table $RT_TABLE"
