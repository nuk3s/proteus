#!/usr/bin/env bash
# Tear down a VPN instance namespace.
# Usage: vpnns-down.sh <instance-name>
set -euo pipefail

INSTANCE="${1:?instance required}"
NS="ns-${INSTANCE}"
VETH_MAIN="v-${INSTANCE}"
STATE_FILE="/etc/proteus/state/${INSTANCE}.state"
NETNS_CONF_DIR="/etc/netns/${NS}"

# shellcheck source=/dev/null
. "$(dirname "${BASH_SOURCE[0]}")/routeguard.sh"
# First, before anything is removed: the catch rule covers a mark whose slot
# has no state file (never came up, or already down), and the ingress sink
# covers a flow that has lost its mark. Non-fatal: teardown must complete.
rg_catch_ensure || echo "WARN: catch rule not installed" >&2
rg_sink_ensure || echo "WARN: ingress sink incomplete" >&2

if [[ -r "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    # A stopped slot must fail CLOSED (see routeguard.sh). Existing flows keep
    # their conntrack mark, and the dispatcher's pins keep handing the mark to
    # new flows until they expire. Before this fix, the rule and table were
    # deleted here, so all of that traffic fell through to `main` and left by
    # the uplink for as long as the slot stayed down. That covered the first
    # half of every `systemctl restart`, and every rotate-dns.sh swap.
    # Now:
    #   - the sentinel goes in first;
    #   - only the tunnel route is removed (`via` makes the delete specific);
    #   - the fwmark and source rules are KEPT, pointing at a table that now
    #     holds only the blackhole sentinel.
    # vpnns-up.sh re-adds the route, and treats the surviving rules as already
    # present. Leftover rules for a slot that never comes back are harmless:
    # they route nothing anywhere.
    if [[ -n "${RT_TABLE:-}" ]]; then
        rg_sentinel_ensure "$RT_TABLE" \
            || echo "WARN: sentinel not installed in table $RT_TABLE; relying on the catch rule and firewall" >&2
        if [[ -n "${TRANSIT_NS:-}" ]]; then
            ip route del default via "$TRANSIT_NS" table "$RT_TABLE" 2>/dev/null || true
        fi
    fi
    if [[ -n "${WG_ENDPOINT_IP:-}" ]]; then
        nft "delete element inet filter wg_peers { ${WG_ENDPOINT_IP} }" 2>/dev/null || true
    fi
fi

ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_MAIN" 2>/dev/null || true
rm -f "$STATE_FILE"
rm -rf "$NETNS_CONF_DIR"
echo "DOWN: ${INSTANCE}"
