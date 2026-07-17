#!/usr/bin/env bash
# Tear down a VPN instance namespace.
# Usage: vpnns-down.sh <instance-name>
set -euo pipefail

INSTANCE="${1:?instance required}"
NS="ns-${INSTANCE}"
VETH_MAIN="v-${INSTANCE}"
STATE_FILE="/etc/multivpn/state/${INSTANCE}.state"
NETNS_CONF_DIR="/etc/netns/${NS}"

if [[ -r "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    ip rule del fwmark "${FWMARK:-}" lookup "${RT_TABLE:-}" 2>/dev/null || true
    ip rule del from "${TRANSIT_MAIN:-0.0.0.0}" lookup "${RT_TABLE:-}" 2>/dev/null || true
    ip route flush table "${RT_TABLE:-}" 2>/dev/null || true
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
