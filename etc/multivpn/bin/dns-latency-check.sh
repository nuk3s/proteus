#!/bin/bash
# Periodic check — if the RTT from ns-dns-6 to Quad9 is above threshold,
# trigger rotate-dns.sh. Rotate-dns.sh has its own cooldown so safe to call
# from a tight timer.
set -euo pipefail

THRESHOLD_MS=${THRESHOLD_MS:-120}
TARGET=${TARGET:-9.9.9.9}

# DNS netns name from the installer env; fall back to production's ns-dns-6.
[[ -r /etc/multivpn/multivpn.env ]] && source /etc/multivpn/multivpn.env
NS="ns-${MULTIVPN_DNS_INSTANCE:-dns-6}"

log() { printf "[%(%FT%T%z)T] dns-latency-check: %s\n" -1 "$*" >&2; }

if ! ip netns list | grep -q "^${NS}\b"; then
    log "$NS does not exist — nothing to check"
    exit 0
fi

# 5 pings, 0.3s interval, 2s wait. ~1.5s total.
avg=$(ip netns exec "$NS" ping -c 5 -i 0.3 -W 2 -q "$TARGET" 2>/dev/null | awk -F/ "/^rtt/{printf \"%d\", \$5}") || avg=""

if [[ -z "$avg" ]]; then
    log "ping to $TARGET through $NS failed entirely — triggering rotation"
    exec /etc/multivpn/bin/rotate-dns.sh
fi

log "$NS -> $TARGET avg=${avg}ms threshold=${THRESHOLD_MS}ms"

if (( avg > THRESHOLD_MS )); then
    log "latency above threshold — triggering rotation"
    exec /etc/multivpn/bin/rotate-dns.sh
fi

exit 0
