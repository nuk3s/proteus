#!/bin/bash
# Periodic check — if the RTT from ns-dns-6 to Quad9 is above threshold,
# trigger rotate-dns.sh. Rotate-dns.sh has its own cooldown so safe to call
# from a tight timer.
set -euo pipefail

# Threshold applies to a TCP dig transaction (connect + query ≈ 2×RTT), not
# an ICMP average — hence higher than the old 120ms ping threshold.
THRESHOLD_MS=${THRESHOLD_MS:-300}
TARGET=${TARGET:-9.9.9.9}
# Neutral reference for distinguishing "tunnel dead" from "Quad9 unreachable"
# when the probe fails. Not a resolver choice — purely a liveness beacon.
REFERENCE_IP=${REFERENCE_IP:-1.1.1.1}

# DNS netns name from the installer env; fall back to production's ns-dns-6.
[[ -r /etc/proteus/proteus.env ]] && source /etc/proteus/proteus.env
NS="ns-${PROTEUS_DNS_INSTANCE:-dns-6}"

log() { printf "[%(%FT%T%z)T] dns-latency-check: %s\n" -1 "$*" >&2; }

if ! ip netns list | grep -q "^${NS}\b"; then
    log "$NS does not exist — nothing to check"
    exit 0
fi

# Probe the path clients actually use: a TCP query to Quad9, mirroring the
# DoT (tcp/853) forwarding in unbound. Quad9 rate-limits UDP/53 and ICMP per
# exit IP under sustained volume — a UDP/ICMP-dark exit is NOT a dead tunnel
# (TCP keeps working) and must not trigger rotation; pinging here caused ~18
# spurious rotations/day, each wiping unbound's cache.
qt=$(ip netns exec "$NS" dig +tcp @"$TARGET" +time=3 +tries=1 . NS 2>/dev/null \
     | awk '/Query time:/{print $4}') || qt=""

if [[ -z "$qt" ]]; then
    # TCP to Quad9 failed. Either way the client DNS path through this exit
    # is unusable, so rotate — but log which failure mode it was.
    if ip netns exec "$NS" ping -c 3 -i 0.3 -W 2 -q "$REFERENCE_IP" >/dev/null 2>&1; then
        log "Quad9 TCP unreachable through $NS but tunnel alive ($REFERENCE_IP ok) — triggering rotation"
    else
        log "tunnel dead ($TARGET tcp and $REFERENCE_IP both unreachable) — triggering rotation"
    fi
    exec /etc/proteus/bin/rotate-dns.sh
fi

log "$NS -> $TARGET tcp query_time=${qt}ms threshold=${THRESHOLD_MS}ms"

if (( qt > THRESHOLD_MS )); then
    log "latency above threshold — triggering rotation"
    exec /etc/proteus/bin/rotate-dns.sh
fi

exit 0
