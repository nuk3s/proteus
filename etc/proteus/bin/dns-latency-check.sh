#!/bin/bash
# Periodic check — if the RTT from ns-dns-6 to the in-tunnel resolver is above
# threshold, trigger rotate-dns.sh. Rotate-dns.sh has its own cooldown so safe
# to call from a tight timer.
set -euo pipefail

# Proton's in-tunnel NetShield resolver: the exact address unbound forwards to,
# and the gateway address inside EVERY Proton WG tunnel, so it never needs
# updating when the DNS tunnel rotates. This must track unbound's forwarder —
# while it probed Quad9 (which unbound no longer uses) a Quad9 outage would
# rotate a perfectly healthy tunnel, and a genuinely broken client-DNS path
# would go undetected.
TARGET=${TARGET:-10.2.0.1}
# Neutral off-tunnel reference, used only when the probe fails. Now the single
# most important signal here: 10.2.0.1 is unreachable BY DEFINITION when the
# tunnel is down, so this ping is the only way to tell "tunnel dead" from
# "resolver sick". Both rotate, but the log line has to say which. Not a
# resolver choice — purely a liveness beacon.
REFERENCE_IP=${REFERENCE_IP:-1.1.1.1}

# DNS netns name from the installer env; fall back to production's ns-dns-6.
[[ -r /etc/proteus/proteus.env ]] && source /etc/proteus/proteus.env
# UI-set overrides survive installer re-runs
[ -f /etc/proteus/proteus-local.env ] && . /etc/proteus/proteus-local.env
NS="ns-${PROTEUS_DNS_INSTANCE:-dns-6}"
# Threshold applies to a single UDP dig transaction (≈1×RTT). It was 300ms,
# sized for a TCP transaction (connect + query ≈ 2×RTT) over a ~220ms Quad9
# path; against the in-tunnel resolver's measured 11-16ms, 300 could NEVER fire
# and rotation-on-degradation would have silently stopped working. Worst
# measured exit was 71ms, so 150 leaves ~2x headroom. Read after the overlay
# source so a UI-set PROTEUS_DNS_LATENCY_THRESHOLD_MS takes effect; the bare
# THRESHOLD_MS still works for ad-hoc CLI overrides.
THRESHOLD_MS="${PROTEUS_DNS_LATENCY_THRESHOLD_MS:-${THRESHOLD_MS:-150}}"

log() { printf "[%(%FT%T%z)T] dns-latency-check: %s\n" -1 "$*" >&2; }

if ! ip netns list | grep -q "^${NS}\b"; then
    log "$NS does not exist — nothing to check"
    exit 0
fi

# Probe the path clients actually use: a plain UDP query to the tunnel's own
# resolver, mirroring unbound's forward-zone. UDP, not TCP — measured 11ms UDP
# vs 27ms TCP, and there is no rate limiter to dodge: Proton does not police its
# own gateway address and the query never leaves the tunnel. (The +tcp used to
# be load-bearing because Quad9 rate-limits UDP/53 and ICMP per exit IP under
# sustained volume, so a UDP/ICMP-dark exit was NOT a dead tunnel and pinging
# here caused ~18 spurious rotations/day, each wiping unbound's cache. If TARGET
# is ever pointed back at a public resolver, put +tcp back.)
# `. NS` stays as the query: verified against 10.2.0.1 as NOERROR, 13 root NS
# records, 431 bytes — no truncation over UDP.
# CAVEAT: 10.2.0.1 is the far end of the WireGuard tunnel, so this now measures
# tunnel RTT only, not internet-wide path quality. An exit whose tunnel is
# healthy but whose upstream transit is poor will pass this check.
qt=$(ip netns exec "$NS" dig @"$TARGET" +time=3 +tries=1 . NS 2>/dev/null \
     | awk '/Query time:/{print $4}') || qt=""

if [[ -z "$qt" ]]; then
    # No answer from the in-tunnel resolver. Either way the client DNS path
    # through this exit is unusable, so rotate — but log which failure mode it
    # was, because "tunnel dead" and "resolver sick" look identical from here.
    if ip netns exec "$NS" ping -c 3 -i 0.3 -W 2 -q "$REFERENCE_IP" >/dev/null 2>&1; then
        log "in-tunnel resolver $TARGET unreachable through $NS but tunnel alive ($REFERENCE_IP ok) — triggering rotation"
    else
        log "tunnel dead ($TARGET and $REFERENCE_IP both unreachable) — triggering rotation"
    fi
    exec /etc/proteus/bin/rotate-dns.sh
fi

log "$NS -> $TARGET udp query_time=${qt}ms threshold=${THRESHOLD_MS}ms"

if (( qt > THRESHOLD_MS )); then
    log "latency above threshold — triggering rotation"
    exec /etc/proteus/bin/rotate-dns.sh
fi

exit 0
