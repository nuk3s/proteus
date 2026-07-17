#!/usr/bin/env bash
# Rotate a multivpn slot to a freshly-minted Proton WG config.
#
# Usage: rotate-slot.sh <slot>      e.g. proton-1
#
# Flow (per attempt; up to MAX_ATTEMPTS):
#   1. Mint a new WG config via proton-mint.
#   2. Stage it in a parallel namespace ($slot-s) at index +100.
#   3. Verify handshake + basic TLS egress in the staging namespace.
#   4. Run reputation-probe.sh inside the staging ns.
#   5. If probe fails: tear down staging, delete the config, loop.
# After a successful attempt:
#   6. Promote: replace the live slot via vpnns-up (idempotent in-place
#      reconfigure), SIGHUP the dispatcher.
#   7. Prune old auto-mints for this slot (keep newest 2 as rollback).
#
# Exit codes:
#   0  rotated successfully
#   1  bad args / preconditions
#   2  all mint attempts failed (see MAX_ATTEMPTS)
#   5  promote failed (should not happen — preconditions validated in staging)
set -euo pipefail

SLOT="${1:?slot required, e.g. proton-1}"
[[ "$SLOT" =~ ^proton-([1-9][0-9]?)$ ]] || {
    echo "slot must match proton-N (1-99): $SLOT" >&2
    exit 1
}
SLOT_IDX="${BASH_REMATCH[1]}"
# Staging uses a short suffix (-s) to stay under the 15-char veth name limit:
#   v-proton-1-s-ns = 15 chars, OK; v-proton-1-new-ns = 16, rejected.
STAGE_NAME="${SLOT}-s"
STAGE_IDX=$((100 + SLOT_IDX))
STAGE_NS="ns-${STAGE_NAME}"

MAX_ATTEMPTS="${MAX_ATTEMPTS:-5}"
RETRY_SLEEP="${RETRY_SLEEP:-3}"
AUTO_DIR="/etc/multivpn/wg/proton/auto"
LOG_TAG="rotate-${SLOT}"
# Streaming gate: reject an exit that can't sustain streaming-grade bandwidth so
# every promoted slot is streaming-capable. 4K needs ~25 Mbps; surveyed exits do
# 44-289, so this rarely bites but stops the occasional dud. 25 MB probe (1 MB
# rides slow-start; see the throughput-probe-artifact findings).
STREAMING_MIN_MBPS="${STREAMING_MIN_MBPS:-25}"
TPUT_URL="https://speed.cloudflare.com/__down?bytes=26214400"

log() { logger -t "$LOG_TAG" -- "$*"; echo "[$(date -Iseconds)] $*"; }

# Best-of-two sustained throughput (Mbps) through a staging ns. Two pulls: the
# first hit to a fresh exit rides slow-start + the cold-catch, the second
# reaches steady state. Echoes the better value, or empty if neither pull
# downloaded enough to measure (caller treats empty as "unknown, don't block").
measure_throughput() {
    local ns=$1 best="" i out size t mbps
    for i in 1 2; do
        out=$(ip netns exec "$ns" curl -s -o /dev/null --connect-timeout 8 \
              --max-time 30 -w "%{size_download} %{time_total}" "$TPUT_URL" 2>/dev/null)
        size=$(awk '{print $1+0}' <<<"$out"); t=$(awk '{print $2+0}' <<<"$out")
        if awk -v s="$size" -v tt="$t" 'BEGIN{exit !(s>1000000 && tt>0)}'; then
            mbps=$(awk -v s="$size" -v tt="$t" 'BEGIN{printf "%.1f",(s*8)/(tt*1000000)}')
            if [[ -z "$best" ]] || awk -v a="$mbps" -v b="$best" 'BEGIN{exit !(a>b)}'; then
                best=$mbps
            fi
        fi
    done
    printf '%s' "$best"
}

mkdir -p "$AUTO_DIR"
chmod 700 "$AUTO_DIR"

# Always refresh Proton API whitelist once per rotation (cheap, idempotent).
log "starting rotation for slot=$SLOT stage=$STAGE_NAME idx=$STAGE_IDX max_attempts=$MAX_ATTEMPTS"
systemctl start multivpn-proton-api-whitelist.service || {
    log "WARN: proton-api-whitelist service failed — continuing with cached set"
}

cleanup_staging() {
    /etc/multivpn/bin/vpnns-down.sh "$STAGE_NAME" >/dev/null 2>&1 || true
}

# Each attempt: mint -> stage -> verify tunnel -> reputation probe.
# On any failure: clean up this attempt's artifacts and continue loop.
# On success: break with $good_conf set.
good_conf=""
good_exit_ip=""
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    log "attempt $attempt/$MAX_ATTEMPTS"

    # 1) Mint
    if ! new_conf=$(/etc/multivpn/bin/proton-mint --slot "$SLOT" --out-dir "$AUTO_DIR"); then
        log "attempt $attempt: mint failed (rc=$?)"
        sleep "$RETRY_SLEEP"; continue
    fi
    if [[ -z "$new_conf" || ! -r "$new_conf" ]]; then
        log "attempt $attempt: mint returned no readable path: '$new_conf'"
        sleep "$RETRY_SLEEP"; continue
    fi
    log "minted: $new_conf"

    # 1b) Endpoint-collision dedup. Two slots ending up on the same Proton
    # physical server share an exit IP (privacy regression) AND seem to share
    # exit-side flow-state, which degrades warmup-keepalive success and
    # causes user-visible cold-SYN drops on the colliding slots. Reject any
    # mint whose endpoint IP matches a sibling proton-N slot and retry.
    new_endpoint=$(awk -F'[ =:]+' '/^Endpoint = / {print $2; exit}' "$new_conf")
    if [[ -z "$new_endpoint" ]]; then
        log "attempt $attempt: could not parse Endpoint from $new_conf"
        rm -f "$new_conf"; sleep "$RETRY_SLEEP"; continue
    fi
    collision=""
    for state in /etc/multivpn/state/proton-*.state; do
        [[ -r "$state" ]] || continue
        sibling=$(basename "$state" .state)
        [[ "$sibling" == "$SLOT" ]] && continue
        # Only compare against rotating-pool slots; skip dns-N and -s staging.
        [[ "$sibling" =~ ^proton-[0-9]+$ ]] || continue
        sibling_ep=$(awk -F= '/^WG_ENDPOINT_IP=/ {print $2; exit}' "$state")
        if [[ "$sibling_ep" == "$new_endpoint" ]]; then
            collision="$sibling"
            break
        fi
    done
    if [[ -n "$collision" ]]; then
        log "attempt $attempt: endpoint $new_endpoint collides with $collision — discarding and retrying"
        rm -f "$new_conf"; sleep "$RETRY_SLEEP"; continue
    fi

    # 2) Stage
    if ! /etc/multivpn/bin/vpnns-up.sh "$STAGE_NAME" "$new_conf" "$STAGE_IDX"; then
        log "attempt $attempt: staging vpnns-up failed"
        rm -f "$new_conf"
        sleep "$RETRY_SLEEP"; continue
    fi

    # 3) Handshake + egress (warms tunnel for probe)
    handshake_ok=0
    for i in {1..10}; do
        sleep 2
        hs=$(ip netns exec "$STAGE_NS" wg show wg0 latest-handshakes 2>/dev/null \
             | awk '{print $2}' | head -n1)
        if [[ -n "${hs:-}" && "$hs" -gt 0 ]]; then
            age=$(( $(date +%s) - hs ))
            (( age < 60 )) && { handshake_ok=1; log "handshake ok (${age}s ago) after $((i*2))s"; break; }
        fi
    done
    if (( handshake_ok == 0 )); then
        log "attempt $attempt: no handshake in 20s"
        cleanup_staging; rm -f "$new_conf"; sleep "$RETRY_SLEEP"; continue
    fi

    if ! trace=$(ip netns exec "$STAGE_NS" timeout 45 curl -sS \
        --retry 3 --retry-all-errors --retry-delay 2 --max-time 12 \
        https://checkip.amazonaws.com 2>&1); then
        log "attempt $attempt: egress probe failed: $trace"
        cleanup_staging; rm -f "$new_conf"; sleep "$RETRY_SLEEP"; continue
    fi
    # checkip.amazonaws.com returns the source IP in plain text. On a clean run
    # $trace is just that IP; but when curl's --retry papers over a flaky tunnel
    # (cold-catch / transient loss), $trace also carries the retry error lines.
    # Pull the last IP-looking token out of the whole blob (the successful
    # response follows the retries), and `|| true` so a no-match doesn't trip
    # `set -e` and kill the rotation with no cleanup.
    exit_ip=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<<"$trace" | tail -n1 || true)
    if [[ -z "$exit_ip" ]]; then
        log "attempt $attempt: trace ok but no ip= field"
        cleanup_staging; rm -f "$new_conf"; sleep "$RETRY_SLEEP"; continue
    fi
    log "staging egress ip=$exit_ip"

    # 4) Reputation probe
    if ! probe_out=$(/etc/multivpn/bin/reputation-probe.sh "$STAGE_NS" 2>&1); then
        # FAIL — discard and try again
        probe_verdict=$(grep -E "^VERDICT " <<<"$probe_out" | head -n1)
        log "attempt $attempt: reputation probe failed ($exit_ip): $probe_verdict"
        echo "$probe_out" | while IFS= read -r line; do log "  $line"; done
        cleanup_staging; rm -f "$new_conf"; sleep "$RETRY_SLEEP"; continue
    fi

    probe_verdict=$(grep -E "^VERDICT " <<<"$probe_out" | head -n1)
    log "attempt $attempt: reputation probe OK ($exit_ip): $probe_verdict"

    # 5) Streaming gate — every promoted slot must sustain streaming-grade
    #    bandwidth. Unmeasurable throughput (speed probe unreachable) passes on
    #    the reputation result rather than blocking rotation on a transient.
    tput=$(measure_throughput "$STAGE_NS")
    if [[ -z "$tput" ]]; then
        log "attempt $attempt: throughput unmeasurable — passing on reputation alone"
    elif awk -v t="$tput" -v m="$STREAMING_MIN_MBPS" 'BEGIN{exit !(t>=m)}'; then
        log "attempt $attempt: throughput ${tput} Mbps >= ${STREAMING_MIN_MBPS} (streaming-capable)"
    else
        log "attempt $attempt: throughput ${tput} Mbps < ${STREAMING_MIN_MBPS} — rejecting exit"
        cleanup_staging; rm -f "$new_conf"; sleep "$RETRY_SLEEP"; continue
    fi

    good_conf="$new_conf"
    good_exit_ip="$exit_ip"
    break
done

if [[ -z "$good_conf" ]]; then
    log "ERR: all $MAX_ATTEMPTS attempts failed — leaving current slot untouched"
    exit 2
fi

# 5/6) Promote: teardown staging, replace live slot, SIGHUP dispatcher.
cleanup_staging

old_conf=""
if [[ -r "/etc/multivpn/state/${SLOT}.state" ]]; then
    old_conf=$(awk -F= '/^WG_CONF=/ {print $2; exit}' "/etc/multivpn/state/${SLOT}.state")
fi

if ! /etc/multivpn/bin/vpnns-up.sh "$SLOT" "$good_conf"; then
    log "ERR: promote vpnns-up failed — slot may be degraded"
    exit 5
fi

systemctl kill --signal=HUP multivpn-dispatcher.service 2>/dev/null || \
    log "WARN: dispatcher SIGHUP failed (not running?)"

ln -sfn "$good_conf" "${AUTO_DIR}/${SLOT}.conf"
log "promoted $SLOT -> $good_conf (exit_ip=$good_exit_ip)"

# 7) Prune — keep newest 2 auto-mints per slot.
mapfile -t stale < <(
    ls -1t "${AUTO_DIR}/${SLOT}-"*.conf 2>/dev/null | tail -n +3
)
for f in "${stale[@]}"; do
    [[ "$f" == "$good_conf" || "$f" == "$old_conf" ]] && continue
    rm -f -- "$f"
    log "pruned $f"
done

exit 0
