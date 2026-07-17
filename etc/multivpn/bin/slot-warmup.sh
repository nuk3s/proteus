#!/bin/bash
# Fire a short TLS hit to proton.me through every rotating-pool slot, IN PARALLEL,
# to keep Proton's exit-side NAT/flow state warm. Without this, the first client
# SYN through an idle slot gets dropped and takes 10-20s of TCP retries. proton.me
# is the warmup target because Proton already sees the WG handshake every 25s
# (PersistentKeepalive) -- no third party involved.
#
# Each pass also writes a per-slot health state file under
# /run/multivpn-slot-health/<slot>.state. The dispatcher reads these and
# skips DEGRADED slots when picking a new flow's destination — so a slot
# that's currently failing warmup doesn't get fresh traffic mapped to it.
#
# When a slot has been DEGRADED long enough (FAIL_STREAK >= ROT_THRESHOLD
# and the cooldown has elapsed), this script also asks systemd to fire an
# unscheduled rotation for it.
set -u
LOG_TAG=slot-warmup
HEALTH_DIR=/run/multivpn-slot-health
# DNS netns name from the installer env; fall back to production's dns-6.
[[ -r /etc/multivpn/multivpn.env ]] && source /etc/multivpn/multivpn.env
DNS_NS="ns-${MULTIVPN_DNS_INSTANCE:-dns-6}"
DEGRADED_AFTER=2          # consecutive ALL_FAILs before a slot is DEGRADED
ROT_THRESHOLD=5           # consecutive ALL_FAILs before auto-rotation fires
ROT_COOLDOWN=300          # seconds between auto-rotation triggers per slot

# --- composite scoring (see the design notes)
JITTER_WINDOW_SAMPLES=15                                                   # ~5min @20s passes
# Throughput probe: 25 MB, not 1 MB. A 1 MB download completes inside TCP
# slow-start over the tunnel RTT and reports ~15 Mbps for an exit that sustains
# 120+; 25 MB reaches steady state (see
# the design notes).
# The bigger pull is ~25x the bytes, so probe far less often — capacity is
# stable, so once per slot every ~50 min is ample and keeps daily probe traffic
# to a few GB. (EVERY_N=60 passes x 10s = one slot probed per 10 min, cycling
# 5 slots -> each ~every 50 min.)
THROUGHPUT_EVERY_N_PASSES=60
THROUGHPUT_TARGET_URL="https://speed.cloudflare.com/__down?bytes=26214400"
THROUGHPUT_TIMEOUT_S=30
PASS_COUNTER_FILE="$HEALTH_DIR/.pass-counter"

# shellcheck source=/dev/null
source /etc/multivpn/bin/scoring.sh

mkdir -p "$HEALTH_DIR"
chmod 0755 "$HEALTH_DIR"

# Read a single key=value field from a slot's health state file.
# Empty string if file or key is missing.
_health_get() {
    local file=$1 key=$2
    [[ -r "$file" ]] || { echo ""; return; }
    awk -F= -v k="$key" '$1==k {print $2; exit}' "$file"
}

# Write the slot's health state atomically and (if appropriate) trigger
# auto-rotation. Args: <inst> <outcome> <latency_ms> [<throughput_mbps>]
# where outcome is ok|warmed|all_fail. throughput is optional; if missing
# the previous value is retained.
_update_health() {
    local inst=$1 outcome=$2 latency_ms=${3:-0} throughput_mbps=${4:-}
    local file="$HEALTH_DIR/$inst.state"
    local hist_file="$HEALTH_DIR/$inst.lat-history"
    local now
    now=$(date +%s)

    local prev_streak prev_rot prev_tp
    prev_streak=$(_health_get "$file" FAIL_STREAK)
    prev_rot=$(_health_get "$file" LAST_ROT_TRIGGER_AT)
    prev_tp=$(_health_get "$file" THROUGHPUT_MBPS)
    : "${prev_streak:=0}"
    : "${prev_rot:=0}"

    local fail_streak status
    if [[ "$outcome" == "all_fail" ]]; then
        fail_streak=$((prev_streak + 1))
    else
        fail_streak=0
    fi
    if (( fail_streak >= DEGRADED_AFTER )); then
        status=degraded
    else
        status=ok
    fi

    # Decide whether to trigger auto-rotation BEFORE writing the file so the
    # write captures the new LAST_ROT_TRIGGER_AT.
    local rot_at=$prev_rot
    local triggered=0
    if (( fail_streak >= ROT_THRESHOLD )) && (( now - prev_rot > ROT_COOLDOWN )); then
        rot_at=$now
        triggered=1
    fi

    # Update latency history. Only first-try ("ok") successes represent
    # warm-path latency; a "warmed" retry's time_connect includes the cold
    # window and would poison the rolling mean/jitter (see scoring.sh
    # should_record_latency). On a skipped pass the ring is unchanged, so
    # mean/jitter carry forward the last N warm samples.
    local mean_lat=0 jitter=0 median_lat=0 mad=0
    if should_record_latency "$outcome" && [[ -n "$latency_ms" ]]; then
        update_lat_history "$hist_file" "$latency_ms" "$JITTER_WINDOW_SAMPLES"
    fi
    local hist=""
    [[ -r "$hist_file" ]] && hist=$(<"$hist_file")
    # median/MAD drive the score (robust to occasional cold-catch spikes);
    # mean/stddev are kept for observability — a large mean-vs-median gap is a
    # useful cold-catch-rate signal.
    mean_lat=$(compute_mean "$hist")
    jitter=$(compute_jitter "$hist")
    median_lat=$(compute_median "$hist")
    mad=$(compute_mad "$hist")

    # Throughput: use new value if measured this pass, else carry forward.
    local tp=${throughput_mbps:-$prev_tp}
    [[ -z "$tp" ]] && tp=0

    local score
    score=$(compute_score "$status" "$median_lat" "$mad" "$tp")

    local tmp="$file.tmp.$$"
    cat > "$tmp" <<EOF
INSTANCE=$inst
STATUS=$status
LAST_OUTCOME=$outcome
LAST_PASS_AT=$now
FAIL_STREAK=$fail_streak
LAST_ROT_TRIGGER_AT=$rot_at
LATENCY_MEAN_MS=$mean_lat
LATENCY_JITTER_MS=$jitter
LATENCY_MEDIAN_MS=$median_lat
LATENCY_MAD_MS=$mad
THROUGHPUT_MBPS=$tp
COMPOSITE_SCORE=$score
SCORE_UPDATED_AT=$now
EOF
    mv "$tmp" "$file"

    if (( triggered )); then
        logger -t "$LOG_TAG" "$inst auto-rotation triggered (fail_streak=$fail_streak)"
        systemctl start --no-block "multivpn-rotate-slot@$inst.service" || \
            logger -t "$LOG_TAG" "$inst auto-rotation failed to start"
    fi
}

# Args: <inst> [<run_throughput>]   run_throughput=1 means probe throughput too.
warm_one() {
    local inst=$1 run_tp=${2:-0}
    local ns=ns-$inst
    local out="" latency_ms=0 status_code="" connect_s=""
    local throughput_mbps=""

    # Multi-probe per pass (existing behavior).
    for try in 1 2 3; do
        out=$(ip netns exec "$ns" curl -s -o /dev/null -I \
              --connect-timeout 5 --max-time 6 \
              -w "code=%{http_code} connect=%{time_connect}s total=%{time_total}s" \
              https://proton.me/ 2>&1) || true
        case "$out" in
            *"code=2"*|*"code=3"*)
                # Extract connect time in seconds, convert to ms. If the
                # sed match fails (curl format drift or unusual output),
                # latency_ms stays empty so _update_health's guard skips
                # poisoning the lat-history with a fake 0.0 sample.
                connect_s=$(echo "$out" | sed -n 's/.*connect=\([0-9.]\+\)s.*/\1/p')
                if [[ -n "$connect_s" ]]; then
                    latency_ms=$(awk -v s="$connect_s" 'BEGIN{ printf "%.1f", s*1000 }')
                else
                    latency_ms=""
                fi

                # Throughput probe (only the slot picked for this pass).
                if (( run_tp )); then
                    local tp_out
                    tp_out=$(ip netns exec "$ns" curl -s -o /dev/null \
                            --connect-timeout 5 --max-time "$THROUGHPUT_TIMEOUT_S" \
                            -w "size=%{size_download} time=%{time_total}s" \
                            "$THROUGHPUT_TARGET_URL" 2>&1) || true
                    local size t
                    size=$(echo "$tp_out" | sed -n 's/.*size=\([0-9]\+\).*/\1/p')
                    t=$(   echo "$tp_out" | sed -n 's/.*time=\([0-9.]\+\)s.*/\1/p')
                    if [[ -n "$size" && -n "$t" ]] && awk -v t="$t" 'BEGIN{exit !(t>0)}'; then
                        # Mbps = (bytes * 8) / (seconds * 1e6)
                        throughput_mbps=$(awk -v sz="$size" -v t="$t" \
                            'BEGIN{ printf "%.2f", (sz * 8) / (t * 1000000) }')
                        logger -t "$LOG_TAG" "$inst throughput=$throughput_mbps Mbps ($size bytes / ${t}s)"
                    else
                        logger -t "$LOG_TAG" "$inst throughput probe failed: $tp_out"
                    fi
                fi

                if (( try > 1 )); then
                    logger -t "$LOG_TAG" "$inst try=$try (warmed) lat=${latency_ms}ms $out"
                    _update_health "$inst" warmed "$latency_ms" "$throughput_mbps"
                else
                    logger -t "$LOG_TAG" "$inst lat=${latency_ms}ms $out"
                    _update_health "$inst" ok "$latency_ms" "$throughput_mbps"
                fi
                return
                ;;
        esac
        sleep 1
    done
    logger -t "$LOG_TAG" "$inst ALL_FAIL last=$out"
    _update_health "$inst" all_fail
}

# Keep the dedicated DNS tunnel (dns-6) warm too. It's not in the rotating
# pool (no scoring/health state), but its Proton exit-side flow-state goes cold
# after ~25-35s idle exactly like the slots — so under light DNS load the first
# query after an idle gap hits the cold-catch and times out (SERVFAIL/no reply)
# before a retry warms it. A cheap neutral query (root NS, cached at Quad9)
# through the tunnel keeps that path warm. Best-effort: if dns-6 is mid-rotation
# the netns is briefly gone and this no-ops.
warm_dns6() {
    # +tries=3 so a cold pass self-warms within the pass (mirrors warm_one's
    # 3-probe retry) — the first UDP query may be dropped upstream of wg0, the
    # retry gets through and leaves the path warm for real client queries.
    ip netns exec "$DNS_NS" dig @9.9.9.9 +time=2 +tries=3 . NS \
        >/dev/null 2>&1 || true
}

# Bump the persisted pass counter and decide which slot (if any) gets the
# throughput probe this pass.
[[ -r "$PASS_COUNTER_FILE" ]] && pass_counter=$(<"$PASS_COUNTER_FILE") || pass_counter=0
pass_counter=$((pass_counter + 1))
echo "$pass_counter" > "$PASS_COUNTER_FILE.tmp"
mv "$PASS_COUNTER_FILE.tmp" "$PASS_COUNTER_FILE"

slot_list=""
for state in /etc/multivpn/state/proton-*.state; do
    inst=$(basename "$state" .state)
    [[ "$inst" =~ ^proton-[0-9]+$ ]] || continue
    slot_list="$slot_list $inst"
done
slot_list=${slot_list# }

tp_slot=$(pick_throughput_slot "$pass_counter" "$THROUGHPUT_EVERY_N_PASSES" "$slot_list")

for inst in $slot_list; do
    if [[ "$inst" == "$tp_slot" ]]; then
        warm_one "$inst" 1 &
    else
        warm_one "$inst" 0 &
    fi
done
warm_dns6 &
wait
