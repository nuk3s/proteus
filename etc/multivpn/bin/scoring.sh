#!/usr/bin/env bash
# etc/multivpn/bin/scoring.sh — sourceable scoring helpers for slot-warmup.sh.
#
# Pure functions: no network I/O, no service calls. Reads/writes only the
# latency-history files passed in as arguments. Tested by tests/scoring_test.sh.

# Score-formula coefficients. See the design notes.
SCORE_BASE_HEALTHY=50
SCORE_BASE_DEGRADED=-1000
SCORE_LAT_MAX=30           # ms-term ceiling
SCORE_LAT_COEF=0.1         # ms*coef subtracted from ceiling
SCORE_JIT_MAX=20           # ms-term ceiling
SCORE_JIT_COEF=0.5
# Throughput term. Real exit capacity is ~44-289 Mbps (see
# the design notes),
# so the old ceiling of 30 Mbps saturated for every slot. Differentiate across
# 0-100 Mbps (100+ is far past any streaming need) at a weight that keeps the
# term's max (~30) comparable to the latency term rather than dominating.
SCORE_TP_MAX=100           # Mbps-term ceiling
SCORE_TP_WEIGHT=0.3        # multiplier on the throughput term (max term = 30)

# compute_score <status> <mean_latency_ms> <jitter_ms> <throughput_mbps>
# Empty / missing throughput is treated as 0. Status is "ok" or "degraded".
# Echoes the score (float, 1 decimal). awk handles all arithmetic.
compute_score() {
    local status=${1:-ok}
    local lat=${2:-0}
    local jit=${3:-0}
    local tp=${4:-0}
    [[ -z "$tp" ]] && tp=0

    awk -v status="$status" -v lat="$lat" -v jit="$jit" -v tp="$tp" \
        -v bh="$SCORE_BASE_HEALTHY" -v bd="$SCORE_BASE_DEGRADED" \
        -v lmax="$SCORE_LAT_MAX" -v lcoef="$SCORE_LAT_COEF" \
        -v jmax="$SCORE_JIT_MAX" -v jcoef="$SCORE_JIT_COEF" \
        -v tmax="$SCORE_TP_MAX" -v tw="$SCORE_TP_WEIGHT" \
    'function clamp(x, lo, hi) { if (x<lo) return lo; if (x>hi) return hi; return x }
     BEGIN {
         base = (status == "degraded") ? bd : bh
         lat_term = clamp(lmax - lat * lcoef, 0, lmax)
         jit_term = -clamp(jit * jcoef, 0, jmax)
         tp_term  = tw * clamp(tp, 0, tmax)
         printf "%.1f", base + lat_term + jit_term + tp_term
     }'
}

# should_record_latency <outcome>
# True (exit 0) only for a first-try success ("ok"). A "warmed" outcome means
# the slot cold-caught and succeeded on retry N>1, so its time_connect carries
# the 2-4s cold-warming penalty; recording that as a latency sample poisons the
# rolling mean and jitter and misranks the slot (see
# the design notes #2).
# "all_fail" has no meaningful latency. On a skipped pass the ring is left
# unchanged, so mean/jitter naturally carry forward the last N warm samples.
should_record_latency() {
    [[ "${1:-}" == "ok" ]]
}

# update_lat_history <history_file> <new_sample_ms> <window_size>
# Appends new_sample to history_file as a whitespace-separated stream of
# samples, trimmed to the last <window_size> entries. Creates parent dir
# if missing. Atomic via rename.
update_lat_history() {
    local file=$1 sample=$2 window=$3
    local dir
    dir=$(dirname "$file")
    [[ -d "$dir" ]] || mkdir -p "$dir"

    local prev=""
    [[ -r "$file" ]] && prev=$(<"$file")

    # awk: split on whitespace, append sample, keep last <window> tokens.
    local trimmed
    trimmed=$(awk -v prev="$prev" -v s="$sample" -v w="$window" \
        'BEGIN {
            n = split(prev, a, /[ \t\n]+/)
            # split() puts empty first element when prev is empty
            out = ""
            start = (n > 0 && a[1] == "") ? 2 : 1
            count = n - start + 1
            count = (count < 0) ? 0 : count
            count += 1            # +1 for the new sample
            drop = count - w
            i = start
            if (drop > 0) i = start + drop
            for (; i <= n; i++) out = out a[i] " "
            out = out s
            print out
        }')

    local tmp="$file.tmp.$$"
    printf '%s' "$trimmed" > "$tmp"
    mv "$tmp" "$file"
}

# compute_mean <history_string>
# Echoes the arithmetic mean of whitespace-separated samples, "0" if empty.
compute_mean() {
    awk -v s="$1" 'BEGIN {
        n = split(s, a, /[ \t\n]+/)
        sum = 0; cnt = 0
        for (i=1; i<=n; i++) {
            if (a[i] == "") continue
            sum += a[i] + 0
            cnt++
        }
        if (cnt == 0) { print "0"; exit }
        printf "%.4g", sum / cnt
    }'
}

# compute_median <history_string>
# Echoes the median of whitespace-separated samples, "0" if empty.
# The median (not the mean) is what the score uses for latency: a cold-catch
# shows up as an occasional 2-4s connect (SYN retransmit) that drags the mean
# but leaves the median — the typical warm-path latency — unchanged. See
# the design notes #2.
compute_median() {
    awk -v s="$1" 'BEGIN {
        n = split(s, a, /[ \t\n]+/); m = 0
        for (i = 1; i <= n; i++) if (a[i] != "") b[++m] = a[i] + 0
        if (m == 0) { print "0"; exit }
        for (i = 1; i <= m; i++)
            for (j = i + 1; j <= m; j++)
                if (b[j] < b[i]) { t = b[i]; b[i] = b[j]; b[j] = t }
        med = (m % 2) ? b[(m + 1) / 2] : (b[m / 2] + b[m / 2 + 1]) / 2
        printf "%.4g", med
    }'
}

# compute_mad <history_string>
# Echoes the median absolute deviation: median(|x_i - median(x)|). This is the
# robust analogue of stddev used for the jitter term — a couple of cold-catch
# spikes don't inflate it the way population stddev does. "0" if <2 samples.
compute_mad() {
    awk -v s="$1" '
    function med(arr, k,   i, j, t) {
        for (i = 1; i <= k; i++)
            for (j = i + 1; j <= k; j++)
                if (arr[j] < arr[i]) { t = arr[i]; arr[i] = arr[j]; arr[j] = t }
        return (k % 2) ? arr[(k + 1) / 2] : (arr[k / 2] + arr[k / 2 + 1]) / 2
    }
    BEGIN {
        n = split(s, a, /[ \t\n]+/); m = 0
        for (i = 1; i <= n; i++) if (a[i] != "") b[++m] = a[i] + 0
        if (m < 2) { print "0"; exit }
        md = med(b, m)
        for (i = 1; i <= m; i++) { d = b[i] - md; dev[i] = (d < 0) ? -d : d }
        printf "%.4g", med(dev, m)
    }'
}

# compute_jitter <history_string>
# Echoes population stddev of samples (rounded to 4 sig figs), "0" if <2 samples.
compute_jitter() {
    awk -v s="$1" 'BEGIN {
        n = split(s, a, /[ \t\n]+/)
        sum = 0; cnt = 0
        for (i=1; i<=n; i++) {
            if (a[i] == "") continue
            sum += a[i] + 0
            cnt++
        }
        if (cnt < 2) { print "0"; exit }
        mean = sum / cnt
        sumsq = 0
        for (i=1; i<=n; i++) {
            if (a[i] == "") continue
            d = (a[i] + 0) - mean
            sumsq += d * d
        }
        printf "%.4g", sqrt(sumsq / cnt)
    }'
}

# pick_throughput_slot <pass_counter> <every_n> <slot_list>
# Returns the slot name to throughput-probe this pass, or empty string
# if this pass is not a probe pass. slot_list is whitespace-separated.
# Rotation: slot_index = (pass_counter / every_n) mod num_slots, applied
# only when (pass_counter mod every_n) == 0.
pick_throughput_slot() {
    local pass=$1 every=$2 slot_list=$3
    [[ -z "$slot_list" ]] && return 0
    (( pass % every != 0 )) && return 0

    # shellcheck disable=SC2206
    local slots=($slot_list)
    local n=${#slots[@]}
    (( n == 0 )) && return 0
    local idx=$(( (pass / every) % n ))
    printf '%s' "${slots[$idx]}"
}
