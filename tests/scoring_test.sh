#!/usr/bin/env bash
# tests/scoring_test.sh — black-box tests for etc/multivpn/bin/scoring.sh
set -uo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=tests/_assert.sh
source tests/_assert.sh
# shellcheck source=etc/multivpn/bin/scoring.sh
source etc/multivpn/bin/scoring.sh

echo "compute_score: degraded slots score very low regardless of metrics"
# base=-1000 + lat_term=29 + jit_term=-0.5 + tp_term=0.3*clamp(100,0,100)=30 -> -941.5
out=$(compute_score degraded 10 1 100)
assert_close "$out" -941.5 0.1 "degraded with great metrics"

echo "compute_score: degraded slot is always below any healthy slot"
# Worst healthy: status=ok, lat=999, jit=999, tp=0 -> base=50+0-20+0 = 30.
# Best degraded: status=degraded, lat=0, jit=0, tp=100 -> -1000+30+0+30 = -940.
worst_healthy=$(compute_score ok 999 999 0)
best_degraded=$(compute_score degraded 0 0 100)
assert_close "$worst_healthy" 30 0.1 "worst healthy = 30"
assert_close "$best_degraded" -940 0.1 "best degraded = -940"

echo "compute_score: healthy slot, fast (low lat, low jit, high tp)"
# base=50 + lat_term=clamp(30 - 10*0.1, 0, 30)=29 + jit_term=-clamp(1*0.5, 0, 20)=-0.5
# + tp_term=0.3*clamp(30, 0, 100)=9 -> 87.5
out=$(compute_score ok 10 1 30)
assert_close "$out" 87.5 0.1 "healthy fast slot"

echo "compute_score: throughput differentiates across the real (post-fix) range"
# Two slots, same latency/jitter, 120 vs 44 Mbps -> tp_term 30 vs 13.2
# 120: 50 + clamp(30-3,0,30)=27 + -clamp(1.5,0,20)=-1.5 + 0.3*clamp(120,0,100)=30 -> 105.5
# 44:  50 + 27 + -1.5 + 0.3*44=13.2 -> 88.7
assert_close "$(compute_score ok 30 3 120)" 105.5 0.1 "120 Mbps slot"
assert_close "$(compute_score ok 30 3 44)"   88.7 0.1 "44 Mbps slot"

echo "compute_score: healthy slot, mediocre"
# base=50 + lat_term=clamp(30 - 100*0.1, 0, 30)=20 + jit_term=-clamp(10*0.5, 0, 20)=-5
# + tp_term=0.3*clamp(10, 0, 100)=3 -> 68
out=$(compute_score ok 100 10 10)
assert_close "$out" 68 0.1 "healthy mediocre slot"

echo "compute_score: healthy slot, slow (terms clamped at zero)"
# base=50 + lat_term=clamp(30 - 500*0.1, 0, 30)=0 + jit_term=-clamp(50*0.5, 0, 20)=-20
# + tp_term=2*clamp(0, 0, 30)=0 -> 30
out=$(compute_score ok 500 50 0)
assert_close "$out" 30 0.1 "healthy slow slot"

echo "compute_score: missing throughput treated as zero"
out=$(compute_score ok 50 5 "")
# base=50 + lat=clamp(30 - 50*0.1, 0, 30)=25 + jit=-clamp(2.5, 0, 20)=-2.5 + tp=0 -> 72.5
assert_close "$out" 72.5 0.1 "missing throughput defaults to 0"

echo "update_lat_history: appends to empty file"
tmp=$(mktemp)
update_lat_history "$tmp" 12.5 5
assert_eq "$(cat "$tmp")" "12.5" "appends first sample"

echo "update_lat_history: trims to window size"
echo "1.0 2.0 3.0 4.0 5.0" > "$tmp"
update_lat_history "$tmp" 6.0 5
assert_eq "$(cat "$tmp")" "2.0 3.0 4.0 5.0 6.0" "trims oldest when exceeding window"

echo "update_lat_history: window of 1 keeps only latest"
echo "old" > "$tmp"
update_lat_history "$tmp" 9.9 1
assert_eq "$(cat "$tmp")" "9.9" "window=1 replaces"

echo "update_lat_history: handles missing parent dir gracefully"
rm -rf /tmp/scoring_test_dir
update_lat_history /tmp/scoring_test_dir/h 7.0 3
assert_eq "$(cat /tmp/scoring_test_dir/h)" "7.0" "creates parent dir"
rm -rf /tmp/scoring_test_dir
rm -f "$tmp"

echo "compute_mean: simple mean of a history string"
out=$(compute_mean "10 20 30")
assert_close "$out" 20 0.001 "mean of 10 20 30"

echo "compute_mean: empty input returns 0"
out=$(compute_mean "")
assert_eq "$out" "0" "empty -> 0"

echo "compute_mean: single sample"
out=$(compute_mean "42.5")
assert_close "$out" 42.5 0.001 "single 42.5"

echo "compute_jitter: stddev of constant samples is 0"
out=$(compute_jitter "5 5 5 5")
assert_close "$out" 0 0.001 "constant -> 0 stddev"

echo "compute_jitter: known stddev"
# pop stddev of {2 4 4 4 5 5 7 9} = 2.0
out=$(compute_jitter "2 4 4 4 5 5 7 9")
assert_close "$out" 2.0 0.001 "stddev = 2.0"

echo "compute_jitter: empty input returns 0"
out=$(compute_jitter "")
assert_eq "$out" "0" "empty stddev -> 0"

echo "pick_throughput_slot: returns empty when not on a probe pass"
# every_n=5; pass_counter=1 -> 1 % 5 != 0 -> empty
out=$(pick_throughput_slot 1 5 "proton-1 proton-2 proton-3 proton-4 proton-5")
assert_eq "$out" "" "non-probe pass -> empty"

echo "pick_throughput_slot: returns first slot on pass 0"
out=$(pick_throughput_slot 0 5 "proton-1 proton-2 proton-3 proton-4 proton-5")
assert_eq "$out" "proton-1" "pass=0 -> first slot"

echo "pick_throughput_slot: rotates through slots"
out=$(pick_throughput_slot 5  5 "proton-1 proton-2 proton-3 proton-4 proton-5")
assert_eq "$out" "proton-2" "pass=5 -> second slot"
out=$(pick_throughput_slot 10 5 "proton-1 proton-2 proton-3 proton-4 proton-5")
assert_eq "$out" "proton-3" "pass=10 -> third slot"
out=$(pick_throughput_slot 25 5 "proton-1 proton-2 proton-3 proton-4 proton-5")
assert_eq "$out" "proton-1" "pass=25 -> wraps back to first"

echo "pick_throughput_slot: empty slot list -> empty"
out=$(pick_throughput_slot 0 5 "")
assert_eq "$out" "" "no slots -> empty"

echo "compute_median: middle value (odd) / mean of two middles (even)"
assert_close "$(compute_median "10 20 30")"    20   0.001 "odd-count median"
assert_close "$(compute_median "10 20 30 40")" 25   0.001 "even-count median"
assert_eq    "$(compute_median "")"            "0"        "empty -> 0"
assert_close "$(compute_median "42.5")"        42.5 0.001 "single sample"

echo "compute_median: robust to cold-catch outliers (the real P2 case)"
# 11 warm ~22ms samples + 4 cold-catch ~2025ms: mean ~557, median 23.
assert_close "$(compute_median "23 23 23 2030 25 22 21 2025 2022 21 21 2024 21 26 22")" \
    23 1.0 "median ignores the 2s cold-catch spikes"

echo "compute_mad: median absolute deviation (robust jitter)"
assert_close "$(compute_mad "10 20 30")" 10 0.001 "mad of {10,20,30} = 10"
assert_close "$(compute_mad "5 5 5 5")"  0  0.001 "constant -> 0"
assert_eq    "$(compute_mad "")"         "0"      "empty -> 0"
assert_close "$(compute_mad "42.5")"     0  0.001 "single sample -> 0"

echo "should_record_latency: only first-try (ok) successes feed the latency ring"
should_record_latency ok       && r=yes || r=no; assert_eq "$r" "yes" "ok (first-try) -> record"
should_record_latency warmed   && r=yes || r=no; assert_eq "$r" "no"  "warmed (cold-catch retry) -> skip"
should_record_latency all_fail && r=yes || r=no; assert_eq "$r" "no"  "all_fail -> skip"
should_record_latency ""       && r=yes || r=no; assert_eq "$r" "no"  "empty outcome -> skip"

summary
