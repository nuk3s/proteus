#!/usr/bin/env bash
# tests/rotate_attempts_test.sh — rotate-slot.sh with every external dependency
# stubbed: transient failures must not consume verdict attempts, the loop must
# stay bounded, the ledger must see every verdict and promotion, and the
# step-down path must promote the best baseline-passing candidate (or not,
# in strict mode).
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FIX="$TMP/fix"
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/run" "$TMP/health" "$TMP/auto" "$FIX"
cp "$ROOT/etc/proteus/bin/checklib.sh" "$ROOT/etc/proteus/bin/ledger.py" \
   "$ROOT/etc/proteus/bin/history.sh" "$TMP/bin/"

# proton-mint: pops the next endpoint from fix/mint.queue (or honours
# --target-entry), writes a minimal conf, prints its path, logs its argv.
cat > "$TMP/bin/proton-mint" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$FIX/mint.log"
target=""; slot=""; out=""
while [ $# -gt 0 ]; do case "$1" in
  --slot) slot=$2; shift 2;; --out-dir) out=$2; shift 2;; --target-entry) target=$2; shift 2;; *) shift;; esac; done
if [ -n "$target" ]; then ep=$target; else ep=$(head -n1 "$FIX/mint.queue"); sed -i '1d' "$FIX/mint.queue"; fi
[ -n "$ep" ] || exit 2
f="$out/$slot-US-XX_${ep##*.}-$(date +%s%N).conf"
printf '# logical=US-XX#%s\n# exit_country=US\n# physical_domain=x.invalid\n[Interface]\n[Peer]\nEndpoint = %s:51820\n' "${ep##*.}" "$ep" > "$f"
echo "$f"
EOF
# vpnns-up: records the staged endpoint so curl can answer the egress probe with it.
cat > "$TMP/bin/vpnns-up.sh" <<'EOF'
#!/usr/bin/env bash
awk '/^Endpoint/ {split($3,a,":"); print a[1]}' "$2" > "$FIX/current.exit"
exit 0
EOF
cat > "$TMP/bin/vpnns-down.sh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$FIX/down.log"
exit 0
EOF
cat > "$TMP/bin/ip" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "netns" ] && [ "$2" = "exec" ] && { shift 3; exec "$@"; }
exit 0
EOF
printf '#!/usr/bin/env bash\necho "peer $(date +%%s)"\n' > "$TMP/bin/wg"
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *cdn-cgi/trace*) printf 'fl=12a34\nh=1.1.1.1\nip=%s\nts=1788470000\n' "$(cat "$FIX/current.exit")";;
  *checkip*) cat "$FIX/current.exit";;
  *speed.cloudflare*) printf '5000000 1.0';;
  *) exit 0;;
esac
EOF
# reputation-probe: pops fix/probe.queue lines "rc|standing|of|baseline|canaries|checks"
# and prints the real trailer format. The step-down override forces PASS.
# rc=sleep:N hangs for N seconds (via /bin/sleep, since `sleep` on PATH is
# stubbed to a no-op) so the caller's `timeout`, or a signal, can reap it.
cat > "$TMP/bin/reputation-probe.sh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$FIX/probe.log"
line=$(head -n1 "$FIX/probe.queue"); sed -i '1d' "$FIX/probe.queue"
IFS='|' read -r rc standing of baseline canaries checks <<<"$line"
case "$rc" in sleep:*) exec /bin/sleep "${rc#sleep:}";; esac
[ "${PROTEUS_CF_TIER_OVERRIDE:-}" = "advisory" ] && rc=0
IFS=',' read -ra cs <<<"$canaries"; for c in "${cs[@]}"; do [ -n "$c" ] && echo "CANARY ${c%%=*} ${c#*=}"; done
IFS=',' read -ra ks <<<"$checks";   for k in "${ks[@]}"; do [ -n "$k" ] && echo "CHECK ${k%%=*} ${k#*=}"; done
echo "STANDING $standing/$of"; echo "BASELINE $baseline"
echo "SUMMARY mandatory: pass=5 block=$rc error=0 | advisory: block=0"
if [ "$rc" = 0 ]; then echo "VERDICT PASS"; else echo "VERDICT FAIL (mandatory block signals present)"; fi
exit "$rc"
EOF
printf '#!/usr/bin/env bash\necho "$@" >> "$FIX/systemctl.log"\n' > "$TMP/bin/systemctl"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/logger"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/sleep"
chmod +x "$TMP/bin"/*
export FIX

reset() {
  rm -rf "$TMP/state" "$TMP/run" "$TMP/health" "$TMP/auto" "$FIX"
  mkdir -p "$TMP/state" "$TMP/run" "$TMP/health" "$TMP/auto" "$FIX"
  : > "$FIX/mint.log"; : > "$FIX/systemctl.log"; : > "$FIX/mint.queue"; : > "$FIX/probe.queue"
  : > "$FIX/probe.log"; : > "$FIX/down.log"
  rm -f "$TMP/ledger.jsonl" "$TMP/history.jsonl"
  printf 'INSTANCE=proton-2\nFWMARK=0x2\nWG_ENDPOINT_IP=10.0.0.2\n' > "$TMP/state/proton-2.state"
  printf 'INSTANCE=proton-1\nFWMARK=0x1\nWG_ENDPOINT_IP=10.0.0.1\nWG_CONF=/x\n' > "$TMP/state/proton-1.state"
}
# The scenarios below are written against a 5/10 budget, so pin it here rather
# than tracking the shipped defaults; a later "$@" entry overrides these, so a
# scenario that names MAX_ATTEMPTS still gets what it asked for. The defaults
# themselves are asserted separately at the end of this file.
run_rotation() { # run_rotation [VAR=val ...]
  echo manual > "$TMP/run/proton-1"
  RC=0
  env PATH="$TMP/bin:$PATH" PROTEUS_BIN="$TMP/bin" PROTEUS_STATE_DIR="$TMP/state" \
      PROTEUS_RUN_DIR="$TMP/run" HEALTH_DIR="$TMP/health" AUTO_DIR="$TMP/auto" \
      PROTEUS_LOCAL_ENV="$TMP/none.env" PROTEUS_LEDGER_FILE="$TMP/ledger.jsonl" \
      PROTEUS_HISTORY_FILE="$TMP/history.jsonl" PROTEUS_STREAMING_MIN_MBPS=1 RETRY_SLEEP=0 \
      MAX_ATTEMPTS=5 MAX_TOTAL_ATTEMPTS=10 \
      "$@" bash "$ROOT/etc/proteus/bin/rotate-slot.sh" proton-1 > "$TMP/out.log" 2>&1 || RC=$?
}
lines() { wc -l < "$1" | tr -d ' '; }
out_has() { grep -qF -- "$1" "$TMP/out.log" && echo y || echo n; }
hist_last() { tail -n1 "$TMP/history.jsonl" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['$1'])"; }
ledger_count() { grep -c "\"source\":\"$1\"" "$TMP/ledger.jsonl" 2>/dev/null || echo 0; }
ledger_field() { grep "\"source\":\"$1\"" "$TMP/ledger.jsonl" | tail -n1 | python3 -c "import json,sys; print(json.load(sys.stdin)['$2'])"; }

echo "transient failures do not consume verdict attempts"
reset
printf '10.0.0.2\n10.0.0.3\n10.0.0.4\n' > "$FIX/mint.queue"
printf '1|3|4|PASS|discord.com=clean,www.patreon.com=challenge|youtube=clean\n0|4|4|PASS|discord.com=clean,www.patreon.com=clean|youtube=clean\n' > "$FIX/probe.queue"
echo 'CF_CLEAN=no' > "$TMP/health/.cf-state.proton-1"; echo 1 > "$TMP/health/.stepdown-at.proton-1"
echo 'PLAYABLE=no' > "$TMP/health/.playability-state.proton-1"
echo 2 > "$TMP/health/.livecheck-fails.proton-1.cf:x"
run_rotation PROTEUS_CF_QUARANTINE_MIN_EXITS=3 PROTEUS_CANARIES_FILE="$TMP/canaries.json"
assert_eq "$RC" "0" "rotation succeeded"
assert_eq "$(out_has 'attempt 1 (verdict 1/5)')" y "attempt 1 announced"
assert_eq "$(out_has 'collides with proton-2')" y "collision detected"
assert_eq "$(out_has 'attempt 2 (verdict 1/5)')" y "collision did not consume a verdict attempt"
assert_eq "$(out_has 'attempt 3 (verdict 2/5)')" y "reputation FAIL consumed one"
assert_eq "$(hist_last outcome)" promoted "history outcome"
assert_eq "$(hist_last attempts)" 3 "history counts total attempts"
assert_eq "$(ledger_count gate)" 2 "two gate records (one fail, one pass)"
assert_eq "$(ledger_count promote)" 1 "one promote record"
assert_eq "$(ledger_field promote exit_ip)" 10.0.0.4 "promote record carries the exit"
assert_eq "$(ledger_field promote verdict)" pass "clean promotion is verdict pass"
[[ -e "$TMP/health/.cf-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "stale cf-state removed on a clean promotion"
[[ -e "$TMP/health/.stepdown-at.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "step-down marker removed on a clean promotion"
[[ -e "$TMP/health/.playability-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "stale playability verdict removed on a clean promotion"
[[ -e "$TMP/health/.livecheck-fails.proton-1.cf:x" ]] && r=present || r=absent
assert_eq "$r" absent "live-check failure counters do not outlive the exit they counted"
assert_eq "$(grep -cxF 'kill --kill-who=main --signal=HUP proteus-dispatcher.service' "$FIX/systemctl.log")" 1 \
  "promotion HUPs the dispatcher's main process only (not its nft children or ExecStartPre)"
assert_eq "$(sed -n 2p "$FIX/mint.log" | grep -c -- '--attempt 1')" 1 "second mint still attempt 1 (collision was transient)"
assert_eq "$(sed -n 3p "$FIX/mint.log" | grep -c -- '--attempt 2')" 1 "third mint is verdict attempt 2"
# The slot's own current server is excluded too: both tunnels would carry this
# slot's one persistent key, and Proton rebinds the peer to the newer one.
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- '--exclude-endpoints 10.0.0.1,10.0.0.2')" 1 "own and sibling endpoints excluded at mint"
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- "--ledger $TMP/ledger.jsonl")" 1 "ledger path passed to mint"
# Mint tiers exits against the same standard the gate applies, so it has to read
# the same basket and the same quarantine threshold; the defaults are not
# guaranteed to match what the operator configured.
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- '--quarantine-min-exits 3')" 1 "quarantine threshold passed to mint"
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- "--canaries-file $TMP/canaries.json")" 1 "canary basket passed to mint"
# In advisory tier the canaries are shadow data: they must not steer the draw
# either, or the "shadow" rollout quietly changes which exits get minted.
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- '--cf-tier mandatory')" 1 "canary tier passed to mint"

echo "the mint call carries the advisory tier"
reset
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
run_rotation PROTEUS_CF_TIER=advisory
assert_eq "$RC" "0" "rotation succeeded"
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- '--cf-tier advisory')" 1 "advisory tier passed to mint"

echo "the loop is bounded whatever the failure mix"
reset
printf '10.0.0.2\n10.0.0.2\n10.0.0.2\n10.0.0.2\n' > "$FIX/mint.queue"
run_rotation MAX_TOTAL_ATTEMPTS=3
assert_eq "$RC" "2" "all-fail exit code"
assert_eq "$(out_has 'no promotable candidate after 3 attempts (0 verdicts)')" y "bound reported"
assert_eq "$(hist_last outcome)" all-fail "history all-fail"
assert_eq "$(wc -l < "$FIX/mint.log" | tr -d ' ')" 3 "exactly three mints"

echo "step-down promotes the highest-standing baseline-passing candidate"
reset
printf '10.0.0.5\n10.0.0.6\n' > "$FIX/mint.queue"
# The third line (the step-down re-probe) fails a DIFFERENT canary than the
# candidate did when it was rejected, so .cf-state can only be right if it is
# built from the re-probe's trailer.
printf '1|2|4|PASS|a=clean,b=clean,c=challenge,d=challenge|\n1|3|4|PASS|a=clean,b=clean,c=clean,d=challenge|\n1|3|4|PASS|a=clean,b=clean,c=challenge,d=clean|\n' > "$FIX/probe.queue"
run_rotation MAX_ATTEMPTS=2
assert_eq "$RC" "0" "step-down rotation succeeded"
assert_eq "$(out_has 'stepping down to US-XX#6 (standing 3/4)')" y "step-down announced with the best candidate"
assert_eq "$(sed -n 3p "$FIX/mint.log" | grep -c -- '--target-entry 10.0.0.6')" 1 "re-mint targets the best candidate"
assert_eq "$(hist_last outcome)" promoted-stepdown "history outcome"
assert_eq "$(grep -c 'CF_CLEAN=no' "$TMP/health/.cf-state.proton-1")" 1 "cf-state written as not clean"
assert_eq "$(grep -c 'FAILING=c' "$TMP/health/.cf-state.proton-1")" 1 "failing canary comes from the re-probe, not the reject"
[[ -s "$TMP/health/.stepdown-at.proton-1" ]] && r=present || r=absent
assert_eq "$r" present "step-down marker written"
assert_eq "$(ledger_field promote verdict)" fail "step-down promotion is verdict fail"
assert_eq "$(ledger_count gate)" 3 "three gate records (two rejects, one step-down re-probe)"

echo "strict mode never steps down"
reset
printf '10.0.0.5\n10.0.0.6\n' > "$FIX/mint.queue"
printf '1|2|4|PASS|a=clean,c=challenge|\n1|3|4|PASS|a=clean,d=challenge|\n' > "$FIX/probe.queue"
run_rotation MAX_ATTEMPTS=2 PROTEUS_CF_FALLBACK=strict
assert_eq "$RC" "2" "all-fail"
assert_eq "$(grep -c -- '--target-entry' "$FIX/mint.log")" 0 "no step-down mint"
assert_eq "$(hist_last outcome)" all-fail "history all-fail"

echo "a candidate whose baseline fails is never a step-down candidate"
reset
printf '10.0.0.7\n' > "$FIX/mint.queue"
printf '1|3|4|FAIL|a=clean|custom:x.invalid=block\n' > "$FIX/probe.queue"
run_rotation MAX_ATTEMPTS=1
assert_eq "$RC" "2" "all-fail"
assert_eq "$(grep -c -- '--target-entry' "$FIX/mint.log")" 0 "no step-down mint"

echo "a throughput reject consumes a verdict attempt and is not a step-down candidate"
reset
printf '10.0.0.8\n' > "$FIX/mint.queue"
printf '0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
run_rotation MAX_ATTEMPTS=1 PROTEUS_STREAMING_MIN_MBPS=500
assert_eq "$RC" "2" "all-fail"
assert_eq "$(out_has 'rejecting exit')" y "throughput reject logged"
assert_eq "$(out_has '(1 verdicts)')" y "counted as a verdict"
assert_eq "$(ledger_count gate)" 1 "the reject reached the ledger"
assert_eq "$(ledger_field gate verdict)" fail \
    "a slow exit is a fail, so mint does not re-draw it as known-good for 24h"

echo "a probe that outruns PROBE_TIMEOUT_S is transient, not a verdict"
reset
printf '10.0.0.3\n10.0.0.4\n' > "$FIX/mint.queue"
printf 'sleep:5|0|0||\n0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
run_rotation PROBE_TIMEOUT_S=1
assert_eq "$RC" "0" "rotation still succeeded"
assert_eq "$(out_has 'reputation probe timed out')" y "timeout logged"
assert_eq "$(out_has 'attempt 2 (verdict 1/5)')" y "timeout did not consume a verdict attempt"
assert_eq "$(hist_last outcome)" promoted "next candidate decides the outcome"

echo "a probe that exits with neither verdict is transient, not a verdict"
reset
printf '10.0.0.3\n10.0.0.4\n' > "$FIX/mint.queue"
printf '2|0|0||\n0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
run_rotation
assert_eq "$RC" "0" "rotation still succeeded"
assert_eq "$(out_has 'reputation probe error (rc=2)')" y "the fault is logged as a fault"
assert_eq "$(out_has 'attempt 2 (verdict 1/5)')" y "a broken probe did not consume a verdict attempt"
assert_eq "$(ledger_count gate)" 1 "no ledger record for a run that produced no verdict"

echo "every sibling endpoint is excluded at mint"
reset
printf 'INSTANCE=proton-3\nFWMARK=0x3\nWG_ENDPOINT_IP=10.0.0.3\n' > "$TMP/state/proton-3.state"
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
run_rotation
assert_eq "$RC" "0" "rotation succeeded"
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- '--exclude-endpoints 10.0.0.1,10.0.0.2,10.0.0.3')" 1 "own endpoint and both siblings excluded at mint"

echo "the slot's own current server is discarded, not staged"
reset
printf '10.0.0.1\n10.0.0.4\n' > "$FIX/mint.queue"
printf '0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
run_rotation
assert_eq "$RC" "0" "the next candidate still promotes"
assert_eq "$(out_has "candidate is the slot's current server")" y "own-server collision logged"
assert_eq "$(out_has 'attempt 2 (verdict 1/5)')" y "it consumed no verdict attempt"
assert_eq "$(lines "$FIX/probe.log")" 1 "the discarded candidate never reached the probe"
assert_eq "$(ledger_count gate)" 1 "and left no ledger record"

echo "a mint failure is transient"
reset
run_rotation MAX_TOTAL_ATTEMPTS=2
assert_eq "$RC" "2" "all-fail"
assert_eq "$(out_has 'no promotable candidate after 2 attempts (0 verdicts)')" y "mint failure consumed no verdict attempt"
assert_eq "$(hist_last outcome)" all-fail "history all-fail"
assert_eq "$(lines "$FIX/probe.log")" 0 "no candidate ever reached the probe"

echo "a step-down candidate that fails the throughput gate is not promoted"
reset
printf '10.0.0.5\n10.0.0.6\n' > "$FIX/mint.queue"
printf '1|2|4|PASS|a=clean,b=clean,c=challenge,d=challenge|\n1|3|4|PASS|a=clean,b=clean,c=clean,d=challenge|\n1|3|4|PASS|a=clean,b=clean,c=challenge,d=clean|\n' > "$FIX/probe.queue"
run_rotation MAX_ATTEMPTS=2 PROTEUS_STREAMING_MIN_MBPS=500
assert_eq "$RC" "2" "all-fail"
assert_eq "$(out_has 'step-down candidate failed (rc=12)')" y "throughput reject blocks the step-down promotion"

echo "the wall-clock deadline stops the loop before it starts"
reset
printf '10.0.0.4\n' > "$FIX/mint.queue"
printf '0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
run_rotation ROTATION_DEADLINE_S=0
assert_eq "$RC" "2" "all-fail"
assert_eq "$(out_has 'deadline reached after')" y "deadline logged"
assert_eq "$(hist_last attempts)" 0 "no attempt was made"
assert_eq "$(lines "$FIX/mint.log")" 0 "no mint call"

echo "a TERM mid-attempt tears down staging and exits 143"
reset
printf '10.0.0.4\n' > "$FIX/mint.queue"
printf 'sleep:3|0|0||\n' > "$FIX/probe.queue"
echo manual > "$TMP/run/proton-1"
env PATH="$TMP/bin:$PATH" PROTEUS_BIN="$TMP/bin" PROTEUS_STATE_DIR="$TMP/state" \
    PROTEUS_RUN_DIR="$TMP/run" HEALTH_DIR="$TMP/health" AUTO_DIR="$TMP/auto" \
    PROTEUS_LOCAL_ENV="$TMP/none.env" PROTEUS_LEDGER_FILE="$TMP/ledger.jsonl" \
    PROTEUS_HISTORY_FILE="$TMP/history.jsonl" PROTEUS_STREAMING_MIN_MBPS=1 RETRY_SLEEP=0 \
    bash "$ROOT/etc/proteus/bin/rotate-slot.sh" proton-1 > "$TMP/out.log" 2>&1 &
rot_pid=$!
# Wait until staging is up and the probe is running, so the signal lands with a
# tunnel to clean up. Bash defers the trap until the probe child returns.
for _ in $(seq 1 200); do [[ -s "$FIX/probe.log" ]] && break; sleep 0.05; done
kill -TERM "$rot_pid"
trc=0; wait "$rot_pid" || trc=$?
assert_eq "$trc" 143 "TERM exits 143"
assert_eq "$(out_has 'terminated by signal')" y "signal logged"
assert_eq "$(grep -c 'proton-1-s' "$FIX/down.log")" 1 "staging torn down by the trap"

echo "the shipped attempt budget"
# Transients stopped consuming verdict attempts, so the budget buys eight real
# verdicts rather than eight failures of any kind. run_rotation pins 5/10 above.
assert_eq "$(grep -c 'MAX_ATTEMPTS="${MAX_ATTEMPTS:-8}"' "$ROOT/etc/proteus/bin/rotate-slot.sh")" 1 \
    "MAX_ATTEMPTS defaults to 8"
assert_eq "$(grep -c 'MAX_TOTAL_ATTEMPTS="${MAX_TOTAL_ATTEMPTS:-14}"' "$ROOT/etc/proteus/bin/rotate-slot.sh")" 1 \
    "MAX_TOTAL_ATTEMPTS defaults to 14"

echo "the egress probe needs no resolver"
# A staging namespace resolves through the tunnel it is testing, and some exits
# never answer; the probe must stay on an IP literal.
assert_eq "$(grep -c 'checkip.amazonaws.com' "$ROOT/etc/proteus/bin/rotate-slot.sh" || true)" 0 \
    "rotate-slot.sh no longer resolves checkip.amazonaws.com"
assert_eq "$(grep -c 'https://1.1.1.1/cdn-cgi/trace' "$ROOT/etc/proteus/bin/rotate-slot.sh")" 1 \
    "the egress probe fetches the trace endpoint by IP literal"

summary
