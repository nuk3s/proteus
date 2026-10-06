#!/usr/bin/env bash
# tests/rotate_attempts_test.sh — rotate-slot.sh with every external dependency
# stubbed: transient failures must not consume verdict attempts, the loop must
# stay bounded, the ledger must see every verdict and promotion, in the mandatory
# tier a canary failure is never promoted, and a promotion records the gate's verdict.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FIX="$TMP/fix"
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/run" "$TMP/health" "$TMP/auto" "$FIX"
cp "$ROOT/etc/proteus/bin/checklib.sh" "$ROOT/etc/proteus/bin/ledger.py" \
   "$ROOT/etc/proteus/bin/history.sh" "$TMP/bin/"

# proton-mint: pops the next endpoint from fix/mint.queue, writes a minimal
# conf, prints its path, logs its argv.
cat > "$TMP/bin/proton-mint" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$FIX/mint.log"
slot=""; out=""
while [ $# -gt 0 ]; do case "$1" in
  --slot) slot=$2; shift 2;; --out-dir) out=$2; shift 2;; *) shift;; esac; done
ep=$(head -n1 "$FIX/mint.queue"); sed -i '1d' "$FIX/mint.queue"
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
# and prints the real trailer format. A canary value "class:quarantined" prints
# the fourth token: q=challenge:quarantined -> "CANARY q challenge quarantined".
# rc=sleep:N hangs for N seconds (via /bin/sleep, since `sleep` on PATH is
# stubbed to a no-op) so the caller's `timeout`, or a signal, can reap it.
cat > "$TMP/bin/reputation-probe.sh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$FIX/probe.log"
line=$(head -n1 "$FIX/probe.queue"); sed -i '1d' "$FIX/probe.queue"
IFS='|' read -r rc standing of baseline canaries checks <<<"$line"
case "$rc" in sleep:*) exec /bin/sleep "${rc#sleep:}";; esac
IFS=',' read -ra cs <<<"$canaries"; for c in "${cs[@]}"; do v=${c#*=}; [ -n "$c" ] && echo "CANARY ${c%%=*} ${v/:/ }"; done
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
# grep -c prints 0 and exits 1 on no match, so the fallback must not echo a second 0.
ledger_count() { local n; n=$(grep -c "\"source\":\"$1\"" "$TMP/ledger.jsonl" 2>/dev/null) || true; echo "${n:-0}"; }
ledger_field() { grep "\"source\":\"$1\"" "$TMP/ledger.jsonl" | tail -n1 | python3 -c "import json,sys; print(json.load(sys.stdin)['$2'])"; }

echo "transient failures do not consume verdict attempts"
reset
printf '10.0.0.2\n10.0.0.3\n10.0.0.4\n' > "$FIX/mint.queue"
printf '1|3|4|PASS|discord.com=clean,www.patreon.com=challenge|youtube=clean\n0|4|4|PASS|discord.com=clean,www.patreon.com=clean|youtube=clean\n' > "$FIX/probe.queue"
echo 'CF_CLEAN=no' > "$TMP/health/.cf-state.proton-1"
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
assert_eq "$(grep -cx 'CF_CLEAN=yes' "$TMP/health/.cf-state.proton-1")" 1 \
  "a promotion whose gate saw every canary clean is cf ok at once"
assert_eq "$(grep -cx 'FAILING=' "$TMP/health/.cf-state.proton-1")" 1 "nothing failing"
assert_eq "$(grep -c '^AT=[0-9][0-9]*$' "$TMP/health/.cf-state.proton-1")" 1 "verdict is time-stamped"
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
# In the advisory tier the canaries are shadow data, so they must not steer the
# draw either. Mint has to know the tier to leave them out.
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- '--cf-tier mandatory')" 1 "the default tier mandatory is passed to mint"

echo "advisory tier: a candidate with a flagged canary promotes and the card shows the flag"
reset
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|3|4|PASS|a=clean,b=clean,c=clean,d=challenge|\n' > "$FIX/probe.queue"
echo 'CF_CLEAN=yes' > "$TMP/health/.cf-state.proton-1"
run_rotation PROTEUS_CF_TIER=advisory
assert_eq "$RC" "0" "promoted"
assert_eq "$(sed -n 1p "$FIX/mint.log" | grep -c -- '--cf-tier advisory')" 1 "the advisory tier is passed to mint"
assert_eq "$(hist_last outcome)" promoted "history says promoted"
assert_eq "$(ledger_field gate verdict)" pass "the gate record is a pass"
assert_eq "$(ledger_field promote verdict)" pass "the promote record is a pass"
assert_eq "$(grep -cx 'CF_CLEAN=no' "$TMP/health/.cf-state.proton-1")" 1 "the flagged canary is recorded"
assert_eq "$(grep -cx 'FAILING=d' "$TMP/health/.cf-state.proton-1")" 1 "the flagged canary is named"
assert_eq "$(grep -c '^AT=[0-9][0-9]*$' "$TMP/health/.cf-state.proton-1")" 1 "verdict is time-stamped"

echo "mandatory tier: a quarantined canary's challenge does not flag a promotion"
reset
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|3|3|PASS|a=clean,b=clean,c=clean,q=challenge:quarantined|\n' > "$FIX/probe.queue"
run_rotation
assert_eq "$RC" "0" "promoted"
assert_eq "$(grep -cx 'CF_CLEAN=yes' "$TMP/health/.cf-state.proton-1")" 1 "cf ok, as before PROTEUS_CF_TIER came back"
assert_eq "$(grep -cx 'FAILING=' "$TMP/health/.cf-state.proton-1")" 1 "nothing failing"
assert_eq "$(grep '"source":"gate"' "$TMP/ledger.jsonl" | tail -n1 \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['canaries'].get('q'))")" challenge \
  "the gate record still carries the quarantined result (it is how the canary recovers)"

echo "only challenge and block classes flag a promotion"
reset
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|2|2|PASS|a=clean,b=clean,x=,y=weird|\n' > "$FIX/probe.queue"
run_rotation
assert_eq "$RC" "0" "promoted"
assert_eq "$(grep -cx 'CF_CLEAN=yes' "$TMP/health/.cf-state.proton-1")" 1 \
  "an empty or unknown canary class never writes a flag"
assert_eq "$(grep -cx 'FAILING=' "$TMP/health/.cf-state.proton-1")" 1 "nothing failing"

echo "a flagged canary outranks an unreached one, and every flagged canary is named"
reset
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|1|4|PASS|a=clean,b=transport,c=block-1020,d=challenge,e=not-cloudflare|\n' > "$FIX/probe.queue"
run_rotation PROTEUS_CF_TIER=advisory
assert_eq "$RC" "0" "promoted"
assert_eq "$(grep -cx 'CF_CLEAN=no' "$TMP/health/.cf-state.proton-1")" 1 "flagged, not unchecked"
assert_eq "$(grep -cx 'FAILING=c,d' "$TMP/health/.cf-state.proton-1")" 1 \
  "only challenge and block classes are named, not transport or not-cloudflare"

echo "the loop is bounded whatever the failure mix"
reset
printf '10.0.0.2\n10.0.0.2\n10.0.0.2\n10.0.0.2\n' > "$FIX/mint.queue"
run_rotation MAX_TOTAL_ATTEMPTS=3
assert_eq "$RC" "2" "all-fail exit code"
assert_eq "$(out_has 'no promotable candidate after 3 attempts (0 verdicts)')" y "bound reported"
assert_eq "$(hist_last outcome)" all-fail "history all-fail"
assert_eq "$(wc -l < "$FIX/mint.log" | tr -d ' ')" 3 "exactly three mints"

echo "a candidate that fails only the canaries is never promoted"
reset
printf '10.0.0.5\n10.0.0.6\n' > "$FIX/mint.queue"
printf '1|2|4|PASS|a=clean,b=clean,c=challenge,d=challenge|\n1|3|4|PASS|a=clean,b=clean,c=clean,d=challenge|\n' > "$FIX/probe.queue"
printf 'CF_CLEAN=no\nAT=7\nFAILING=d\n' > "$TMP/health/.cf-state.proton-1"
run_rotation MAX_ATTEMPTS=2
assert_eq "$RC" "2" "all-fail"
assert_eq "$(hist_last outcome)" all-fail "history all-fail"
assert_eq "$(lines "$FIX/mint.log")" 2 "no extra mint after the budget"
assert_eq "$(ledger_count promote)" 0 "nothing promoted"
assert_eq "$(grep -cx 'AT=7' "$TMP/health/.cf-state.proton-1")" 1 \
  "the current exit keeps its verdict (the rotation saw nothing about it)"
assert_eq "$(grep -c 'stepping down' "$TMP/out.log" || true)" 0 "no step-down"

echo "a promotion whose gate could not reach a canary is cf unchecked"
reset
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|2|3|PASS|a=clean,b=clean,c=transport|\n' > "$FIX/probe.queue"
printf 'CF_CLEAN=no\nAT=7\nFAILING=c\n' > "$TMP/health/.cf-state.proton-1"
run_rotation
assert_eq "$RC" "0" "promoted"
[[ -e "$TMP/health/.cf-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "no verdict: the old exit's flag is gone and nothing claims cf ok"
assert_eq "$(ledger_field promote verdict)" pass "promote record is a pass"

echo "a promotion with no active canary at the gate is cf ok by default"
reset
printf '10.0.0.9\n' > "$FIX/mint.queue"
printf '0|0|0|PASS|a=not-cloudflare|\n' > "$FIX/probe.queue"
run_rotation
assert_eq "$RC" "0" "promoted"
assert_eq "$(grep -cx 'CF_CLEAN=yes' "$TMP/health/.cf-state.proton-1")" 1 "no active canary is still cf ok"
assert_eq "$(out_has 'no active canary at the gate; proton-1 is cf ok by default')" y "the default is logged"

# A root user ignores directory modes, so this case cannot run as root.
if (( $(id -u) != 0 )); then
  echo "a promotion that cannot write the cf verdict still completes"
  reset
  printf '10.0.0.9\n' > "$FIX/mint.queue"
  printf '0|4|4|PASS|a=clean|\n' > "$FIX/probe.queue"
  chmod 555 "$TMP/health"
  run_rotation
  chmod 755 "$TMP/health"
  assert_eq "$RC" "0" "promoted"
  assert_eq "$(hist_last outcome)" promoted "history says promoted"
  assert_eq "$(out_has 'could not write the cf verdict for proton-1')" y "the failed write is logged"
  [[ -e "$TMP/health/.cf-state.proton-1" ]] && r=present || r=absent
  assert_eq "$r" absent "no verdict file was left behind"
fi

echo "a throughput reject consumes a verdict attempt"
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

echo "the cf verdict is written after the new exit is recorded"
# A live check of the old exit discards its result once .meta names a new
# EXIT_IP, so the verdict must land after that write.
meta_ln=$(grep -n '^} > "\$meta"' "$ROOT/etc/proteus/bin/rotate-slot.sh" | head -n1 | cut -d: -f1)
# shellcheck disable=SC2016  # the pattern is the literal source text, not an expansion.
cf_ln=$(grep -nF '> "$HEALTH_DIR/.cf-state.$SLOT.tmp"' "$ROOT/etc/proteus/bin/rotate-slot.sh" | head -n1 | cut -d: -f1)
assert_eq "$(( ${cf_ln:-0} > ${meta_ln:-999999} ? 1 : 0 ))" 1 "the verdict write follows the .meta write"

echo "step-down is gone"
# CF_TIER and --cf-tier are legitimate again; the pattern must not match them.
assert_eq "$(grep -ciE 'CF_FALLBACK|step-?down|target-entry' "$ROOT/etc/proteus/bin/rotate-slot.sh" || true)" 0 \
    "rotate-slot.sh has no step-down, fallback or target entry left"

summary
