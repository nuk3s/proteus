#!/usr/bin/env bash
# tests/livecheck_test.sh — slot-warmup.sh live_check: Cloudflare canaries and
# mandatory custom checks re-run on promoted slots. Pins the things a future
# "simplification" would break: two fails before acting, one shared cooldown,
# attainability and step-down gates for canaries only, no health writes.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FIX="$TMP/fix"
mkdir -p "$TMP/bin" "$TMP/health" "$TMP/run" "$TMP/state" "$FIX"
export FIX

cat > "$TMP/bin/ip" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "netns" ] && [ "$2" = "exec" ] && { shift 3; exec "$@"; }
exit 0
EOF
cat > "$TMP/bin/curl" <<'CURLEOF'
#!/usr/bin/env bash
out=""; hdr=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -D) hdr="$2"; shift 2;;
    -w|-A|-H|--retry|--retry-delay|--max-time|--connect-timeout) shift 2;;
    --) shift;;
    http://*|https://*) url="$1"; shift;;
    *) shift;;
  esac
done
host=$(printf '%s' "$url" | sed -E 's#^https?://##; s#[/:?].*$##')
echo "$host" >> "$FIX/hits.log"
# Simulates a rotation landing mid-run: the slot's exit changes while the
# second canary is being probed.
if [ "$host" = "two.invalid" ] && [ -e "$FIX/flip-exit" ]; then
  printf 'LOGICAL_NAME=US-XX#2\nEXIT_IP=9.9.9.42\n' > "$META"
fi
code=200
[ -r "$FIX/$host.code" ] && code=$(cat "$FIX/$host.code")
# 000: curl never got an answer. Empty header/body files and a curl-ish failure
# exit, so probe()/cf_probe_canary classify it as transport.
if [ "$code" = "000" ]; then
  [ -n "$hdr" ] && : > "$hdr"
  [ -n "$out" ] && : > "$out"
  printf '000'; exit 7
fi
if [ -n "$hdr" ]; then : > "$hdr"; [ -r "$FIX/$host.hdr" ] && cat "$FIX/$host.hdr" > "$hdr"; fi
if [ -n "$out" ]; then : > "$out"; [ -r "$FIX/$host.body" ] && cat "$FIX/$host.body" > "$out"; fi
printf '%s' "$code"
CURLEOF
cat > "$TMP/bin/systemctl" <<'SCEOF'
#!/usr/bin/env bash
# is-active answers live_check's mid-rotation guard: nothing is rotating unless
# the test says so. Deliberately NOT logged — it names the rotate unit, and
# rotations() counts lines that mention it.
if [ "$1" = "is-active" ]; then
  [ -e "$FIX/rotating" ] && exit 0
  exit 1
fi
echo "$@" >> "$FIX/systemctl.log"
SCEOF
printf '#!/usr/bin/env bash\nshift 2 2>/dev/null; echo "$*" >> "$FIX/logger.log"\n' > "$TMP/bin/logger"
chmod +x "$TMP/bin"/*
export PATH="$TMP/bin:$PATH"

fix() { # fix <host> <code> <cf|chal|nocf> [body]
  echo "$2" > "$FIX/$1.code"
  case "$3" in
    cf)   printf 'HTTP/2 %s\r\ncf-ray: 8a1-IAD\r\n\r\n' "$2" > "$FIX/$1.hdr";;
    chal) printf 'HTTP/2 %s\r\ncf-mitigated: challenge\r\ncf-ray: 8a1-IAD\r\n\r\n' "$2" > "$FIX/$1.hdr";;
    nocf) printf 'HTTP/2 %s\r\nserver: nginx\r\n\r\n' "$2" > "$FIX/$1.hdr";;
  esac
  if [ -n "${4:-}" ]; then printf '%s' "$4" > "$FIX/$1.body"; else rm -f "$FIX/$1.body"; fi
}
printf 'INSTANCE=proton-1\nFWMARK=0x1\nWG_ENDPOINT_IP=10.0.0.1\n' > "$TMP/state/proton-1.state"
printf 'INSTANCE=proton-2\nFWMARK=0x2\nWG_ENDPOINT_IP=10.0.0.2\n' > "$TMP/state/proton-2.state"
printf 'LOGICAL_NAME=US-XX#1\nEXIT_IP=9.9.9.1\n' > "$TMP/state/proton-1.meta"
export META="$TMP/state/proton-1.meta"
printf '{"canaries":[{"url":"https://one.invalid/"},{"url":"https://two.invalid/"}]}' > "$TMP/canaries.json"

# Extract the live-check functions from the real script so the test tracks source.
FN="$TMP/fn.sh"
for f in _health_get _meta_get _live_fail _live_ok live_check; do
  sed -n "/^$f()/,/^}/p" "$ROOT/etc/proteus/bin/slot-warmup.sh" >> "$FN"
done
run_check() { # run_check [VAR=val ...]
  env "$@" PROTEUS_LEDGER_FILE="$TMP/ledger.jsonl" PROTEUS_CANARIES_FILE="$TMP/canaries.json" \
      PROTEUS_CHECKS_FILE="$TMP/checks.json" PROTEUS_STATE_DIR="$TMP/state" \
      bash -c '
    set -u
    HEALTH_DIR='"$TMP"'/health; STATE_DIR='"$TMP"'/state; RUN_DIR='"$TMP"'/run; LOG_TAG=slot-warmup
    LIVECHECK_FAILS_BEFORE_ROTATE=2
    LIVECHECK_ROT_COOLDOWN=${LIVECHECK_ROT_COOLDOWN:-3600}
    CF_STEPDOWN_RETRY_S=${CF_STEPDOWN_RETRY_S:-21600}
    . '"$ROOT"'/etc/proteus/bin/checklib.sh
    . '"$FN"'
    live_check proton-1' >/dev/null 2>&1
}
fails() { cat "$TMP/health/.livecheck-fails.proton-1.$1" 2>/dev/null || echo 0; }
rotations() { grep -c 'rotate-slot@proton-1' "$FIX/systemctl.log" 2>/dev/null || true; }
cfstate() { awk -F= -v k="$1" '$1==k {print $2}' "$TMP/health/.cf-state.proton-1" 2>/dev/null; }
ledger_verdict() { python3 -c "import json;print(json.loads(open('$TMP/ledger.jsonl').read().splitlines()[-1])['verdict'])"; }
logged() { grep -qF -- "$1" "$FIX/logger.log" && echo y || echo n; }
clear_logs() { : > "$FIX/systemctl.log"; : > "$FIX/logger.log"; : > "$FIX/hits.log"; }
clear_logs

echo "all clean: verdict yes, ledger live record, no rotation"
fix one.invalid 200 cf; fix two.invalid 200 cf
run_check
assert_eq "$(cfstate CF_CLEAN)" yes "CF_CLEAN=yes"
assert_eq "$(cfstate FAILING)" "" "nothing failing"
assert_eq "$(rotations)" "0" "no rotation"
assert_eq "$(grep -c '"source":"live"' "$TMP/ledger.jsonl")" 1 "one live ledger record"
assert_eq "$(python3 -c "import json;d=json.loads(open('$TMP/ledger.jsonl').read().splitlines()[-1]);print(d['exit_ip'],d['entry_ip'],d['verdict'],d['standing'],d['of'])")" \
          "9.9.9.1 10.0.0.1 pass 2 2" "record carries exit, entry, verdict and standing"

echo "one challenge is counted, not acted on"
fix two.invalid 403 chal
run_check
assert_eq "$(fails cf:two.invalid)" "1" "counter 1"
assert_eq "$(cfstate CF_CLEAN)" no "CF_CLEAN=no immediately (dispatcher bias)"
assert_eq "$(cfstate FAILING)" two.invalid "failing host recorded"
assert_eq "$(rotations)" "0" "one failure -> no rotation"
assert_eq "$(logged 'cf:two.invalid FAIL (challenge) (1/2)')" y "failure logged with class"

echo "second consecutive challenge rotates (thin ledger => attainable)"
run_check
assert_eq "$(rotations)" "1" "rotation triggered"
assert_eq "$(cat "$TMP/run/proton-1")" cf-canary "trigger names the canary watch"
assert_eq "$(fails cf:two.invalid)" "0" "counters reset after triggering"
[[ -s "$TMP/health/.live-lastrot.proton-1" ]] && r=ok || r=fail
assert_eq "$r" ok "shared cooldown stamp written"

echo "shared cooldown throttles"
clear_logs; echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check
assert_eq "$(rotations)" "0" "within cooldown -> no rotation"
assert_eq "$(logged 'on cooldown')" y "cooldown logged"
assert_eq "$(fails cf:two.invalid)" "2" "a suppressed trigger keeps the streak"
rm -f "$TMP/health/.live-lastrot.proton-1"

echo "recovery resets and is logged"
clear_logs; fix two.invalid 200 cf; echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check
assert_eq "$(fails cf:two.invalid)" "0" "counter reset"
assert_eq "$(logged 'cf:two.invalid recovered')" y "recovery logged"
assert_eq "$(cfstate CF_CLEAN)" yes "verdict back to yes"

echo "an unattainable standard suppresses canary rotations"
clear_logs; rm -f "$TMP/ledger.jsonl"
# 11 exits challenged, 1 clean: not quarantined (one exit passes) but the pool
# (1) is below the live slot count (2), so the standard is not attainable.
for i in $(seq 1 11); do
  python3 "$ROOT/etc/proteus/bin/ledger.py" append --path "$TMP/ledger.jsonl" --exit-ip "10.7.7.$i" \
    --entry-ip "10.6.6.$i" --slot proton-1 --source gate --verdict fail --canaries "one.invalid=clean,two.invalid=challenge"
done
python3 "$ROOT/etc/proteus/bin/ledger.py" append --path "$TMP/ledger.jsonl" --exit-ip "10.7.7.99" \
    --entry-ip "10.6.6.99" --slot proton-1 --source gate --verdict pass --canaries "one.invalid=clean,two.invalid=clean"
fix two.invalid 403 chal; echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check
assert_eq "$(rotations)" "0" "no rotation while unattainable"
assert_eq "$(logged 'not attainable')" y "reason logged"
assert_eq "$(fails cf:two.invalid)" "2" "counter still climbs while unattainable"

echo "...but a mandatory custom check still rotates"
clear_logs
printf '{"checks":[{"url":"https://cust.invalid/","tier":"mandatory"},{"url":"https://adv.invalid/","tier":"advisory"}]}' > "$TMP/checks.json"
fix cust.invalid 403 chal; fix adv.invalid 403 chal
echo 1 > "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid"
run_check
assert_eq "$(rotations)" "1" "custom-check rotation"
assert_eq "$(cat "$TMP/run/proton-1")" custom-check "trigger names the custom check"
assert_eq "$(grep -c adv.invalid "$FIX/hits.log")" 0 "advisory custom checks are not live-watched"
rm -f "$TMP/checks.json" "$TMP/ledger.jsonl" "$TMP/health/.live-lastrot.proton-1"

echo "the step-down retry window holds canary rotations"
clear_logs; date +%s > "$TMP/health/.stepdown-at.proton-1"
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check
assert_eq "$(rotations)" "0" "no rotation inside the window"
assert_eq "$(logged 'since step-down')" y "reason logged"
assert_eq "$(fails cf:two.invalid)" "2" "counter still climbs inside the window"
rm -f "$TMP/health/.stepdown-at.proton-1"

echo "a quarantined canary is probed but not counted"
clear_logs; rm -f "$TMP/ledger.jsonl"
for i in $(seq 1 8); do
  python3 "$ROOT/etc/proteus/bin/ledger.py" append --path "$TMP/ledger.jsonl" --exit-ip "10.5.5.$i" \
    --entry-ip "10.4.4.$i" --slot proton-1 --source gate --verdict fail --canaries "two.invalid=challenge"
done
rm -f "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check
assert_eq "$(cfstate CF_CLEAN)" yes "quarantined failure does not dirty the verdict"
assert_eq "$(fails cf:two.invalid)" "0" "no counter for a quarantined canary"
assert_eq "$(grep -c two.invalid "$FIX/hits.log")" 1 "still probed (how it recovers)"
rm -f "$TMP/ledger.jsonl"

echo "a canary that left Cloudflare is ignored"
clear_logs; fix two.invalid 403 nocf
run_check
assert_eq "$(cfstate CF_CLEAN)" yes "not-cloudflare is not a verdict"
assert_eq "$(fails cf:two.invalid)" "0" "no counter"

echo "the pause flag suppresses it"
clear_logs; fix two.invalid 403 chal; echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
touch "$TMP/state/rotation-paused"
run_check
assert_eq "$(rotations)" "0" "paused -> no rotation"
assert_eq "$(fails cf:two.invalid)" "2" "counter still climbs while paused"
rm -f "$TMP/state/rotation-paused"

echo "a canary transport failure counts but never rotates"
clear_logs; rm -f "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid" "$TMP/ledger.jsonl"
fix two.invalid 000 nocf
run_check; run_check
assert_eq "$(fails cf:two.invalid)" "2" "two transport failures counted"
assert_eq "$(rotations)" "0" "a dead socket is the health path's job, not ours"
assert_eq "$(logged 'cf:two.invalid unreachable (2/2)')" y "logged as unreachable, not as a verdict"
assert_eq "$(cfstate CF_CLEAN)" yes "an unreachable canary is not a dirty Cloudflare verdict"
assert_eq "$(cfstate FAILING)" "" "nothing recorded as failing"
assert_eq "$(python3 -c "import json;print(json.loads(open('$TMP/ledger.jsonl').read().splitlines()[-1])['verdict'])")" \
          pass "recorded as a pass, so a blip cannot drop the exit out of the pool for 24h"
fix two.invalid 200 cf

echo "a custom-check transport failure counts but never rotates"
clear_logs; rm -f "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid" "$TMP/ledger.jsonl"
printf '{"checks":[{"url":"https://cust.invalid/","tier":"mandatory"}]}' > "$TMP/checks.json"
fix cust.invalid 000 nocf
run_check; run_check
assert_eq "$(fails custom:cust.invalid)" "2" "two transport failures counted"
assert_eq "$(rotations)" "0" "no rotation"
assert_eq "$(logged 'custom:cust.invalid unreachable (2/2)')" y "logged as unreachable"
assert_eq "$(cfstate CF_CLEAN)" yes "an unreachable custom check is not a dirty verdict"
assert_eq "$(cfstate FAILING)" "" "nothing recorded as failing"
assert_eq "$(python3 -c "import json;print(json.loads(open('$TMP/ledger.jsonl').read().splitlines()[-1])['verdict'])")" \
          pass "recorded as a pass"
assert_eq "$(python3 -c "import json;print(json.loads(open('$TMP/ledger.jsonl').read().splitlines()[-1])['checks']['custom:cust.invalid'])")" \
          transport "recorded as transport, not a block"
rm -f "$TMP/checks.json"

echo "a slot mid-rotation is skipped entirely"
clear_logs; rm -f "$TMP/health/.cf-state.proton-1" "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
fix two.invalid 403 chal; touch "$FIX/rotating"
run_check
assert_eq "$(logged 'skipped: rotation in progress')" y "skip logged"
assert_eq "$(fails cf:two.invalid)" "0" "counters untouched"
assert_eq "$(grep -c . "$FIX/hits.log")" 0 "nothing probed"
[[ -e "$TMP/health/.cf-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "no verdict written about an exit that is being replaced"
rm -f "$FIX/rotating"

echo "two checks trip in one run: one rotation, and only this slot's counters reset"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/health/.live-lastrot.proton-1"
printf '{"checks":[{"url":"https://cust.invalid/","tier":"mandatory"}]}' > "$TMP/checks.json"
fix cust.invalid 403 chal
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
echo 1 > "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid"
echo 3 > "$TMP/health/.livecheck-fails.proton-10.cf:x"
run_check
assert_eq "$(rotations)" "1" "one rotation, not one per failing check"
assert_eq "$(find "$TMP/health" -maxdepth 1 -name '.livecheck-fails.proton-1.*' | wc -l)" 0 \
          "both counter files cleared"
assert_eq "$(cat "$TMP/health/.livecheck-fails.proton-10.cf:x" 2>/dev/null)" 3 \
          "a sibling slot's counter survives the glob"
rm -f "$TMP/checks.json" "$TMP/health/.livecheck-fails.proton-10.cf:x"

echo "a missing .meta still yields a parseable ledger line"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/state/proton-1.meta"
fix two.invalid 200 cf
run_check
assert_eq "$(python3 -c "import json;d=json.loads(open('$TMP/ledger.jsonl').read().splitlines()[-1]);print(repr(d['exit_ip']),d['verdict'])")" \
          "'' pass" "empty exit_ip, still a valid record"
printf 'LOGICAL_NAME=US-XX#1\nEXIT_IP=9.9.9.1\n' > "$TMP/state/proton-1.meta"

echo "an exit that changes mid-run discards the whole result"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/health/.cf-state.proton-1"
fix two.invalid 200 cf; touch "$FIX/flip-exit"
run_check
rm -f "$FIX/flip-exit"
assert_eq "$(logged 'live check discarded: exit changed during the run')" y "discard logged"
[[ -e "$TMP/health/.cf-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "no verdict about an exit the slot no longer holds"
assert_eq "$(cat "$TMP/ledger.jsonl" 2>/dev/null | wc -l | tr -d ' ')" 0 "nothing filed under the new exit"
printf 'LOGICAL_NAME=US-XX#1\nEXIT_IP=9.9.9.1\n' > "$META"

echo "advisory tier (shadow mode) records but never rotates on canaries"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/health/.live-lastrot.proton-1" "$TMP/health/.stepdown-at.proton-1" "$TMP/state/rotation-paused" "$TMP/checks.json"
fix one.invalid 200 cf; fix two.invalid 403 chal
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(rotations)" "0" "advisory -> no canary rotation"
assert_eq "$(logged 'shadow mode')" y "shadow mode logged"
assert_eq "$(cfstate CF_CLEAN)" no "verdict still recorded"
assert_eq "$(fails cf:two.invalid)" "0" "canary streak reset in shadow mode (no rotation storm on a later flip)"
# .cf-state is display data the dispatcher ignores in advisory; the ledger is
# not — a fail there would drop the exit out of mint's pool for 24h, which is
# the canaries steering selection by the back door.
assert_eq "$(ledger_verdict)" pass "an advisory canary never fails the exit in the ledger"

echo "...while a mandatory custom check still rotates in advisory tier"
clear_logs
printf '{"checks":[{"url":"https://cust.invalid/","tier":"mandatory"}]}' > "$TMP/checks.json"
fix cust.invalid 403 chal
echo 1 > "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(rotations)" "1" "custom-check rotation unaffected by the tier"
rm -f "$TMP/checks.json" "$TMP/health/.live-lastrot.proton-1"

echo "...and in mandatory tier the same canary failure is a ledger fail"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check
assert_eq "$(cfstate CF_CLEAN)" no "verdict recorded in either tier"
assert_eq "$(ledger_verdict)" fail "a mandatory canary failure fails the exit in the ledger"
rm -f "$TMP/health/.live-lastrot.proton-1"

echo "it must NOT write slot health"
for forbidden in 'FAIL_STREAK' 'STATUS=' 'COMPOSITE_SCORE' 'DEGRADED'; do
  grep -q "$forbidden" "$FN" && r=fail || r=ok
  assert_eq "$r" ok "live_check does not touch $forbidden"
done

echo "scheduling never collides with throughput or playability"
grep -qF 'pick_throughput_slot "$((pass_counter + 5))" "$LIVECHECK_EVERY_N_PASSES"' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "live check is offset by 5 passes"
grep -qF 'systemctl start --no-block "proteus-livecheck@$lc_slot.service"' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "the pass starts the live check as its own unit, it does not wait on it"
grep -qF -- '--live-check' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "the --live-check entrypoint the unit calls exists"

summary
