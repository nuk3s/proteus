#!/usr/bin/env bash
# tests/livecheck_test.sh — slot-warmup.sh live_check: Cloudflare canaries and
# mandatory custom checks re-run on promoted slots. Pins the things a future
# "simplification" would break: two fails before acting, one shared cooldown,
# the attainability gate for canaries only, a verdict only from an observation,
# quick checks for unverified slots, no health writes, and PROTEUS_CF_TIER:
# mandatory (the default) acts on canaries, advisory records and shows only.
set -euo pipefail
# The mandatory cases below rely on the default tier. A tier exported by the
# shell that runs the suite must not change them.
unset PROTEUS_CF_TIER
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
# Simulates a rotation starting mid-run before it records the new exit.
if [ "$host" = "two.invalid" ] && [ -e "$FIX/start-rotation" ]; then
  touch "$FIX/rotating"
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
# the test says so. Like systemd for a running oneshot unit, it prints the state
# and exits 3 either way. Deliberately NOT logged: it names the rotate unit, and
# rotations() counts lines that mention it.
if [ "$1" = "is-active" ]; then
  if [ -e "$FIX/rotating" ]; then echo activating; else echo inactive; fi
  exit 3
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
for f in _health_get _meta_get _live_fail _live_ok _rotating live_check livecheck_quick_slots livecheck_turn_slots livecheck_off_clear_flags; do
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
echo 2 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check
assert_eq "$(fails cf:two.invalid)" "0" "a streak from when it was on Cloudflare is reset"

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
printf 'CF_CLEAN=yes\nAT=5\nFAILING=\n' > "$TMP/health/.cf-state.proton-1"
run_check; run_check
assert_eq "$(fails cf:two.invalid)" "2" "two transport failures counted"
assert_eq "$(rotations)" "0" "a dead socket is the health path's job, not ours"
assert_eq "$(logged 'cf:two.invalid unreachable (2/2)')" y "logged as unreachable, not as a verdict"
assert_eq "$(cfstate CF_CLEAN)" yes "an unreachable canary does not flag the exit"
assert_eq "$(cfstate AT)" 5 "and it observed nothing, so the verdict is left as it was"
assert_eq "$(python3 -c "import json;print(json.loads(open('$TMP/ledger.jsonl').read().splitlines()[-1])['verdict'])")" \
          pass "recorded as a pass, so a blip cannot drop the exit out of the pool for 24h"
echo "an unreachable canary leaves a flag in place, and gives an unchecked slot no verdict"
printf 'CF_CLEAN=no\nAT=5\nFAILING=two.invalid\n' > "$TMP/health/.cf-state.proton-1"
run_check
assert_eq "$(cfstate CF_CLEAN)" no "a run that could not see the canary does not clear a flag"
rm -f "$TMP/health/.cf-state.proton-1"
run_check
[[ -e "$TMP/health/.cf-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "and does not claim cf ok for a slot with no verdict"
rm -f "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
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

echo "a rotation that starts mid-run discards the result before the exit changes"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/health/.cf-state.proton-1"
fix two.invalid 200 cf; touch "$FIX/start-rotation"
run_check
rm -f "$FIX/start-rotation" "$FIX/rotating"
assert_eq "$(logged 'live check discarded')" y "discard logged"
[[ -e "$TMP/health/.cf-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "no verdict about an exit that is being replaced"
assert_eq "$(cat "$TMP/ledger.jsonl" 2>/dev/null | wc -l | tr -d ' ')" 0 "nothing filed"

echo "no active canary (none behind Cloudflare) is cf ok"
clear_logs; fix one.invalid 200 nocf; fix two.invalid 403 nocf
run_check
assert_eq "$(cfstate CF_CLEAN)" yes "CF_CLEAN=yes with no active canary"
fix one.invalid 200 cf; fix two.invalid 200 cf

echo "mandatory tier (the default): a canary flag fails the exit and a confirmed flag rotates"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid" \
  "$TMP/health/.live-lastrot.proton-1" "$TMP/state/rotation-paused" "$TMP/checks.json"
fix one.invalid 200 cf; fix two.invalid 403 chal
run_check
assert_eq "$(cfstate CF_CLEAN)" no "flag recorded"
assert_eq "$(ledger_verdict)" fail "a canary failure fails the exit in the ledger"
assert_eq "$(rotations)" "0" "one failure -> no rotation"
run_check
assert_eq "$(rotations)" "1" "a confirmed flag rotates"
assert_eq "$(cat "$TMP/run/proton-1")" cf-canary "trigger names the canary watch"
rm -f "$TMP/health/.live-lastrot.proton-1"

echo "advisory tier: canaries record and show, nothing acts on them"
clear_logs; rm -f "$TMP/ledger.jsonl" "$TMP/health/.livecheck-fails.proton-1."* "$TMP/run/proton-1"
fix one.invalid 200 cf; fix two.invalid 403 chal
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(cfstate CF_CLEAN)" no "the flag is recorded for the tunnel card"
assert_eq "$(cfstate FAILING)" two.invalid "the failing host is recorded"
# A fail would drop the exit out of mint's pool for 24h: the canaries would
# steer the draw after all.
assert_eq "$(ledger_verdict)" pass "a canary flag alone is a ledger pass"
assert_eq "$(fails cf:two.invalid)" "0" \
  "the streak is cleared on every advisory run: a switch to mandatory needs two fresh failures"
# A streak a mandatory run left behind before the operator switched to advisory.
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(rotations)" "0" "a confirmed flag does not rotate"
assert_eq "$(logged 'canary failing but cf ok is not required (PROTEUS_CF_TIER=advisory); not rotating')" y \
  "the log says that cf ok is not required"
[[ -e "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid" ]] && r=present || r=absent
assert_eq "$r" absent "the canary streak files are gone: a later switch to mandatory does not act on old failures"
[[ -e "$TMP/run/proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "no rotation trigger written"
[[ -e "$TMP/health/.live-lastrot.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "no cooldown stamp: the shared cooldown stays free for a custom check"

echo "advisory tier: the reset comes before the attainability gate"
clear_logs; rm -f "$TMP/ledger.jsonl"
for i in $(seq 1 11); do
  python3 "$ROOT/etc/proteus/bin/ledger.py" append --path "$TMP/ledger.jsonl" --exit-ip "10.7.7.$i" \
    --entry-ip "10.6.6.$i" --slot proton-1 --source gate --verdict fail --canaries "one.invalid=clean,two.invalid=challenge"
done
python3 "$ROOT/etc/proteus/bin/ledger.py" append --path "$TMP/ledger.jsonl" --exit-ip "10.7.7.99" \
    --entry-ip "10.6.6.99" --slot proton-1 --source gate --verdict pass --canaries "one.invalid=clean,two.invalid=clean"
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(logged 'not attainable')" n "the attainability gate is not reached"
assert_eq "$(logged 'cf ok is not required')" y "the tier answers first"
[[ -e "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid" ]] && r=present || r=absent
assert_eq "$r" absent "and the streak is reset even when the standard is not attainable"
rm -f "$TMP/ledger.jsonl"

echo "advisory tier: a mandatory custom check still rotates"
clear_logs
printf '{"checks":[{"url":"https://cust.invalid/","tier":"mandatory"}]}' > "$TMP/checks.json"
fix cust.invalid 403 chal
echo 1 > "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(ledger_verdict)" fail "a custom-check failure fails the exit in either tier"
assert_eq "$(rotations)" "1" "custom-check rotation unaffected by the tier"
assert_eq "$(cat "$TMP/run/proton-1")" custom-check "trigger names the custom check"
rm -f "$TMP/checks.json" "$TMP/health/.live-lastrot.proton-1" "$TMP/health/.livecheck-fails.proton-1."*

echo "advisory tier: a pause does not keep a canary streak"
clear_logs; rm -f "$TMP/ledger.jsonl"
fix two.invalid 403 chal
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
touch "$TMP/state/rotation-paused"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(rotations)" "0" "paused -> no rotation"
[[ -e "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid" ]] && r=present || r=absent
assert_eq "$r" absent "the canary streak at the threshold is reset while paused"
assert_eq "$(logged 'cf ok is not required')" y "the tier answers before the pause gate"

echo "advisory tier: a paused custom-check trigger does not rotate"
clear_logs
printf '{"checks":[{"url":"https://cust.invalid/","tier":"mandatory"}]}' > "$TMP/checks.json"
fix cust.invalid 403 chal
echo 1 > "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(logged 'live-check rotation suppressed (paused)')" y "the custom-check trigger reaches the pause gate"
assert_eq "$(rotations)" "0" "paused -> no rotation"
rm -f "$TMP/state/rotation-paused"

echo "advisory tier: a custom check and a canary trip in one run"
clear_logs; rm -f "$TMP/health/.livecheck-fails.proton-1."*
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
echo 1 > "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(rotations)" "1" "the custom check rotates"
assert_eq "$(cat "$TMP/run/proton-1")" custom-check "trigger names the custom check"
[[ -e "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid" ]] && r=present || r=absent
assert_eq "$r" absent "the canary streak files are gone"
echo "...and on cooldown the canary streak still goes, the custom-check streak stays"
clear_logs
echo 1 > "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid"
echo 1 > "$TMP/health/.livecheck-fails.proton-1.custom:cust.invalid"
run_check PROTEUS_CF_TIER=advisory
assert_eq "$(rotations)" "0" "within cooldown -> no rotation"
[[ -e "$TMP/health/.livecheck-fails.proton-1.cf:two.invalid" ]] && r=present || r=absent
assert_eq "$r" absent "the canary streak is reset"
assert_eq "$(fails custom:cust.invalid)" "2" "the custom-check streak is kept"
rm -f "$TMP/checks.json" "$TMP/health/.live-lastrot.proton-1" "$TMP/health/.livecheck-fails.proton-1."* "$TMP/ledger.jsonl"
fix two.invalid 200 cf

echo "quick checks: an unverified slot or an unconfirmed flag joins the turn"
QH="$TMP/quick"; mkdir -p "$QH"
quick() { # quick <round-robin slot> <slot list> -> the turn's slots, space-separated
  # checklib.sh sets CF_TIER from PROTEUS_CF_TIER, as in the real script.
  bash -c '
    set -u
    HEALTH_DIR='"$QH"'; LIVECHECK_FAILS_BEFORE_ROTATE=2
    . '"$ROOT"'/etc/proteus/bin/checklib.sh
    . '"$FN"'
    livecheck_turn_slots "$1" "$2"' _ "$1" "$2" | tr '\n' ' ' | sed 's/ $//'
}
printf 'CF_CLEAN=yes\nAT=1\nFAILING=\n' > "$QH/.cf-state.proton-1"
printf 'CF_CLEAN=no\nAT=1\nFAILING=b\n'  > "$QH/.cf-state.proton-2"; echo 1 > "$QH/.livecheck-fails.proton-2.cf:b"
# proton-3 has no .cf-state: no verdict yet
printf 'CF_CLEAN=no\nAT=1\nFAILING=b\n'  > "$QH/.cf-state.proton-4"; echo 2 > "$QH/.livecheck-fails.proton-4.cf:b"
printf 'CF_CLEAN=yes\nAT=1\nFAILING=\n' > "$QH/.cf-state.proton-5"; echo 1 > "$QH/.livecheck-fails.proton-5.custom:x"
ALL='proton-1 proton-2 proton-3 proton-4 proton-5'
assert_eq "$(quick proton-1 "$ALL")" "proton-1 proton-2 proton-3" \
  "round-robin slot first, then the unconfirmed flag and the unchecked slot"
assert_eq "$(quick proton-2 "$ALL")" "proton-2 proton-3" "a slot that is both starts once"
assert_eq "$(quick proton-4 "$ALL")" "proton-4 proton-2 proton-3" \
  "a confirmed flag (streak at the threshold) gets only its round-robin turn"
printf 'CF_CLEAN=no\nAT=1\nFAILING=b\n' > "$QH/.cf-state.proton-1"
assert_eq "$(quick proton-5 'proton-1 proton-5')" "proton-5 proton-1" \
  "a flag with no streak file (counters cleared by an all-fail rotation) is unconfirmed"
assert_eq "$(quick proton-5 'proton-5')" "proton-5" "a custom-check streak does not make a slot quick"
# proton-6 has no .cf-state and a canary streak at the threshold: a canary it
# cannot reach. Unbounded, it would join every turn forever.
echo 2 > "$QH/.livecheck-fails.proton-6.cf:b"
assert_eq "$(quick proton-5 'proton-5 proton-6')" "proton-5" \
  "a slot with no verdict whose streak is at the threshold gets only its round-robin turn"
# A verdict file that does not say yes is read as no verdict, like a missing one.
printf 'garbage\n' > "$QH/.cf-state.proton-7"
assert_eq "$(quick proton-5 'proton-5 proton-7')" "proton-5 proton-7" \
  "a malformed verdict with no streak is quick"
echo 2 > "$QH/.livecheck-fails.proton-7.cf:b"
assert_eq "$(quick proton-5 'proton-5 proton-7')" "proton-5" \
  "a malformed verdict whose streak is at the threshold gets only its round-robin turn"
# The stub's rotating marker covers every slot, so keep it to this one assert.
touch "$FIX/rotating"
assert_eq "$(quick proton-5 'proton-5 proton-3')" "proton-5" "a rotating slot is never quick"
rm -f "$FIX/rotating"
echo "quick checks: none in advisory tier (nothing acts on a flag)"
assert_eq "$(quick proton-5 "$ALL")" "proton-5 proton-1 proton-2 proton-3" \
  "mandatory: the unconfirmed flags and the unchecked slot join the turn"
assert_eq "$(PROTEUS_CF_TIER=advisory quick proton-5 "$ALL")" "proton-5" \
  "advisory: only the round-robin slot, even with an unconfirmed flag present"

echo "with live checks off, a flag is dropped (nothing can confirm or clear it)"
OH="$TMP/off"; mkdir -p "$OH"
printf 'CF_CLEAN=no\nAT=1\nFAILING=b\n'  > "$OH/.cf-state.proton-1"
printf 'CF_CLEAN=yes\nAT=1\nFAILING=\n' > "$OH/.cf-state.proton-2"
bash -c 'set -u; HEALTH_DIR='"$OH"'; . '"$FN"'; livecheck_off_clear_flags "proton-1 proton-2 proton-3"'
[[ -e "$OH/.cf-state.proton-1" ]] && r=present || r=absent
assert_eq "$r" absent "the flag is gone: the slot is unchecked, as after a reboot"
assert_eq "$(grep -cx 'CF_CLEAN=yes' "$OH/.cf-state.proton-2")" 1 "a cf ok verdict stays"
[[ -e "$OH/.cf-state.proton-3" ]] && r=present || r=absent
assert_eq "$r" absent "a slot with no verdict gets none"

echo "it must NOT write slot health"
for forbidden in 'FAIL_STREAK' 'STATUS=' 'COMPOSITE_SCORE' 'DEGRADED'; do
  grep -q "$forbidden" "$FN" && r=fail || r=ok
  assert_eq "$r" ok "live_check does not touch $forbidden"
done

echo "scheduling never collides with throughput or playability"
grep -qF 'pick_throughput_slot "$((pass_counter + 5))" "$LIVECHECK_EVERY_N_PASSES"' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "live check is offset by 5 passes"
grep -qF 'systemctl start --no-block "proteus-livecheck@$s.service"' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "the pass starts each of the turn's live checks as its own unit, it does not wait on them"
grep -qF 'livecheck_turn_slots "$lc_slot" "$slot_list"' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "quick checks run only at a live-check turn"
assert_eq "$(grep -cE 'STEPDOWN|stepdown' "$ROOT/etc/proteus/bin/slot-warmup.sh" || true)" 0 \
  "no step-down left in slot-warmup.sh"
grep -qF 'livecheck_off_clear_flags "$slot_list"' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "the pass drops stale flags when live checks are off"
grep -qF -- '--live-check' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "the --live-check entrypoint the unit calls exists"

summary
