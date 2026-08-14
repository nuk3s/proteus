#!/usr/bin/env bash
# tests/playability_watch_test.sh
#
# rotate-slot.sh gates a CANDIDATE on playability, but an exit that passed can be
# bot-gated days later and nothing noticed: the ongoing health probe pulls from a
# CDN, which a bot-gated exit serves perfectly. These tests pin the re-check that
# closes that gap — including the two things most likely to be "simplified" later:
# it must NOT touch slot health, and it must not rotate on a single blip.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/health" "$TMP/run" "$TMP/state"

# ip: `netns exec <ns> <cmd...>` runs <cmd...> locally so curl is our stub.
cat > "$TMP/bin/ip" <<'IPEOF'
#!/usr/bin/env bash
[ "$1" = "netns" ] && [ "$2" = "exec" ] && { shift 3; exec "$@"; }
exit 0
IPEOF
# curl: body comes from BODY_FILE, or empty to simulate an unreachable exit.
cat > "$TMP/bin/curl" <<'CURLEOF'
#!/usr/bin/env bash
[ -n "${BODY_FILE:-}" ] && [ -r "${BODY_FILE}" ] && cat "${BODY_FILE}"
exit 0
CURLEOF
cat > "$TMP/bin/systemctl" <<'SCEOF'
#!/usr/bin/env bash
echo "$@" >> "${SYSTEMCTL_LOG}"
SCEOF
cat > "$TMP/bin/logger" <<'LGEOF'
#!/usr/bin/env bash
shift 2 2>/dev/null; echo "$*" >> "${LOGGER_LOG}"
LGEOF
chmod +x "$TMP/bin"/*
export PATH="$TMP/bin:$PATH"
export SYSTEMCTL_LOG="$TMP/systemctl.log" LOGGER_LOG="$TMP/logger.log"
: > "$SYSTEMCTL_LOG"; : > "$LOGGER_LOG"

OK_BODY="$TMP/ok.html";   printf 'x%.0s' $(seq 5000) > "$OK_BODY"
printf '{"playabilityStatus":{"status":"OK","x":1}}' >> "$OK_BODY"
GATED="$TMP/gated.html";  printf 'x%.0s' $(seq 5000) > "$GATED"
printf '{"playabilityStatus":{"status":"LOGIN_REQUIRED"}} Sign in to confirm you are not a bot' >> "$GATED"

# Run just the playability_check function out of the real script.
run_check() { # run_check <body-file|""> [fails-seed]
  local body="$1" seed="${2:-}"
  [[ -n "$seed" ]] && echo "$seed" > "$TMP/health/.playability-fails.proton-1"
  BODY_FILE="$body" HEALTH_DIR="$TMP/health" LOG_TAG=slot-warmup \
  PROTEUS_PLAYABILITY_FAILS=2 PROTEUS_PLAYABILITY_ROT_COOLDOWN="${COOLDOWN:-3600}" \
  bash -c '
    HEALTH_DIR='"$TMP"'/health; LOG_TAG=slot-warmup
    PLAYABILITY_UA=ua; PLAYABILITY_URL=http://x/; PLAYABILITY_TIMEOUT_S=5
    PLAYABILITY_MUST_CONTAIN='"'"'"playabilityStatus":{"status":"OK"'"'"'
    PLAYABILITY_FAILS_BEFORE_ROTATE=2
    PLAYABILITY_ROT_COOLDOWN=${PROTEUS_PLAYABILITY_ROT_COOLDOWN}
    # pull the function body out of the real script so the test tracks the source
    eval "$(sed -n "/^playability_check()/,/^}/p" '"$ROOT"'/etc/proteus/bin/slot-warmup.sh)"
    playability_check proton-1' 2>/dev/null
}
fails() { cat "$TMP/health/.playability-fails.proton-1" 2>/dev/null || echo 0; }
rotations() { grep -c 'rotate-slot@proton-1' "$SYSTEMCTL_LOG" 2>/dev/null | head -1; }

echo "a playable exit is a no-op"
run_check "$OK_BODY"
assert_eq "$(fails)" "0" "playable -> fail counter stays 0"
assert_eq "$(rotations)" "0" "playable -> no rotation"

echo "one failure is not enough to rotate (a blip must not move a healthy exit)"
run_check "$GATED"
assert_eq "$(fails)" "1" "first failure counted"
assert_eq "$(rotations)" "0" "one failure -> still no rotation"

echo "two consecutive failures rotate the slot out"
run_check "$GATED"
assert_eq "$(rotations)" "1" "second failure -> rotation triggered"
assert_eq "$(fails)" "0" "counter reset after triggering"
grep -q 'bot-gated' "$LOGGER_LOG" && r=ok || r=fail
assert_eq "$r" ok "bot-gating named in the log, not just 'failed'"
grep -q "^health$" "$TMP/run/proton-1" 2>/dev/null || true

echo "recovery clears the counter"
run_check "$OK_BODY" 1
assert_eq "$(fails)" "0" "a good result resets a partial streak"
grep -q 'playability recovered' "$LOGGER_LOG" && r=ok || r=fail
assert_eq "$r" ok "recovery is logged"

echo "an unreachable exit is counted but reported as transport, not reputation"
: > "$LOGGER_LOG"
run_check "" 0
assert_eq "$(fails)" "1" "empty body counts as a failure"
grep -q 'unreachable' "$LOGGER_LOG" && r=ok || r=fail
assert_eq "$r" ok "unreachable is distinguished from bot-gated in the log"

echo "cooldown throttles repeat rotations"
: > "$SYSTEMCTL_LOG"
echo "$(date +%s)" > "$TMP/health/.playability-lastrot.proton-1"
run_check "$GATED" 1     # would otherwise hit the threshold and rotate
assert_eq "$(rotations)" "0" "within cooldown -> no rotation"
grep -q 'on cooldown' "$LOGGER_LOG" && r=ok || r=fail
assert_eq "$r" ok "cooldown is logged"

echo "the pause flag suppresses it like every other rotation path"
: > "$SYSTEMCTL_LOG"; rm -f "$TMP/health/.playability-lastrot.proton-1"
mkdir -p "$TMP/state"
if [[ -w /etc/proteus/state ]] 2>/dev/null; then echo "  - skipped (would touch real state dir)"; else
  # the function reads a fixed path; assert the guard exists in the source instead
  grep -q 'rotation-paused' <(sed -n '/^playability_check()/,/^}/p' "$ROOT/etc/proteus/bin/slot-warmup.sh") && r=ok || r=fail
  assert_eq "$r" ok "playability_check honours /etc/proteus/state/rotation-paused"
fi

echo "it must NOT write slot health (a bot-gated exit is fine for non-streaming)"
sed -n '/^playability_check()/,/^}/p' "$ROOT/etc/proteus/bin/slot-warmup.sh" > "$TMP/fn.sh"
for forbidden in 'FAIL_STREAK' 'STATUS=' 'COMPOSITE_SCORE' 'DEGRADED'; do
  grep -q "$forbidden" "$TMP/fn.sh" && r=fail || r=ok
  assert_eq "$r" ok "playability_check does not touch $forbidden"
done

echo "the desktop UA stays pinned (a mobile UA misses bot-gating entirely)"
grep -q 'PLAYABILITY_UA=.*Windows NT' "$ROOT/etc/proteus/bin/slot-warmup.sh" && r=ok || r=fail
assert_eq "$r" ok "playability UA is a pinned desktop string"

summary
