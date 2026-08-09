#!/usr/bin/env bash
# tests/ui_apply_test.sh
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/dropin" "$TMP/trigger"
cat > "$TMP/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "$@" >> "${SYSTEMCTL_LOG}"
if [[ "$1" == "restart" && -f "${SYSTEMCTL_FAIL_FLAG:-/nonexistent-flag}" ]]; then
  exit 1
fi
EOF
chmod +x "$TMP/bin/systemctl"
export SYSTEMCTL_LOG="$TMP/systemctl.log"; touch "$SYSTEMCTL_LOG"
export SYSTEMCTL_FAIL_FLAG="$TMP/fail-restart"
export PATH="$TMP/bin:$PATH"

SOCK="$TMP/apply.sock"
python3 "$ROOT/etc/proteus/bin/proteus-ui-apply" \
  --test-socket "$SOCK" --env-file "$TMP/local.env" \
  --dropin-dir "$TMP/dropin" --flag-file "$TMP/paused" \
  --trigger-dir "$TMP/trigger" --checks-file "$TMP/checks.json" &
BROKER=$!; sleep 0.3
trap 'kill $BROKER 2>/dev/null; rm -rf "$TMP"' EXIT

req() { printf '%s\n' "$1" | python3 -c '
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read()); print(s.makefile().readline().strip())
' "$SOCK"; }

ok_field() { python3 -c 'import json,sys;print(json.load(sys.stdin)["ok"])'; }

# valid set writes overlay atomically
OUT=$(req '{"cmd":"set","key":"PROTEUS_STREAMING_MIN_MBPS","value":"30"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "set ok"
grep -q '^PROTEUS_STREAMING_MIN_MBPS=30$' "$TMP/local.env" || { echo "FAIL overlay"; exit 1; }

# re-set the same key: overlay is deduped, not appended
req '{"cmd":"set","key":"PROTEUS_STREAMING_MIN_MBPS","value":"40"}' >/dev/null
COUNT=$(grep -c '^PROTEUS_STREAMING_MIN_MBPS=' "$TMP/local.env")
assert_eq "$COUNT" "1" "overlay dedup: one line for the key"
grep -q '^PROTEUS_STREAMING_MIN_MBPS=40$' "$TMP/local.env" || { echo "FAIL dedup value"; exit 1; }

# overlay write is atomic and mode 644, no leftover tmp file
[ -f "$TMP/local.env.tmp" ] && { echo "FAIL: local.env.tmp leftover"; exit 1; }
assert_eq "$(stat -c %a "$TMP/local.env")" "644" "overlay file mode"

# reject: range, unknown key, unknown cmd, bad slot name
for bad in '{"cmd":"set","key":"PROTEUS_STREAMING_MIN_MBPS","value":"9999"}' \
           '{"cmd":"set","key":"EVIL","value":"1"}' \
           '{"cmd":"fork-bomb"}' \
           '{"cmd":"rotate","slot":"proton-1; reboot"}'; do
  OUT=$(req "$bad")
  assert_eq "$(echo "$OUT" | ok_field)" "False" "reject: $bad"
done

# dispatcher knob kicks restart
req '{"cmd":"set","key":"PROTEUS_SPREAD_BAND","value":"60"}' >/dev/null
grep -q 'restart proteus-dispatcher.service' "$SYSTEMCTL_LOG" || { echo "FAIL kick"; exit 1; }

# kick restart failure: overlay already saved, broker reports it honestly (not silently or masked)
touch "$SYSTEMCTL_FAIL_FLAG"
OUT=$(req '{"cmd":"set","key":"PROTEUS_SPREAD_BAND","value":"77"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "kick restart failure reported"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["error"])')" \
  "saved but proteus-dispatcher.service restart failed" "kick restart failure: honest error text"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["saved"])')" \
  "True" "kick restart failure: saved flag set"
grep -q '^PROTEUS_SPREAD_BAND=77$' "$TMP/local.env" || { echo "FAIL: value not saved despite restart failure"; exit 1; }
rm -f "$SYSTEMCTL_FAIL_FLAG"

# restart-dispatcher command
req '{"cmd":"restart-dispatcher"}' >/dev/null
grep -q 'restart proteus-dispatcher.service' "$SYSTEMCTL_LOG" || { echo "FAIL restart-dispatcher"; exit 1; }

# rotate writes trigger file then starts unit
req '{"cmd":"rotate","slot":"proton-2"}' >/dev/null
assert_eq "$(cat "$TMP/trigger/proton-2")" "manual" "trigger file"
grep -q 'start --no-block proteus-rotate-slot@proton-2.service' "$SYSTEMCTL_LOG" || { echo "FAIL rotate"; exit 1; }

# dns slots are out of v1 scope for manual rotation — no proteus-rotate-slot@ unit exists for them
OUT=$(req '{"cmd":"rotate","slot":"dns-6"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "dns rotate rejected"

# pause/resume flag file
req '{"cmd":"pause"}' >/dev/null;  [ -f "$TMP/paused" ] || { echo "FAIL pause"; exit 1; }
req '{"cmd":"resume"}' >/dev/null; [ ! -f "$TMP/paused" ] || { echo "FAIL resume"; exit 1; }

# cadence drop-in
req '{"cmd":"set-cadence","on_calendar":"daily","randomized_delay":"6h"}' >/dev/null
grep -q 'RandomizedDelaySec=6h' "$TMP/dropin/override.conf" || { echo "FAIL dropin"; exit 1; }
grep -q 'daemon-reload' "$SYSTEMCTL_LOG" || { echo "FAIL reload"; exit 1; }

# cadence flag-injection: a leading-dash value must not be parsed as a systemd-analyze option
OUT=$(req '{"cmd":"set-cadence","on_calendar":"-h","randomized_delay":"6h"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "cadence -h not treated as a flag"
OUT=$(req '{"cmd":"set-cadence","on_calendar":"daily","randomized_delay":"-h"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "cadence delay -h rejected"

# non-dict JSON: valid JSON but not an object — must not crash, must report ok:false
for j in '[]' '123'; do
  OUT=$(req "$j")
  assert_eq "$(echo "$OUT" | ok_field)" "False" "non-dict JSON rejected: $j"
done

# malformed/binary input must not crash the broker (regression for the readline-outside-try bug)
printf '\xff\xfe\x00garbage\n' | python3 -c '
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read())
try:
    s.makefile().readline()
except Exception:
    pass
' "$SOCK"
sleep 0.2
kill -0 "$BROKER" 2>/dev/null || { echo "FAIL: broker died on binary input"; exit 1; }
OUT=$(req '{"cmd":"pause"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "broker still serving after binary input"
req '{"cmd":"resume"}' >/dev/null

# set-checks: valid list writes checks.json (640), atomic, correct content
OUT=$(req '{"cmd":"set-checks","checks":[{"url":"https://www.example.com/","tier":"advisory"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "set-checks valid ok"
[ -f "$TMP/checks.json" ] || { echo "FAIL: checks.json not written"; exit 1; }
grep -q 'www.example.com' "$TMP/checks.json" || { echo "FAIL: checks.json content"; exit 1; }
[ ! -f "$TMP/checks.json.tmp" ] || { echo "FAIL: leftover checks tmp"; exit 1; }
assert_eq "$(stat -c '%a' "$TMP/checks.json")" "640" "checks.json mode 640"
# set-checks rejects a bad scheme and a non-list
for bad in '{"cmd":"set-checks","checks":[{"url":"ftp://x/","tier":"advisory"}]}' \
           '{"cmd":"set-checks","checks":"nope"}'; do
  OUT=$(req "$bad")
  assert_eq "$(echo "$OUT" | ok_field)" "False" "set-checks reject: $bad"
done

summary
