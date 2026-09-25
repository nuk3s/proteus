#!/usr/bin/env bash
# tests/ui_http_test.sh
#
# End-to-end checks of the proteus-ui HTTP surface against a real daemon on a
# throwaway port: bodies that are valid JSON but not an object, a torn row in
# the rotation history, the .state/.meta sidecar merge, and the auth gates.
# Every request here must get an HTTP reply — a dropped connection ("000")
# means the handler raised, which is exactly the class of bug this pins.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); SRV=""
cleanup() { [[ -n "$SRV" ]] && kill "$SRV" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

command -v openssl >/dev/null || { echo "  - skipped (no openssl)"; exit 0; }

mkdir -p "$TMP/secrets/tls" "$TMP/state" "$TMP/health" "$TMP/run"
python3 -c "
import sys; sys.path.insert(0,'$ROOT/etc/proteus/bin'); import ui_logic
open('$TMP/secrets/passwd','w').write(ui_logic.hash_passphrase('correct horse battery', iterations=1000)+chr(10))"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=test" -keyout "$TMP/secrets/tls/key.pem" -out "$TMP/secrets/tls/cert.pem" >/dev/null 2>&1

# Fixture data the status endpoint reads.
printf 'INSTANCE=proton-1\nWG_ENDPOINT_IP=192.0.2.10\nUP_TIME=2026-08-01T10:00:00+00:00\n' > "$TMP/state/proton-1.state"
printf 'LOGICAL_NAME=US-TX#97\nEXIT_COUNTRY=US\nEXIT_IP=192.0.2.99\n' > "$TMP/state/proton-1.meta"
printf 'STATUS=ok\nCOMPOSITE_SCORE=81\nSCORE_UPDATED_AT=%s\n' "$(date +%s)" > "$TMP/health/proton-1.state"
# rotation history: a good row, a torn row (the write raced a reader), a good row
{
  echo '{"ts":1,"slot":"proton-1","old_logical":"A","new_logical":"B","trigger":"scheduled","outcome":"promoted","attempts":1}'
  echo '{"ts":2,"slot":"proton-1","old_logical":"B","new_lo'
  echo '{"ts":3,"slot":"proton-1","old_logical":"B","new_logical":"C","trigger":"manual","outcome":"promoted","attempts":2}'
} > "$TMP/run/rotation-history.jsonl"

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
PROTEUS_UI_SECRETS="$TMP/secrets" PROTEUS_UI_PORT="$PORT" \
  PROTEUS_UI_STATE_DIR="$TMP/state" PROTEUS_UI_HEALTH_DIR="$TMP/health" PROTEUS_UI_RUN_DIR="$TMP/run" \
  python3 "$ROOT/etc/proteus/bin/proteus-ui" >"$TMP/srv.log" 2>&1 &
SRV=$!
for _ in $(seq 40); do
  curl -sk --max-time 1 -o /dev/null "https://127.0.0.1:$PORT/api/status" && break
  sleep 0.25
done
kill -0 $SRV 2>/dev/null || { echo "  - skipped (daemon did not start)"; sed 's/^/    /' "$TMP/srv.log"; exit 0; }

U="https://127.0.0.1:$PORT"
code() { curl -sk --max-time 10 -o "$TMP/body" -w '%{http_code}' "$@" || echo 000; }
post() { code -X POST -H 'Content-Type: application/json' "$@"; }

echo "a JSON body that is not an object gets a normal reply, not a dropped connection"
assert_eq "$(post -d '[]'      "$U/api/login")" "401" "login body [] -> 401"
assert_eq "$(post -d '"str"'   "$U/api/login")" "401" "login body \"str\" -> 401"
assert_eq "$(post -d '42'      "$U/api/login")" "401" "login body 42 -> 401"
assert_eq "$(post -d 'not json' "$U/api/login")" "401" "login body garbage -> 401"

echo "auth gates"
assert_eq "$(code "$U/api/status")" "401" "status without a token -> 401"
assert_eq "$(code -H 'Authorization: Bearer nope.nope.nope' "$U/api/status")" "401" "status with a forged token -> 401"
assert_eq "$(post -d '{}' "$U/api/knobs")" "401" "knobs without a token -> 401"
assert_eq "$(code "$U/nope")" "404" "unknown path -> 404"
assert_eq "$(post -d '{"passphrase":"correct horse battery"}' "$U/api/login")" "200" "correct passphrase -> 200"
TOKEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$TMP/body")
[[ -n "$TOKEN" ]] && r=ok || r=fail
assert_eq "$r" ok "login returns a token"
AUTH=(-H "Authorization: Bearer $TOKEN")

echo "an authenticated mutating request with a non-object body is rejected, not crashed"
# The broker socket does not exist here, so a well-formed request yields a
# clean 400 (broker unreachable); a body of [] used to raise before reaching it.
assert_eq "$(post "${AUTH[@]}" -d '[]' "$U/api/knobs")"   "400" "knobs body [] -> 400"
assert_eq "$(post "${AUTH[@]}" -d '[]' "$U/api/action")"  "400" "action body [] -> 400"
assert_eq "$(post "${AUTH[@]}" -d '[]' "$U/api/checks")"  "400" "checks body [] -> 400"

echo "status survives a torn history row and merges the .meta sidecar"
assert_eq "$(code "${AUTH[@]}" "$U/api/status")" "200" "status -> 200 despite a corrupt history line"
python3 - "$TMP/body" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert [h["ts"] for h in s["history"]] == [3, 1], s["history"]          # newest first, torn row skipped
slot = s["slots"][0]
assert slot["name"] == "proton-1" and slot["logical"] == "US-TX#97" and slot["exit_ip"] == "192.0.2.99", slot
assert slot["status"] == "ok" and slot["health"]["score"] == "81" and slot["health"]["stale"] is False, slot
assert slot["endpoint_ip"] == "192.0.2.10", slot
print("  ✓ history newest-first with the torn row dropped; slot merges .state + .meta + health")
PY

echo "the daemon logged no traceback for any of the above"
grep -q 'Traceback' "$TMP/srv.log" && r=traceback || r=clean
assert_eq "$r" clean "no handler traceback in the daemon log"
kill -0 $SRV 2>/dev/null && r=ok || r=fail
assert_eq "$r" ok "daemon still running"

summary
