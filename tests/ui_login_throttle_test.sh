#!/usr/bin/env bash
# tests/ui_login_throttle_test.sh
#
# /api/login runs 600k PBKDF2 rounds BEFORE any authentication exists, and
# hashlib releases the GIL, so unthrottled concurrent logins burn one core each.
# On this gateway that starves the NFQUEUE dispatcher, which routes every
# client's traffic — a login flood becomes gateway-wide packet loss. These tests
# pin the two properties that prevent it: verifications are serialised, and
# excess load is shed rather than queued.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); SRV=""
cleanup() { [[ -n "$SRV" ]] && kill "$SRV" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

command -v openssl >/dev/null || { echo "  - skipped (no openssl)"; exit 0; }

mkdir -p "$TMP/secrets/tls"
# Low iteration count keeps the suite fast; the throttle behaviour under test is
# independent of the cost, and using the real 600k would add ~2s per attempt.
python3 -c "
import sys; sys.path.insert(0,'$ROOT/etc/proteus/bin'); import ui_logic
open('$TMP/secrets/passwd','w').write(ui_logic.hash_passphrase('correct horse battery', iterations=200000)+chr(10))"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=test" -keyout "$TMP/secrets/tls/key.pem" -out "$TMP/secrets/tls/cert.pem" >/dev/null 2>&1

# Pick a free port rather than hardcoding: a stale listener from an earlier
# run would otherwise fail this suite in a way that looks like a code defect.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
PROTEUS_UI_SECRETS="$TMP/secrets" PROTEUS_UI_PORT="$PORT" \
  python3 "$ROOT/etc/proteus/bin/proteus-ui" >"$TMP/srv.log" 2>&1 &
SRV=$!
for _ in $(seq 40); do
  curl -sk --max-time 1 -o /dev/null "https://127.0.0.1:$PORT/api/status" && break
  sleep 0.25
done
kill -0 $SRV 2>/dev/null || { echo "  - skipped (daemon did not start)"; sed 's/^/    /' "$TMP/srv.log"; exit 0; }

login() { curl -sk --max-time 20 -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -d '{"passphrase":"wrong guess here"}' "https://127.0.0.1:$PORT/api/login"; }

echo "a single wrong passphrase is still rejected normally"
assert_eq "$(login)" "401" "lone bad login -> 401"

echo "concurrent logins are shed, not all executed"
pids=()
for i in $(seq 40); do login > "$TMP/c$i" & pids+=("$!"); done
# Wait ONLY on the login jobs: a bare `wait` would also wait on the daemon,
# which never exits.
for p in "${pids[@]}"; do wait "$p" || true; done   # curl rc is not the assertion; codes are
codes=$(awk '{print $0}' "$TMP"/c* | sort | uniq -c | tr '\n' ' ')
# awk, not `grep -c`: grep exits 1 when the count is zero, and under
# `set -euo pipefail` that aborted the run before any assertion could report.
# Per FILE, not `cat`: curl -w writes the code with no trailing newline, so
# concatenating 40 of them yields one long line and an anchored match finds
# nothing. awk takes the file list directly and still exits 0 on zero matches.
n429=$(awk '$0=="429"{n++} END{print n+0}' "$TMP"/c*)
n401=$(awk '$0=="401"{n++} END{print n+0}' "$TMP"/c*)
echo "    codes seen: $codes"
[[ $((n429 + n401)) -eq 40 ]] && r=ok || r=fail
assert_eq "$r" ok "all 40 concurrent requests answered (no hangs/5xx): 401=$n401 429=$n429"
[[ $n429 -ge 1 ]] && r=ok || r=fail
assert_eq "$r" ok "at least one request shed with 429 instead of burning a core"

echo "the daemon survives the flood and still serves"
kill -0 $SRV 2>/dev/null && r=ok || r=fail
assert_eq "$r" ok "daemon still running after concurrent login flood"

echo "the global ceiling engages once enough failures accumulate"
# Per-source limit is 5/60s; from one source this locks out quickly and must
# keep returning 429 rather than continuing to spend CPU.
for _ in $(seq 6); do login >/dev/null; done
assert_eq "$(login)" "429" "locked-out source gets 429 without a verification"

grep -qE 'login (busy|lockout)' "$TMP/srv.log" && r=ok || r=fail
assert_eq "$r" ok "throttling is logged for the operator"

echo "an idle TCP connection cannot wedge the accept loop"
# Wrapping the LISTENING socket puts the TLS handshake inside serve_forever's
# single accept loop, so a client that completes the TCP handshake and then
# says nothing blocks every other connection. Costs one socket and no auth.
python3 - "$PORT" <<'IDLE' &
import socket, sys, time
socks = [socket.create_connection(("127.0.0.1", int(sys.argv[1]))) for _ in range(3)]
time.sleep(10)
IDLE
HOLDER=$!
sleep 2
code=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PORT/api/status" || echo 000)
kill $HOLDER 2>/dev/null; wait $HOLDER 2>/dev/null || true
assert_eq "$code" "401" "panel still answers while 3 sockets sit idle mid-handshake"

summary
