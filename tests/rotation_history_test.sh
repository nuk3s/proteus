#!/usr/bin/env bash
# tests/rotation_history_test.sh
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
export PROTEUS_HISTORY_FILE="$TMP/hist.jsonl"

. "$ROOT/etc/proteus/bin/history.sh"
for i in $(seq 1 60); do
  history_append "proton-1" "NL#$i" "NL#$((i+1))" "scheduled" "promoted" "1"
done
assert_eq "$(wc -l < "$PROTEUS_HISTORY_FILE")" "50" "ring capped at 50"
tail -1 "$PROTEUS_HISTORY_FILE" | python3 -c '
import json,sys; e=json.load(sys.stdin)
assert e["new_logical"]=="NL#61" and e["trigger"]=="scheduled" and "ts" in e'
# a logical name with a quote must not corrupt the ring
history_append "proton-2" 'NL#3"x' "NL#9" "manual" "promoted" "2"
tail -1 "$PROTEUS_HISTORY_FILE" | python3 -c '
import json,sys; e=json.load(sys.stdin); assert e["old_logical"]=='"'"'NL#3"x'"'"''
summary
