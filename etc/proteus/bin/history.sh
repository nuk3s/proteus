#!/usr/bin/env bash
# Rotation history ring: RAM-only (/run), 50 events, group-readable by proteus-ui.
PROTEUS_HISTORY_FILE="${PROTEUS_HISTORY_FILE:-/run/proteus/rotation-history.jsonl}"

history_append() { # slot old_logical new_logical trigger outcome attempts
  local dir; dir=$(dirname "$PROTEUS_HISTORY_FILE")
  mkdir -p "$dir"
  local lock="${PROTEUS_HISTORY_FILE}.lock"
  # Concurrent rotate-slot@N services + rotate-dns.sh all append to this one
  # shared ring; without a lock, two racing read-tail-write cycles can
  # interleave or drop each other's row. flock (same exclusive-lock pattern
  # proton-mint's acquire_mint_lock uses) serializes the append+truncate.
  # Best-effort: `|| true` means a missing flock binary or a lock timeout
  # falls through to an unlocked append rather than blocking a rotation.
  (
    flock -w 5 200 || true
    python3 -c '
import json, sys, time
print(json.dumps({"ts": int(time.time()), "slot": sys.argv[1],
  "old_logical": sys.argv[2], "new_logical": sys.argv[3], "trigger": sys.argv[4],
  "outcome": sys.argv[5], "attempts": int(sys.argv[6])}))' \
      "$1" "$2" "$3" "$4" "$5" "$6" >> "$PROTEUS_HISTORY_FILE"
    tail -n 50 "$PROTEUS_HISTORY_FILE" > "$PROTEUS_HISTORY_FILE.tmp" \
      && mv "$PROTEUS_HISTORY_FILE.tmp" "$PROTEUS_HISTORY_FILE"
  ) 200>"$lock"
  chgrp proteus-ui "$PROTEUS_HISTORY_FILE" 2>/dev/null || true
  chmod 640 "$PROTEUS_HISTORY_FILE" 2>/dev/null || true
}
