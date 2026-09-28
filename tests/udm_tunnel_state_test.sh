#!/usr/bin/env bash
# tests/udm_tunnel_state_test.sh — the .udm-tunnel handshake-age file that
# slot-warmup.sh writes for the web UI.
#
# The UI daemon is unprivileged and cannot ask WireGuard anything, so this file
# is the only way it learns whether the UDM peer is alive. It is written inline
# in the main pass, BEFORE the per-slot warmup loop and under the script's
# `set -u` — so the property that matters most here is not the value in the
# file, it is that nothing `wg` can say aborts the pass. An abort there costs
# every slot its warmup and its health write, and the dispatcher steers on those.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FIX="$TMP/fix"
mkdir -p "$TMP/bin" "$TMP/nowg" "$TMP/health" "$TMP/sys" "$FIX"
export FIX

cat > "$TMP/bin/wg" <<'EOF'
#!/usr/bin/env bash
[ -e "$FIX/wg-fail" ] && { echo "wg: simulated failure" >&2; exit 1; }
cat "$FIX/wg-out" 2>/dev/null
EOF
chmod +x "$TMP/bin/wg"
# A PATH with everything the block needs EXCEPT wg, for the case where
# wireguard-tools is not installed at all.
for prog in bash awk date mv rm cat; do ln -sf "$(command -v "$prog")" "$TMP/nowg/$prog"; done
[ -z "$(PATH="$TMP/nowg" command -v wg || true)" ] || { echo "FAIL: wg still on the stripped PATH"; exit 1; }

# Extract the block from the real script so this test tracks the source, and
# point its one unstubbable absolute path at a temp directory.
BLOCK="$TMP/block.sh"; export BLOCK
sed -n '/^# The web UI runs unprivileged/,/^fi$/p' "$ROOT/etc/proteus/bin/slot-warmup.sh" \
  | sed "s#/sys/class/net/wg-udm#$TMP/sys/wg-udm#" > "$BLOCK"
grep -q 'HANDSHAKE_AGE_S' "$BLOCK" || { echo "FAIL: extracted the wrong block"; exit 1; }
grep -q "$TMP/sys/wg-udm" "$BLOCK" || { echo "FAIL: interface path not redirected"; exit 1; }

# Prints "done" only if the block ran to the end: an abort under `set -u` is the
# regression this exists to catch, and it is silent otherwise.
run_block() { # run_block <path>
  env PATH="$1" HEALTH_DIR="$TMP/health" bash -c 'set -u; . "$BLOCK"; echo done' 2>/dev/null
}
NORMAL="$TMP/bin:$PATH"
state() { cat "$TMP/health/.udm-tunnel" 2>/dev/null || echo "(absent)"; }
age() { sed -n 's/^HANDSHAKE_AGE_S=//p' "$TMP/health/.udm-tunnel" 2>/dev/null; }
# What the reader makes of the file the writer just produced.
ui_age() { python3 -c '
import sys; sys.path.insert(0, sys.argv[1])
import ui_logic
print(ui_logic.trusted_summary([], True, sys.argv[2], None)["handshake_age_s"])' \
  "$ROOT/etc/proteus/bin" "$TMP/health"; }

touch "$TMP/sys/wg-udm"

echo "a live peer records its handshake age"
printf 'PUBKEY=\t%s\n' "$(( $(date +%s) - 30 ))" > "$FIX/wg-out"
assert_eq "$(run_block "$NORMAL")" "done" "the pass continues"
assert_close "$(age)" 30 2 "age is seconds since the handshake"
assert_eq "$(ui_age)" "30" "and the UI reads back the same number"

echo "a second field that is not a number does not abort the pass"
# The regression: `[[ $x -gt 0 ]]` evaluates $x as arithmetic, so a bare word is
# read as a variable name and `set -u` kills the shell — no warmup for any slot.
printf 'PUBKEY=\t(none)\n' > "$FIX/wg-out"
assert_eq "$(run_block "$NORMAL")" "done" "the pass continues"
assert_eq "$(state)" "HANDSHAKE_AGE_S=" "and the file says: no handshake known"
assert_eq "$(ui_age)" "None" "which the UI reads as null, not as an age"

echo "a peer that has never completed a handshake reads as zero"
printf 'PUBKEY=\t0\n' > "$FIX/wg-out"
assert_eq "$(run_block "$NORMAL")" "done" "the pass continues"
assert_eq "$(state)" "HANDSHAKE_AGE_S=" "no handshake known"

echo "wg exiting non-zero is harmless"
touch "$FIX/wg-fail"
assert_eq "$(run_block "$NORMAL")" "done" "the pass continues"
assert_eq "$(state)" "HANDSHAKE_AGE_S=" "no handshake known"
rm -f "$FIX/wg-fail"

echo "wg not installed at all is harmless"
assert_eq "$(run_block "$TMP/nowg")" "done" "the pass continues"
assert_eq "$(state)" "HANDSHAKE_AGE_S=" "no handshake known"

echo "no interface removes the file, so a stale age cannot outlive the tunnel"
printf 'PUBKEY=\t%s\n' "$(( $(date +%s) - 5 ))" > "$FIX/wg-out"
run_block "$NORMAL" >/dev/null
assert_close "$(age)" 5 2 "an age was recorded first"
rm -f "$TMP/sys/wg-udm"
assert_eq "$(run_block "$NORMAL")" "done" "the pass continues"
assert_eq "$(state)" "(absent)" "the file is gone"

echo "no temp file is ever left behind"
assert_eq "$(find "$TMP/health" -name '*.tmp' | wc -l | tr -d ' ')" "0" "no .udm-tunnel.tmp"

summary
