#!/usr/bin/env bash
# tests/slot_up_hup_test.sh
#
# vpnns-up.sh tells the dispatcher when a LIVE slot is up, the counterpart of
# vpnns-down.sh's signal (tests/slot_down_hup_test.sh). The SIGHUP that
# vpnns-down.sh sent drops the slot from the dispatcher's list, and on a
# one-slot box, or when every slot restarts, empties it. Pinned here:
#   - proton-N sends exactly one main-process SIGHUP, after the state file is
#     complete (a reload before that would not see the slot);
#   - a staging copy (proton-N-s with an index override, rotate-slot.sh's
#     staging bring-up) and the DNS tunnel (with and without an override,
#     rotate-dns.sh and proteus-dns-tunnel.service) send none;
#   - a failing or missing systemctl is silent and never fails the bring-up
#     (at boot the dispatcher is not running yet; the sim's `env -i` sandbox).
# The script runs from a copy whose /etc and /run paths point into a scratch
# dir, with ip, nft, systemctl and routeguard.sh stubbed, so nothing on the
# host (or a gateway running the suite as root) is touched.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UP="$ROOT/etc/proteus/bin/vpnns-up.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/stub" "$WORK/tools"
sed -e "s#/etc/#$WORK/e/#g" -e "s#/run/#$WORK/r/#g" "$UP" > "$WORK/bin/vpnns-up.sh"
# Refuse to run a copy that still names a real /etc or /run path.
if grep -vE '^[[:space:]]*#' "$WORK/bin/vpnns-up.sh" | grep -qE '/etc/|/run/'; then
    echo "  ✗ the copy of vpnns-up.sh still names an /etc or /run path; not running it"
    exit 1
fi
cat > "$WORK/bin/routeguard.sh" <<'EOF'
rg_catch_ensure() { :; }
rg_sink_ensure() { :; }
rg_sentinel_ensure() { :; }
rg_rule_ensure() { :; }
EOF
for c in ip nft; do printf '#!/bin/sh\nexit 0\n' > "$WORK/stub/$c"; done
# Records each call and how far the slot's state file had got by then: the
# last line vpnns-up.sh writes is UP_TIME.
cat > "$WORK/stub/systemctl" <<EOF
#!/bin/sh
f="$WORK/e/proteus/state/\$SLOT_UNDER_TEST.state"
state=gone
[ -e "\$f" ] && state=partial
grep -q '^UP_TIME=' "\$f" 2>/dev/null && state=complete
echo "\$* state=\$state" >> "$WORK/systemctl.log"
[ -n "\${SYSTEMCTL_FAIL:-}" ] && { echo "Failed to kill unit proteus-dispatcher.service: No main process to kill" >&2; exit 1; }
exit 0
EOF
chmod +x "$WORK/stub/"*
# The real tools the script needs; no systemctl (nor python3: without it
# trusted.py's lookup fails, which the script treats as "no trusted ranges").
for t in awk cat chmod date dirname grep mkdir mktemp rm tr xargs; do
    ln -s "$(command -v "$t")" "$WORK/tools/$t"
done
printf '[Interface]\nPrivateKey = x\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.3:51820\n' \
    > "$WORK/wg.conf"

# up <instance> [index-override]: run the copy the way systemd does (clean
# env), from an empty scratch /etc and /run.
up() {
    local inst=$1
    rm -rf "$WORK/e" "$WORK/r"
    : > "$WORK/systemctl.log"
    env -i PATH="$WORK/stub:$WORK/tools" SLOT_UNDER_TEST="$inst" \
        SYSTEMCTL_FAIL="${SYSTEMCTL_FAIL:-}" \
        "$BASH" "$WORK/bin/vpnns-up.sh" "$inst" "$WORK/wg.conf" "${@:2}" \
        > "$WORK/out" 2> "$WORK/err"
}

echo "a live slot signals the dispatcher, once its state file is complete"
rc=0; up proton-3 || rc=$?
assert_eq "$rc" "0" "vpnns-up.sh proton-3 exits 0"
assert_eq "$(cat "$WORK/systemctl.log")" \
    "kill --kill-who=main --signal=HUP proteus-dispatcher.service state=complete" \
    "one SIGHUP to the dispatcher's main process, after the state file was written"
assert_eq "$(grep -c '^FWMARK=0x3$' "$WORK/e/proteus/state/proton-3.state")" "1" \
    "the state file is the real one (the stubs did not short-circuit the script)"
rc=0; up proton-12 || rc=$?
assert_eq "$rc:$(wc -l < "$WORK/systemctl.log" | tr -d ' ')" "0:1" "two-digit slots signal too"

echo "staging copies and the DNS tunnel do not"
for args in "proton-3-s 103" "proton-9-s 109" "dns-6" "dns-6 6" "dns-99 99"; do
    read -ra argv <<< "$args"
    rc=0; up "${argv[@]}" || rc=$?
    assert_eq "$rc:$(cat "$WORK/systemctl.log")" "0:" "vpnns-up.sh $args: no SIGHUP"
done
assert_eq "$(grep -c '"$BIN"/vpnns-up.sh "$STAGE_NAME" "$conf" "$STAGE_IDX"' "$ROOT/etc/proteus/bin/rotate-slot.sh")" "1" \
    "rotate-slot.sh stages under \$STAGE_NAME with an index override (what the staging case above runs)"
assert_eq "$(grep -c 'STAGE_NAME="${SLOT}-s"' "$ROOT/etc/proteus/bin/rotate-slot.sh")" "1" \
    "... and \$STAGE_NAME is proton-N-s"

echo "a dispatcher that is not running, or no systemctl at all, changes nothing"
rc=0; SYSTEMCTL_FAIL=1 up proton-3 || rc=$?
assert_eq "$rc" "0" "systemctl failing does not fail the bring-up"
assert_eq "$(cat "$WORK/err")" "" "... and prints nothing"
assert_eq "$(grep -c '^UP: proton-3 ' "$WORK/out")" "1" "... and the bring-up finished"
rm "$WORK/stub/systemctl"
rc=0; up proton-3 || rc=$?
assert_eq "$rc" "0" "no systemctl on PATH does not fail the bring-up"
assert_eq "$(cat "$WORK/err")" "" "... and prints nothing"
assert_eq "$(grep -c '^UP: proton-3 ' "$WORK/out")" "1" "... and the bring-up finished"

summary
