#!/usr/bin/env bash
# tests/slot_down_hup_test.sh
#
# vpnns-down.sh tells the dispatcher when a LIVE slot stops, so it stops
# handing the slot out and its janitor drains the slot's pins (they lead to
# the blackhole sentinel). Pinned here:
#   - proton-N sends exactly one main-process SIGHUP, after the state file is
#     gone (a reload before that would still list the slot);
#   - staging copies (proton-N-s, rotate-slot.sh's teardown) and the DNS tunnel
#     send none;
#   - a failing or missing systemctl is silent and never fails the teardown
#     (boot, shutdown, the sim's `env -i` sandbox).
# The script runs from a copy whose /etc paths point into a scratch dir, with
# ip, nft, systemctl and routeguard.sh stubbed, so nothing on the host (or a
# gateway running the suite as root) is touched.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOWN="$ROOT/etc/proteus/bin/vpnns-down.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/stub" "$WORK/tools" "$WORK/state" "$WORK/netns"
sed -e "s#/etc/proteus/state#$WORK/state#g" -e "s#/etc/netns#$WORK/netns#g" \
    "$DOWN" > "$WORK/bin/vpnns-down.sh"
# Refuse to run a copy that still names a real /etc path.
if grep -vE '^[[:space:]]*#' "$WORK/bin/vpnns-down.sh" | grep -q '/etc/'; then
    echo "  ✗ the copy of vpnns-down.sh still names an /etc path; not running it"
    exit 1
fi
cat > "$WORK/bin/routeguard.sh" <<'EOF'
rg_catch_ensure() { :; }
rg_sink_ensure() { :; }
rg_sentinel_ensure() { :; }
EOF
for c in ip nft; do printf '#!/bin/sh\nexit 0\n' > "$WORK/stub/$c"; done
# Records each call and whether the slot's state file still existed then.
cat > "$WORK/stub/systemctl" <<EOF
#!/bin/sh
state=gone; [ -e "$WORK/state/\$SLOT_UNDER_TEST.state" ] && state=present
echo "\$* state=\$state" >> "$WORK/systemctl.log"
[ -n "\${SYSTEMCTL_FAIL:-}" ] && { echo "Failed to kill unit proteus-dispatcher.service: No main process to kill" >&2; exit 1; }
exit 0
EOF
chmod +x "$WORK/stub/"*
# The few real tools the script needs, and no systemctl among them.
for t in dirname rm xargs; do ln -s "$(command -v "$t")" "$WORK/tools/$t"; done

# down <instance> [PATH]: run the copy the way systemd does (clean env).
down() {
    local inst=$1 path=${2:-$WORK/stub:$WORK/tools}
    printf 'INSTANCE=%s\nFWMARK=0x3\nRT_TABLE=103\nTRANSIT_NS=172.31.3.2\nWG_ENDPOINT_IP=192.0.2.3\n' \
        "$inst" > "$WORK/state/$inst.state"
    mkdir -p "$WORK/netns/ns-$inst"
    : > "$WORK/systemctl.log"
    env -i PATH="$path" SLOT_UNDER_TEST="$inst" SYSTEMCTL_FAIL="${SYSTEMCTL_FAIL:-}" \
        "$BASH" "$WORK/bin/vpnns-down.sh" "$inst" > "$WORK/out" 2> "$WORK/err"
}

echo "a live slot signals the dispatcher, once the state file is gone"
rc=0; down proton-3 || rc=$?
assert_eq "$rc" "0" "vpnns-down.sh proton-3 exits 0"
assert_eq "$(cat "$WORK/systemctl.log")" \
    "kill --kill-who=main --signal=HUP proteus-dispatcher.service state=gone" \
    "one SIGHUP to the dispatcher's main process, after the state file was removed"
assert_eq "$([[ -e "$WORK/state/proton-3.state" ]] && echo present || echo gone)" "gone" \
    "the state file is removed"
rc=0; down proton-12 || rc=$?
assert_eq "$(wc -l < "$WORK/systemctl.log" | tr -d ' ')" "1" "two-digit slots signal too"

echo "staging copies and the DNS tunnel do not"
for inst in proton-3-s proton-12-s dns-6 dns proton-x; do
    rc=0; down "$inst" || rc=$?
    assert_eq "$rc:$(cat "$WORK/systemctl.log")" "0:" "$inst: no SIGHUP"
done
assert_eq "$(grep -c 'STAGE_NAME="${SLOT}-s"' "$ROOT/etc/proteus/bin/rotate-slot.sh")" "1" \
    "rotate-slot.sh still names staging proton-N-s (what the live-slot test above excludes)"

echo "a dispatcher that is not running, or no systemctl at all, changes nothing"
rc=0; SYSTEMCTL_FAIL=1 down proton-3 || rc=$?
assert_eq "$rc" "0" "systemctl failing does not fail the teardown"
assert_eq "$(cat "$WORK/err")" "" "... and prints nothing"
assert_eq "$(cat "$WORK/out")" "DOWN: proton-3" "... and the teardown finished"
rm "$WORK/stub/systemctl"
rc=0; down proton-3 || rc=$?
assert_eq "$rc" "0" "no systemctl on PATH does not fail the teardown"
assert_eq "$(cat "$WORK/err")" "" "... and prints nothing"
assert_eq "$(cat "$WORK/out")" "DOWN: proton-3" "... and the teardown finished"

summary
