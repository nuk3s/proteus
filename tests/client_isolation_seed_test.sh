#!/usr/bin/env bash
# tests/client_isolation_seed_test.sh
#
# The boot seed is the riskiest file proteus writes: /etc/nftables.conf includes
# it, so a malformed one makes the WHOLE ruleset fail to parse and — because
# nftables.conf starts with `flush ruleset` — leaves the box with no firewall.
# These tests pin the (mode x failsafe) truth table and the syntactic
# properties the boot loader depends on.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/etc/proteus/bin/proteus-client-isolation.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# The script sources its env overlay files AFTER reading the environment, so the
# config deliberately wins over inherited vars (a stray FOO=x must not be able to
# apply a mode nobody configured). That makes these assertions non-hermetic on any
# box that HAS /etc/proteus/*.env — including the gateway itself. Point the paths
# at /dev/null so the truth table below tests the code, not the host's config.
seed() { # seed <mode> <failsafe>
    env -i PATH="$PATH" \
        PROTEUS_ENV_FILE=/dev/null PROTEUS_LOCAL_ENV_FILE=/dev/null \
        PROTEUS_CLIENT_ISOLATION="$1" \
        PROTEUS_CLIENT_ISOLATION_FAILSAFE="$2" \
        PROTEUS_CLIENT_VLAN_CIDR="172.16.1.0/24" \
        bash "$SCRIPT" --print-seed
}
grants() { seed "$1" "$2" | grep -qE '^add element inet filter client_pivot \{ 172\.16\.1\.0/24 \}$' && echo yes || echo no; }

echo "seed truth table: failsafe=open always grants (today's behaviour, no lockout risk)"
assert_eq "$(grants open open)"     "yes" "failsafe=open  mode=open     -> grants pivot"
assert_eq "$(grants isolated open)" "yes" "failsafe=open  mode=isolated -> grants pivot at boot (fails open by design)"

echo "seed truth table: failsafe=closed mirrors the mode"
assert_eq "$(grants open closed)"     "yes" "failsafe=closed mode=open     -> grants pivot (chosen mode, not a gap)"
assert_eq "$(grants isolated closed)" "no"  "failsafe=closed mode=isolated -> empty, isolated from first boot instant"

echo "unknown values fall back to the permissive setting, never to a silent lockout"
assert_eq "$(grants garbage garbage)" "yes" "garbage mode+failsafe -> grants pivot"
assert_eq "$(grants isolated garbage)" "yes" "garbage failsafe -> treated as open"

echo "syntactic properties the boot loader depends on"
out=$(seed isolated closed)
[[ -n "$out" ]] && r=ok || r=fail
assert_eq "$r" ok "fail-closed seed is comment-only, not empty (an operator must be able to read the state)"
assert_eq "$(seed isolated closed | grep -c '^#')" "2" "fail-closed seed is all comments"
assert_eq "$(seed open open | grep -cE $'\r')" "0" "no CR in output (a CRLF seed hard-fails the whole ruleset)"
assert_eq "$(seed open open | tail -c1 | xxd -p)" "0a" "seed ends with a newline (a truncated last line is a parse error)"

echo "the CIDR is validated before it reaches an nft statement"
for bad in "172.16.1.0/24; rm -rf /" '$(id)' "172.16.1.0" "not-a-cidr" "172.16.1.0/24 172.16.2.0/24"; do
    if env -i PATH="$PATH" PROTEUS_ENV_FILE=/dev/null PROTEUS_LOCAL_ENV_FILE=/dev/null PROTEUS_CLIENT_VLAN_CIDR="$bad" \
        bash "$SCRIPT" --print-seed >/dev/null 2>&1; then r=accepted; else r=rejected; fi
    assert_eq "$r" rejected "rejects PROTEUS_CLIENT_VLAN_CIDR='$bad'"
done
# Empty is NOT an error: `${VAR:-default}` treats empty and unset alike, matching
# every other env override in this tree. It must land on the default, not on an
# empty nft element (which would be a parse error in the boot ruleset).
assert_eq "$(env -i PATH="$PATH" PROTEUS_ENV_FILE=/dev/null PROTEUS_LOCAL_ENV_FILE=/dev/null PROTEUS_CLIENT_VLAN_CIDR="" bash "$SCRIPT" --print-seed \
    | grep -c '172.16.1.0/24')" "1" "empty CIDR falls back to the default, same as unset"
assert_eq "$(env -i PATH="$PATH" PROTEUS_ENV_FILE=/dev/null PROTEUS_LOCAL_ENV_FILE=/dev/null PROTEUS_CLIENT_VLAN_CIDR="10.9.0.0/16" bash "$SCRIPT" --print-seed \
    | grep -c '10.9.0.0/16')" "1" "accepts a different valid CIDR"

echo "generated seed actually parses as nftables input"
if command -v nft >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    cat > "$TMP/check.nft" <<EOF
table inet filter {
    set client_pivot {
        type ipv4_addr
        flags interval
    }
}
include "$TMP/seed.nft"
EOF
    seed open open > "$TMP/seed.nft"
    sudo -n nft -c -f "$TMP/check.nft" 2>/dev/null && r=ok || r=fail
    assert_eq "$r" ok "fail-open seed passes nft -c"
    seed isolated closed > "$TMP/seed.nft"
    sudo -n nft -c -f "$TMP/check.nft" 2>/dev/null && r=ok || r=fail
    assert_eq "$r" ok "fail-closed (comment-only) seed passes nft -c"
else
    echo "  - skipped nft -c checks (no nft or no passwordless sudo here)"
fi

summary
