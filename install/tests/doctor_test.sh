#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/../.."
source tests/_assert.sh
source install/lib/common.sh
source install/lib/doctor.sh
load_config install/tests/fixtures/good.conf; validate_config
export PATH="$PWD/install/tests/fixtures/mock:$PATH"

echo "check_ifaces: present interfaces pass"
check_ifaces >/dev/null 2>&1 && r=pass || r=fail
assert_eq "$r" pass "ens18/ens19 present -> pass"

echo "check_ifaces: missing interface fails"
( CLIENT_IFACE=missing0 check_ifaces >/dev/null 2>&1 ) && r=pass || r=fail
assert_eq "$r" fail "missing iface -> fail"

echo "check_ssh_source: live SSH source inside MGMT_CIDR passes"
check_ssh_source >/dev/null 2>&1 && r=pass || r=fail
assert_eq "$r" pass "ssh src 10.0.0.200 in 10.0.0.0/24 -> pass"

echo "check_ssh_source: SSH source outside allowed range fails"
( MGMT_CIDR=192.168.99.0/24 check_ssh_source >/dev/null 2>&1 ) && r=pass || r=fail
assert_eq "$r" fail "ssh src not permitted -> fail (lockout guard)"

echo "check_no_conflict: clean env passes"
check_no_conflict >/dev/null 2>&1 && r=pass || r=fail
assert_eq "$r" pass "no leftover netns/rules -> pass"

summary
