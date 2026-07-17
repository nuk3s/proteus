#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/../.."
source tests/_assert.sh
source install/lib/common.sh

echo "validate_config: a good config passes"
( load_config install/tests/fixtures/good.conf && validate_config ) && r=ok || r=fail
assert_eq "$r" "ok" "good.conf validates"

echo "validate_config: missing required key fails"
tmp=$(mktemp); grep -v '^MGMT_IFACE=' install/tests/fixtures/good.conf > "$tmp"
( load_config "$tmp" && validate_config ) 2>/dev/null && r=ok || r=fail
assert_eq "$r" "fail" "missing MGMT_IFACE rejected"; rm -f "$tmp"

echo "validate_config: gateway IP outside client CIDR fails"
tmp=$(mktemp); sed 's#^CLIENT_GW_IP=.*#CLIENT_GW_IP=10.0.0.1#' install/tests/fixtures/good.conf > "$tmp"
( load_config "$tmp" && validate_config ) 2>/dev/null && r=ok || r=fail
assert_eq "$r" "fail" "gw outside client CIDR rejected"; rm -f "$tmp"

echo "validate_config: overlapping mgmt/client CIDRs fail"
tmp=$(mktemp); sed 's#^MGMT_CIDR=.*#MGMT_CIDR=172.16.0.0/16#' install/tests/fixtures/good.conf > "$tmp"
( load_config "$tmp" && validate_config ) 2>/dev/null && r=ok || r=fail
assert_eq "$r" "fail" "overlapping CIDRs rejected"; rm -f "$tmp"

echo "validate_config: SLOT_COUNT out of range fails"
tmp=$(mktemp); sed 's#^SLOT_COUNT=.*#SLOT_COUNT=10#' install/tests/fixtures/good.conf > "$tmp"
( load_config "$tmp" && validate_config ) 2>/dev/null && r=ok || r=fail
assert_eq "$r" "fail" "SLOT_COUNT 10 rejected"; rm -f "$tmp"

echo "validate_config: SLOT_COUNT at cap (9) is accepted"
tmp=$(mktemp); sed 's#^SLOT_COUNT=.*#SLOT_COUNT=9#' install/tests/fixtures/good.conf > "$tmp"
( load_config "$tmp" && validate_config ) 2>/dev/null && r=ok || r=fail
assert_eq "$r" "ok" "SLOT_COUNT 9 accepted"; rm -f "$tmp"

echo "ip helpers: pure-bash IPv4 math (preflight runs before python3 is installed)"
ip_in_cidr 172.16.1.5 172.16.1.0/24 && r=ok || r=fail; assert_eq "$r" ok   "ip inside /24"
ip_in_cidr 10.0.0.1   172.16.1.0/24 && r=ok || r=fail; assert_eq "$r" fail "ip outside /24"
ip_in_cidr 192.168.9.9 0.0.0.0/0    && r=ok || r=fail; assert_eq "$r" ok   "/0 matches everything"
cidrs_overlap 172.16.0.0/16 172.16.1.0/24 && r=ok || r=fail; assert_eq "$r" ok   "nested CIDRs overlap"
cidrs_overlap 10.88.0.0/16   172.16.1.0/24 && r=ok || r=fail; assert_eq "$r" fail "disjoint CIDRs do not overlap"
valid_ipv4 999.1.1.1 && r=ok || r=fail; assert_eq "$r" fail "reject octet > 255"
valid_cidr 10.0.0.0  && r=ok || r=fail; assert_eq "$r" fail "reject CIDR missing /len"
valid_cidr 10.0.0.0/33 && r=ok || r=fail; assert_eq "$r" fail "reject prefixlen > 32"

echo "derive: slot 1..N and dns(99) indices/tables/transits"
load_config install/tests/fixtures/good.conf
out=$(derive)
assert_eq "$(grep '^SLOT_1_FWMARK=' <<<"$out" | cut -d= -f2)" "1"   "slot1 fwmark"
assert_eq "$(grep '^SLOT_1_TABLE='  <<<"$out" | cut -d= -f2)" "101" "slot1 table"
assert_eq "$(grep '^SLOT_1_TRANSIT_MAIN=' <<<"$out" | cut -d= -f2)" "172.31.1.1" "slot1 transit main"
assert_eq "$(grep '^SLOT_5_TABLE='  <<<"$out" | cut -d= -f2)" "105" "slot5 table"
assert_eq "$(grep '^DNS_INDEX='     <<<"$out" | cut -d= -f2)" "99"  "dns index 99 (off the slot/staging ranges)"
assert_eq "$(grep '^DNS_TABLE='     <<<"$out" | cut -d= -f2)" "199" "dns table 199"
assert_eq "$(grep '^DNS_TRANSIT_MAIN=' <<<"$out" | cut -d= -f2)" "172.31.99.1" "dns transit main (unbound binds here)"
assert_eq "$(grep '^STAGE_1_INDEX='  <<<"$out" | cut -d= -f2)" "101" "slot1 staging index"

summary
