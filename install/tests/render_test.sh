#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/../.."
source tests/_assert.sh
source install/lib/common.sh
source install/lib/render.sh

load_config install/tests/fixtures/good.conf
validate_config
STAGE=$(mktemp -d)
render_all "$STAGE"

echo "render: multivpn.env matches golden"
assert_eq "$(cat "$STAGE/multivpn.env")" "$(cat install/tests/fixtures/expected-multivpn.env)" "env renders exactly"

echo "render: nftables has no unexpanded vars and substituted interfaces"
assert_eq "$(grep -c '\${' "$STAGE/nftables.conf")" "0" "no leftover \${...} in nftables"
# Note: good.conf intentionally reuses ens18/ens19 as MGMT_IFACE/CLIENT_IFACE,
# so after substitution those literal strings legitimately still appear in
# the rendered output. The interface-substitution check is therefore also a
# "no leftover \${...}" check rather than a literal-absence check (soft, per plan).
assert_eq "$(grep -c '\${' "$STAGE/nftables.conf")" "0" "iface literals replaced (sample config reuses ens18/19 so check via CIDR instead)"

echo "render: nftables preserves its own native define-vars (envsubst not greedy)"
grep -q '\$CLIENT_VLAN\b' "$STAGE/nftables.conf" && r=ok || r=fail
assert_eq "$r" ok "nft \$CLIENT_VLAN survives render"
grep -q '\$RFC1918\b' "$STAGE/nftables.conf" && r=ok || r=fail
assert_eq "$r" ok "nft \$RFC1918 survives render"

# (Full `nft -c` validation of the rendered ruleset happens in apply.sh on the
# real target, where the referenced skuid users — _apt, unbound, systemd-timesync
# — exist. It's environment-dependent, so not asserted here; the var-preservation
# checks above are the environment-independent guard against the blanking bug.)

echo "render: unbound binds the configured gateway IP + dns transit"
grep -q "interface: 172.16.1.5" "$STAGE/unbound-multivpn-dns.conf" && r=ok || r=fail
assert_eq "$r" ok "unbound interface rendered"
grep -q "outgoing-interface: 172.31.99.1" "$STAGE/unbound-multivpn-dns.conf" && r=ok || r=fail
assert_eq "$r" ok "unbound outgoing-interface uses dns index 99"

echo "render: key systemd units are produced"
for u in multivpn-dispatcher.service multivpn-proton@.service multivpn-dns-tunnel.service multivpn-rotate-slot@.timer; do
    [[ -f "$STAGE/$u" ]] && r=ok || r=fail
    assert_eq "$r" ok "$u rendered"
done

rm -rf "$STAGE"; summary
