#!/usr/bin/env bash
# install/tests/template_drift_test.sh
#
# install/templates/ is what the installer ships; etc/ holds the reference copies
# the docs describe. A unit template with no ${...} substitution must be
# byte-identical to its reference, or a fix made to one silently never reaches
# the other. That happened: the broker's sandboxing directives (ProtectKernel*,
# RestrictNamespaces, ...) were added to etc/ only, so every fresh install ran
# the privileged broker without them.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
source tests/_assert.sh

echo "every variable-free unit template matches its etc/ reference"
n=0
for t in install/templates/*.tmpl; do
    base=$(basename "$t" .tmpl)
    case "$base" in *.service|*.timer|*.socket) ;; *) continue;; esac
    grep -q '\${' "$t" && continue           # substituted units: render_test covers them
    n=$((n+1))
    ref="etc/systemd/system/$base"
    if [[ ! -f "$ref" ]]; then assert_eq missing present "$base: reference exists in etc/"; continue; fi
    cmp -s "$t" "$ref" && r=identical || r=differs
    assert_eq "$r" identical "$base: template == etc/ reference"
done
(( n >= 10 )) && r=ok || r=fail
assert_eq "$r" ok "sanity: compared $n static unit templates"

echo "every unit in etc/ has a template (the installer ships templates, not etc/)"
for ref in etc/systemd/system/*; do
    base=$(basename "$ref")
    [[ -f "install/templates/$base.tmpl" ]] && r=ok || r=missing
    assert_eq "$r" ok "$base has install/templates/$base.tmpl"
done

echo "the substituted units carry every reference they render into"
# proteus-dns-tunnel.service is the one unit whose template differs from etc/
# on purpose (etc/ is the legacy dns-6 layout). Pin what the template must keep.
t=install/templates/proteus-dns-tunnel.service.tmpl
grep -q '^ConditionPathExists=/etc/proteus/wg/proton/auto/\${DNS_INSTANCE}.conf' "$t" && r=ok || r=fail
assert_eq "$r" ok "dns-tunnel template gates on the minted conf"
grep -q 'vpnns-up.sh \${DNS_INSTANCE} .* \${DNS_INDEX}$' "$t" && r=ok || r=fail
assert_eq "$r" ok "dns-tunnel template passes the DNS index override"

summary
