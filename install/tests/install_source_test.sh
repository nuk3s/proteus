#!/usr/bin/env bash
# install/tests/install_source_test.sh
#
# The wizard (install/proteus) sources install.sh to borrow its phase
# functions. install.sh used to end in an unconditional `main "$@"`, so every
# such source RAN AN INSTALL: the doctor, apt, render, apply — and apply_network
# re-armed the auto-revert timer, which nothing cancelled afterwards. Pin the
# contract: sourcing defines functions and does nothing else.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
source tests/_assert.sh

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "sourcing install.sh is side-effect free"
# No install/proteus.conf exists in a checkout; main would die loudly on that
# (and, before the guard, had already started the doctor phase).
out=$( ( source install/install.sh ) 2>&1 ); rc=$?
assert_eq "$rc" "0" "source exits 0"
assert_eq "$out" "" "source prints nothing (no phase ran)"

echo "sourcing install.sh defines the phase functions the wizard calls"
for fn in install_deps proton_bootstrap initial_mint enable_services main; do
    ( source install/install.sh; declare -F "$fn" >/dev/null ) && r=defined || r=missing
    assert_eq "$r" defined "$fn defined after source"
done

echo "executing install.sh still runs main"
cp -r install "$TMP/install"; rm -f "$TMP/install/proteus.conf"
out=$(bash "$TMP/install/install.sh" --check 2>&1); rc=$?
[[ $rc -ne 0 ]] && r=nonzero || r=zero
assert_eq "$r" nonzero "install.sh --check without a config exits non-zero"
grep -q 'copy install/proteus.conf.example' <<<"$out" && r=ok || r=fail
assert_eq "$r" ok "install.sh --check without a config says why"

summary
