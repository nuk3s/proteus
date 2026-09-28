#!/usr/bin/env bash
# tests/run.sh — Run all *_test.sh and pytest tests, print a summary.
#
# Usage:
#   tests/run.sh            # run everything
#   tests/run.sh scoring    # run only tests/scoring_test.sh
#
# Exits non-zero if any test fails.
#
# Needs: bash, python3 (+ pytest for the *_test.py files), coreutils, curl,
# openssl (UI tests; skipped without it) and envsubst from gettext-base
# (installer render tests; skipped without it). All of these are on the
# gateway after install.sh's deps phase. The publish guard test also needs
# git 2.32+, rsync and tar; install.sh does not install git or rsync, and the
# test is skipped without them.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

filter=${1:-}
fail=0

# Bash tests
for t in tests/*_test.sh; do
    [[ -e "$t" ]] || continue
    name=$(basename "$t" _test.sh)
    if [[ -n "$filter" && "$name" != *"$filter"* ]]; then continue; fi
    echo "=== bash: $name ==="
    if ! bash "$t"; then
        fail=1
    fi
done

for t in install/tests/*_test.sh; do
    [[ -e "$t" ]] || continue
    name="install/$(basename "$t" _test.sh)"
    echo "=== bash: $name ==="
    bash "$t" || fail=1
done

# End-to-end network-namespace simulation of the slot-rebuild leak (about 35s;
# needs user namespaces with a subuid range, overlayfs and the wireguard
# module). Opt-in, because it is slow and kernel-dependent: PROTEUS_SIM=1.
# Exit 77 means the environment cannot run it: a skip, not a failure.
if [[ "${PROTEUS_SIM:-0}" == 1 && ( -z "$filter" || "rebuild_leak_sim" == *"$filter"* ) ]]; then
    echo "=== sim: rebuild_leak_sim ==="
    bash tests/rebuild_leak_sim.sh; rc=$?
    (( rc == 0 || rc == 77 )) || fail=1
fi

# Python tests (pytest if available, otherwise skip)
if command -v pytest >/dev/null 2>&1 && compgen -G "tests/*_test.py" >/dev/null; then
    echo "=== pytest ==="
    pytest_args=(-q tests/)
    [[ -n "$filter" ]] && pytest_args+=(-k "$filter")
    if ! pytest "${pytest_args[@]}"; then
        fail=1
    fi
fi

if (( fail )); then
    echo "FAIL"
    exit 1
fi
echo "PASS"
