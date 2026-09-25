#!/usr/bin/env bash
# install/tests/apply_guard_test.sh
#
# apply_files must refuse an empty rendered nftables.conf. `nft -c` accepts an
# empty file (verified: rc 0), so without the size check an empty render would
# be installed over the kill-switch. Every tool apply_files would reach after
# the guard is stubbed here so the test can never touch the host.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
source tests/_assert.sh
source install/lib/common.sh
source install/lib/render.sh
source install/lib/apply.sh
load_config install/tests/fixtures/good.conf

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/stage"
for tool in nft install useradd systemd-tmpfiles openssl chown chgrp chmod; do
    printf '#!/usr/bin/env bash\necho "%s $*" >> "%s/calls"\nexit 0\n' "$tool" "$TMP" > "$TMP/bin/$tool"
    chmod +x "$TMP/bin/$tool"
done
: > "$TMP/calls"
: > "$TMP/stage/nftables.conf"      # the failure mode: rendered but empty

echo "apply_files refuses an empty rendered ruleset before touching anything"
( PATH="$TMP/bin:$PATH" apply_files "$TMP/stage" ) >/dev/null 2>&1 && r=applied || r=refused
assert_eq "$r" refused "empty nftables.conf -> apply_files returns non-zero"
assert_eq "$(cat "$TMP/calls")" "" "no nft/install/useradd/... command was run"

summary
