#!/usr/bin/env bash
# install/tests/install_repo_files_test.sh
#
# Two files make `systemctl restart nftables` safe on a proteus box: the
# nftables.service drop-in (no flush on stop, a set refill after every start
# and reload) and the helper it calls. Neither has a template, so the installer
# copies both from etc/ in install_repo_files. If either stops being installed,
# a fresh box silently goes back to Debian's flush-then-reload restart, or runs
# a drop-in whose helper is missing. `install` is stubbed, so nothing here
# touches the host.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
source tests/_assert.sh
source install/lib/common.sh
source install/lib/apply.sh
ROOT=$(pwd)
APPLY=install/lib/apply.sh
INSTALL_SH=install/install.sh

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
printf '#!/usr/bin/env bash\necho "install $*" >> "%s/calls"\nexit 0\n' "$TMP" > "$TMP/bin/install"
chmod +x "$TMP/bin/install"
: > "$TMP/calls"

code_only() { grep -vE '^[[:space:]]*(#|$)' "$1" || true; }
has_call() { grep -qxF -- "$1" "$TMP/calls" && echo yes || echo no; }

( PATH="$TMP/bin:$PATH" install_repo_files ) >/dev/null 2>&1; rc=$?

echo "install_repo_files installs the nftables drop-in and its helper"
assert_eq "$rc" "0" "install_repo_files exits 0"
assert_eq "$(has_call "install -d -o root -g root -m 0755 /etc/systemd/system/nftables.service.d")" yes \
    "creates /etc/systemd/system/nftables.service.d root:root 0755"
assert_eq "$(has_call "install -o root -g root -m 0644 $ROOT/etc/systemd/system/nftables.service.d/proteus.conf /etc/systemd/system/nftables.service.d/proteus.conf")" yes \
    "installs the drop-in root:root 0644"
assert_eq "$(has_call "install -o root -g root -m 0755 $ROOT/etc/proteus/bin/proteus-nft-repopulate.sh /etc/proteus/bin/proteus-nft-repopulate.sh")" yes \
    "installs the helper root:root 0755"
# The drop-in dir must exist before the file lands in it.
dir_line=$(grep -nxF "install -d -o root -g root -m 0755 /etc/systemd/system/nftables.service.d" "$TMP/calls" | head -1 | cut -d: -f1)
file_line=$(grep -nF "/etc/systemd/system/nftables.service.d/proteus.conf" "$TMP/calls" | head -1 | cut -d: -f1)
[[ -n "$dir_line" && -n "$file_line" && "$dir_line" -lt "$file_line" ]] && r=yes || r=no
assert_eq "$r" yes "the directory is created before the drop-in is copied into it"

echo "every file under etc/proteus/bin and every drop-in reaches the box"
n_bin=$(find etc/proteus/bin -maxdepth 1 -type f | wc -l)
assert_eq "$(grep -cE '^install -o root -g root -m 0755 .*/etc/proteus/bin/[^/]+ /etc/proteus/bin/[^/]+$' "$TMP/calls")" "$n_bin" \
    "one install per bin file ($n_bin)"
for f in etc/systemd/system/*.d/*.conf; do
    [[ -f "$f" ]] || continue
    rel=${f#etc/systemd/system/}
    assert_eq "$(has_call "install -o root -g root -m 0644 $ROOT/$f /etc/systemd/system/$rel")" yes "drop-in $rel installed"
done

echo "apply_files runs install_repo_files, and --confirm daemon-reloads before enabling"
assert_eq "$(awk '/^apply_files\(\) \{/,/^\}/' "$APPLY" | code_only /dev/stdin | grep -cxE '[[:space:]]*install_repo_files')" "1" \
    "apply_files calls install_repo_files"
# The drop-in only takes effect once systemd re-reads its unit files. That is
# enable_services' first step, which --confirm and the wizard both run.
first=$(awk '/^enable_services\(\) \{/,/^\}/' "$INSTALL_SH" | code_only /dev/stdin | sed -n 2p | tr -d '[:space:]')
assert_eq "$first" "systemctldaemon-reload" "enable_services starts with systemctl daemon-reload"
assert_eq "$(code_only "$INSTALL_SH" | grep -cE '^[[:space:]]+log "== phase: enable =="; enable_services$')" "1" "--confirm runs enable_services"

summary
