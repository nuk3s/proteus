#!/usr/bin/env bash
# install/tests/apply_revert_test.sh
#
# The nft auto-revert must put the box back as it was: the running ruleset AND
# /etc/nftables.conf, or a reboot after a revert loads the ruleset it backed
# out. And it must only be armed on a real snapshot: a failed `nft list
# ruleset` used to leave a snapshot of just `flush ruleset`, so the revert
# would have wiped a working ruleset.
#
# Every tool apply_files/apply_network reach is stubbed on PATH and the three
# nft paths point into a scratch dir, so nothing here touches the host. Both
# functions also call scripts under /etc/proteus/bin by absolute path, which a
# stub cannot shadow, so each run is stopped before them: under `set -e`, the
# `install` of the ruleset (apply_files) and `nft -f` (apply_network) fail,
# and every later `install` and `sysctl` fail as a second stop behind those.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
source tests/_assert.sh
source install/lib/common.sh
source install/lib/apply.sh
load_config install/tests/fixtures/good.conf

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/stage"
NFT_CONF="$TMP/nftables.conf"
NFT_SNAPSHOT="$TMP/nftables.conf.pre-install"
NFT_PRIOR_FILE="$TMP/nftables.conf.pre-install-file"
NFT_REVERTED_MARK="$TMP/reverted"

# nft: `list ruleset` per $NFT_LIST (fail | empty | rules); `-c` passes; `-f` fails.
cat > "$TMP/bin/nft" <<EOS
#!/usr/bin/env bash
echo "nft \$*" >> "$TMP/calls"
case "\$*" in
  "list ruleset")
    case "\${NFT_LIST:-rules}" in
      fail)  echo 'table inet filter {'; echo "netlink: Error: cache initialization failed" >&2; exit 1 ;;
      empty) exit 0 ;;
      *)     printf 'table inet filter {\n}\n'; exit 0 ;;
    esac ;;
  "-c -f "*) exit 0 ;;
  *) exit 1 ;;
esac
EOS
# install: fails for the ruleset itself (the stop in apply_files), and for
# every call after that (the second stop), else records.
cat > "$TMP/bin/install" <<EOS
#!/usr/bin/env bash
echo "install \$*" >> "$TMP/calls"
[[ -e "$TMP/stopped" ]] && exit 1
[[ "\${!#}" == "$NFT_CONF" ]] && { touch "$TMP/stopped"; exit 1; }
exit 0
EOS
for tool in systemctl systemd-run useradd systemd-tmpfiles openssl chown chgrp chmod; do
    printf '#!/usr/bin/env bash\necho "%s $*" >> "%s/calls"\nexit 0\n' "$tool" "$TMP" > "$TMP/bin/$tool"
done
printf '#!/usr/bin/env bash\necho "sysctl $*" >> "%s/calls"\nexit 1\n' "$TMP" > "$TMP/bin/sysctl"
chmod +x "$TMP/bin"/*

reset() { rm -f "$NFT_CONF" "$NFT_SNAPSHOT" "$NFT_SNAPSHOT.tmp" "$NFT_PRIOR_FILE" "$TMP/stopped"; : > "$TMP/calls"; }
net() { ( set -e; PATH="$TMP/bin:$PATH"; NFT_LIST=$1; export NFT_LIST; apply_network ) >/dev/null 2>&1; }
files() { ( set -e; PATH="$TMP/bin:$PATH"; apply_files "$TMP/stage" ) >/dev/null 2>&1; }
calls() { grep -c -- "^$1" "$TMP/calls" || true; }
revert_cmd() { sed -n 's/^systemd-run .* \/bin\/sh -c //p' "$TMP/calls"; }

echo "apply_network: a failed nft list ruleset arms nothing and applies nothing"
reset
echo "old snapshot" > "$NFT_SNAPSHOT"
echo "old file" > "$NFT_PRIOR_FILE"; echo "new render" > "$NFT_CONF"
net fail && r=applied || r=refused
assert_eq "$r" refused "apply_network returns non-zero"
assert_eq "$(calls systemd-run)" "0" "no revert unit armed"
assert_eq "$(calls 'nft -f')" "0" "no ruleset loaded"
assert_eq "$(cat "$NFT_SNAPSHOT")" "old snapshot" "the previous snapshot is not replaced by a partial one"
assert_eq "$([[ -e "$NFT_SNAPSHOT.tmp" ]] && echo left || echo gone)" gone "no temp file left behind"
assert_eq "$(cat "$NFT_CONF")" "old file" "the file apply_files replaced is put back (a reboot loads the old ruleset)"

echo "apply_network: an empty listing (fresh box) is a valid snapshot"
reset
net empty
assert_eq "$(cat "$NFT_SNAPSHOT")" "flush ruleset" "snapshot is exactly 'flush ruleset'"
assert_eq "$(calls systemd-run)" "1" "revert armed"
assert_eq "$(tail -1 "$TMP/calls")" "nft -f $NFT_CONF" "(stopped at the ruleset load, before any /etc/proteus/bin script)"

echo "apply_network: a populated listing keeps the flush prefix"
reset
net rules
assert_eq "$(head -1 "$NFT_SNAPSHOT")/$(grep -c '^table inet filter' "$NFT_SNAPSHOT")" "flush ruleset/1" "snapshot = flush ruleset + the listing"

echo "apply_network: the revert restores the file as well as the ruleset"
reset
echo "old file" > "$NFT_PRIOR_FILE"; echo "new render" > "$NFT_CONF"
net rules
cmd=$(revert_cmd)
assert_eq "$([[ "$cmd" == "touch $NFT_REVERTED_MARK; cp -a $NFT_PRIOR_FILE $NFT_CONF; /usr/sbin/nft -f $NFT_SNAPSHOT && { $REPOPULATE_CMD; }" ]] && echo yes || echo "no: $cmd")" yes \
    "revert = mark it fired; put the old file back; load the snapshot && repopulate"
# Run the mark + file-restore part of that exact text (not the nft load).
sh -c "${cmd%%; /usr/sbin/nft *}"
assert_eq "$(cat "$NFT_CONF")" "old file" "... and that command text really puts the old file back"
assert_eq "$([[ -e "$NFT_REVERTED_MARK" ]] && echo marked || echo unmarked)" marked "... and leaves the fired marker"
reset
echo "new render" > "$NFT_CONF"
net rules
assert_eq "$(revert_cmd)" "touch $NFT_REVERTED_MARK; /usr/sbin/nft -f $NFT_SNAPSHOT && { $REPOPULATE_CMD; }" \
    "with no previous file the new one stays (deleting it would boot the box with no ruleset)"

echo "apply_files: keeps the file it replaces, and only that one"
reset
echo "rendered" > "$TMP/stage/nftables.conf"
echo "live file" > "$NFT_CONF"
files
assert_eq "$(tail -1 "$TMP/calls")" "install -o root -g root -m 0644 $TMP/stage/nftables.conf $NFT_CONF" \
    "(stopped at the ruleset install, before any /etc/proteus/bin script)"
assert_eq "$(cat "$NFT_PRIOR_FILE" 2>/dev/null)" "live file" "the live file is kept for the revert"
reset
echo "stale" > "$NFT_PRIOR_FILE"
files
assert_eq "$([[ -e "$NFT_PRIOR_FILE" ]] && echo kept || echo removed)" removed \
    "no live file: a copy left by an earlier install is removed, not restored later"

echo "apply_network: a marker left by an earlier revert is cleared before arming"
reset; touch "$NFT_REVERTED_MARK"
net rules
assert_eq "$([[ -e "$NFT_REVERTED_MARK" ]] && echo stale || echo cleared)" cleared "stale fired-marker removed"

echo "confirm: refuses once the revert has fired"
cf() { ( PATH="$TMP/bin:$PATH"; confirm ) 2>&1; }
# systemctl stub: the revert service is not running (is-active -> 3).
printf '#!/usr/bin/env bash\necho "systemctl $*" >> "%s/calls"\n[[ "$*" == is-active* ]] && exit 3\nexit 0\n' "$TMP" > "$TMP/bin/systemctl"
: > "$TMP/calls"; touch "$NFT_REVERTED_MARK"
out=$(cf); rc=$?
assert_eq "$rc" 1 "non-zero, so install.sh and the wizard stop"
assert_eq "$(grep -c 'auto-revert already ran' <<<"$out" || true)" 1 "says why"
assert_eq "$(grep -c 'ruleset kept' <<<"$out" || true)" 0 "does not claim the ruleset was kept"
assert_eq "$(calls "systemctl stop ${REVERT_UNIT}.timer")" 1 "still stops the timer first"

echo "confirm: an armed, unfired revert is cancelled"
: > "$TMP/calls"; rm -f "$NFT_REVERTED_MARK"
out=$(cf); rc=$?
assert_eq "$rc" 0 "zero"
assert_eq "$(grep -c 'ruleset kept' <<<"$out" || true)" 1 "cancelled and kept"
assert_eq "$(sed -n 1p "$TMP/calls")" "systemctl stop ${REVERT_UNIT}.timer" "timer stopped before anything is checked"

echo "confirm: a revert running right now counts as fired"
printf '#!/usr/bin/env bash\necho "systemctl $*" >> "%s/calls"\nexit 0\n' "$TMP" > "$TMP/bin/systemctl"
out=$(cf); rc=$?
assert_eq "$rc" 1 "refuses while the revert service is active"

summary
