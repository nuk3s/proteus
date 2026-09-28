#!/usr/bin/env bash
# install/tests/apply_sysctl_test.sh
#
# The installer puts every etc/sysctl.d/*.conf on the box under the same name
# (so the tracked 90-proxy-hardening.conf replaces a hand-made copy) and loads
# it with `sysctl -p`. apply_network does that, and only once `nft -f` has
# succeeded: the file turns forwarding on, so it must not reach the disk, and
# with it the next boot, ahead of a ruleset load that then fails. It loads
# before apply_network's own `sysctl -w` lines, the order boot uses
# (90-proxy-hardening.conf, then 99-proteus.conf). A load that fails warns and
# the apply goes on, under install.sh's `set -e` too. So does a sysctl.d file
# that sorts after these and sets one of their keys to another value: the
# loads leave our value running, and the next boot would change it.
#
# Every tool is stubbed on PATH. apply_network also runs scripts under
# /etc/proteus by absolute path, which no stub can shadow, so it runs here as a
# copy whose /etc/proteus paths point into a scratch dir, and the copy is
# checked for any path left over before it runs.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
source tests/_assert.sh
source install/lib/common.sh
source install/lib/apply.sh
load_config install/tests/fixtures/good.conf
ROOT=$(pwd)
SRC90="$ROOT/etc/sysctl.d/90-proxy-hardening.conf"
DST90=/etc/sysctl.d/90-proxy-hardening.conf

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/etc-proteus/bin" "$TMP/etc-proteus/state"
NFT_CONF="$TMP/nftables.conf"
NFT_SNAPSHOT="$TMP/nftables.conf.pre-install"
NFT_PRIOR_FILE="$TMP/nftables.conf.pre-install-file"
NFT_REVERTED_MARK="$TMP/reverted"
: > "$NFT_CONF"

# Every call lands in $TMP/calls, one line each. Failures on demand:
#   NFT_F=fail        `nft -f` fails (the ruleset did not load)
#   SYSCTL_P=fail     `sysctl ... -p ...` fails
#   INSTALL_FAIL=<s>  `install` fails when its arguments contain <s>
cat > "$TMP/bin/nft" <<EOS
#!/usr/bin/env bash
echo "nft \$*" >> "$TMP/calls"
case "\$*" in
  "list ruleset") printf 'table inet filter {\n}\n' ;;
  "-f "*) [[ "\${NFT_F:-ok}" == ok ]] || exit 1 ;;
esac
exit 0
EOS
cat > "$TMP/bin/sysctl" <<EOS
#!/usr/bin/env bash
echo "sysctl \$*" >> "$TMP/calls"
[[ " \$* " == *" -p "* && "\${SYSCTL_P:-ok}" == fail ]] && { echo "sysctl: setting key: Invalid argument" >&2; exit 1; }
exit 0
EOS
cat > "$TMP/bin/install" <<EOS
#!/usr/bin/env bash
echo "install \$*" >> "$TMP/calls"
[[ -n "\${INSTALL_FAIL:-}" && "\$*" == *"\$INSTALL_FAIL"* ]] && exit 1
exit 0
EOS
# What systemd-sysctl would read at boot is $TMP/catcfg, written per case.
#   SA=fail           `systemd-analyze` fails
cat > "$TMP/bin/systemd-analyze" <<EOS
#!/usr/bin/env bash
echo "systemd-analyze \$*" >> "$TMP/calls"
[[ "\${SA:-ok}" == ok ]] || exit 1
cat "$TMP/catcfg" 2>/dev/null
exit 0
EOS
for tool in systemctl systemd-run; do
    printf '#!/usr/bin/env bash\necho "%s $*" >> "%s/calls"\nexit 0\n' "$tool" "$TMP" > "$TMP/bin/$tool"
done
for s in repopulate-wg-peers.sh proteus-trusted-egress.sh routeguard.sh; do
    printf '#!/usr/bin/env bash\necho "script %s${*:+ $*}" >> "%s/calls"\nexit 0\n' "$s" "$TMP" > "$TMP/etc-proteus/bin/$s"
done
chmod +x "$TMP/bin"/* "$TMP/etc-proteus/bin"/*

# apply_network with /etc/proteus moved into the scratch dir.
body=$(declare -f apply_network | sed "s#/etc/proteus/#$TMP/etc-proteus/#g")
if grep -q '/etc/proteus' <<<"$body"; then
    echo "  ✗ apply_network still names /etc/proteus after the rewrite; not running it"; exit 1
fi
eval "$body"

reset() { : > "$TMP/calls"; }
calls() { grep -c -- "$1" "$TMP/calls" || true; }
line_of() { grep -nxF -- "$1" "$TMP/calls" | head -1 | cut -d: -f1; }
before() {   # <a> <b>: "yes" iff call a is recorded, then call b
    local a b; a=$(line_of "$1"); b=$(line_of "$2")
    [[ -n "$a" && -n "$b" && "$a" -lt "$b" ]] && echo yes || echo no
}
files() { ( PATH="$TMP/bin:$PATH"; export SYSCTL_P INSTALL_FAIL; install_sysctl_files ) >/dev/null 2>&1; echo $?; }
net() {
    ( set -e; PATH="$TMP/bin:$PATH"; export NFT_F SYSCTL_P INSTALL_FAIL SA; apply_network ) >"$TMP/out" 2>&1
    echo $?
}
INSTALL_90="install -o root -g root -m 0644 $SRC90 $DST90"
LOAD_90="sysctl -q -p $DST90"

echo "install_sysctl_files: installs each file under its own name, then loads it"
reset; NFT_F=ok; SYSCTL_P=ok; INSTALL_FAIL=
rc=$(files)
assert_eq "$rc" "0" "exits 0"
assert_eq "$(calls "^$INSTALL_90\$")" "1" "90-proxy-hardening.conf installed root:root 0644 as $DST90"
assert_eq "$(calls "^$LOAD_90\$")" "1" "... and loaded with sysctl -p from there"
assert_eq "$(before "$INSTALL_90" "$LOAD_90")" yes "installed before it is loaded"
n_src=$(find etc/sysctl.d -maxdepth 1 -type f -name '*.conf' | wc -l)
assert_eq "$([[ $n_src -ge 1 ]] && echo yes || echo no)" yes "etc/sysctl.d has at least one file ($n_src)"
assert_eq "$(grep -cE "^install -o root -g root -m 0644 $ROOT/etc/sysctl\.d/[^/]+\.conf /etc/sysctl\.d/[^/]+\.conf\$" "$TMP/calls")" "$n_src" \
    "every etc/sysctl.d/*.conf is installed"
assert_eq "$(grep -cE '^sysctl -q -p /etc/sysctl\.d/[^/]+\.conf$' "$TMP/calls")" "$n_src" "... and every one is loaded"

echo "install_sysctl_files: failures are reported"
reset; SYSCTL_P=fail
assert_eq "$(files)" "1" "a failed sysctl -p makes it return non-zero"
reset; SYSCTL_P=ok; INSTALL_FAIL=90-proxy-hardening.conf
assert_eq "$(files)" "1" "a failed install makes it return non-zero"
assert_eq "$(calls "^$LOAD_90\$")" "0" "... and the file it could not install is not loaded"
INSTALL_FAIL=

echo "apply_network: loads the files after the ruleset, before its own sysctl -w"
reset; NFT_F=ok; SYSCTL_P=ok
rc=$(net)
assert_eq "$rc" "0" "apply_network exits 0 (stubbed)"
assert_eq "$(before "nft -f $NFT_CONF" "$INSTALL_90")" yes "the file is installed only after nft -f loaded the ruleset"
assert_eq "$(before "$INSTALL_90" "$LOAD_90")" yes "... then loaded"
assert_eq "$(before "$LOAD_90" "sysctl -qw net.ipv4.ip_forward=1")" yes \
    "... before apply_network's own sysctl -w (boot order: 90 before 99)"
assert_eq "$(before "$LOAD_90" "install -o root -g root -m 0644 /dev/stdin /etc/sysctl.d/99-proteus.conf")" yes \
    "... and before 99-proteus.conf is written"
assert_eq "$(before "$LOAD_90" "script routeguard.sh")" yes "... and before routeguard.sh arms the sink"

echo "apply_network: no ruleset loaded, no sysctl file"
reset; NFT_F=fail
rc=$(net)
assert_eq "$rc" "1" "a failed nft -f still fails the apply"
assert_eq "$(calls ' /etc/sysctl\.d/')" "0" "nothing is written to /etc/sysctl.d (it would turn forwarding on at the next boot)"
assert_eq "$(calls '^sysctl ')" "0" "no sysctl runs at all"
NFT_F=ok

echo "apply_network: a failed load warns and the apply goes on under set -e"
reset; SYSCTL_P=fail
rc=$(net)
assert_eq "$rc" "0" "apply_network still exits 0"
assert_eq "$(grep -c "WARN: kernel settings from the repo's etc/sysctl.d not fully applied" "$TMP/out" || true)" "1" "says so"
assert_eq "$(calls "^sysctl -qw net.ipv4.ip_forward=1\$")/$(calls "^sysctl -qw net.ipv4.fwmark_reflect=0\$")" "1/1" "forwarding and fwmark_reflect are still set"
assert_eq "$(calls '^script routeguard.sh')" "1" "routeguard.sh still runs"
SYSCTL_P=ok

# ---------------------------------------------------------------------------
# A file sorting after ours can set one of our keys to another value. The loads
# above leave our value running, so only the next boot would show it.
# $TMP/catcfg is the boot config as `systemd-analyze cat-config sysctl.d` prints
# it: a "# <path>" line above each file, in boot order. base = a package's
# defaults (the style of Debian's 50-default.conf, glob and exclusion included)
# and 90-proxy-hardening.conf as installed.
section() { printf '# %s\n%s\n\n' "$1" "$2"; }
base() {
    section /usr/lib/sysctl.d/50-default.conf $'net.ipv4.conf.default.rp_filter = 2\nnet.ipv4.conf.*.rp_filter = 2\n-net.ipv4.conf.all.rp_filter'
    section "$DST90" "$(cat "$SRC90")"
}
s99() { section /etc/sysctl.d/99-proteus.conf $'net.ipv4.ip_forward=1\nnet.ipv4.fwmark_reflect=0'; }
overrides() { ( PATH="$TMP/bin:$PATH"; export SA; sysctl_boot_overrides ) 2>/dev/null; }
T=$'\t'
LOCAL_RPF1=$'# a comment\nnet.ipv4.conf.all.rp_filter = 1'

echo "sysctl_boot_overrides: our keys a later file sets differently at boot"
SA=ok
{ base; s99; } > "$TMP/catcfg"
assert_eq "$(overrides)" "" "our files and a package's defaults only: nothing"
{ base; section /etc/sysctl.d/95-local.conf "$LOCAL_RPF1"; s99; } > "$TMP/catcfg"
assert_eq "$(overrides)" "net.ipv4.conf.all.rp_filter${T}1${T}/etc/sysctl.d/95-local.conf${T}2${T}$DST90" \
    "a later file's rp_filter=1: key, boot value, that file, value running, our file"
{ section /etc/sysctl.d/10-early.conf "$LOCAL_RPF1"; base; s99; } > "$TMP/catcfg"
assert_eq "$(overrides)" "" "a file sorting before ours: ours wins at boot as well"
{ base; section /etc/sysctl.d/95-local.conf 'net.ipv4.conf.all.rp_filter = 2'; s99; } > "$TMP/catcfg"
assert_eq "$(overrides)" "" "a later file with the same value: nothing"
{ base; section /etc/sysctl.d/95-local.conf 'net/ipv6/conf/all/forwarding = 1'; s99; } > "$TMP/catcfg"
assert_eq "$(overrides | cut -f1-3)" "net.ipv6.conf.all.forwarding${T}1${T}/etc/sysctl.d/95-local.conf" \
    "a key written with slashes is the same key"
{ base; section /etc/sysctl.d/95-local.conf '-net.ipv4.conf.all.rp_filter=1'; s99; } > "$TMP/catcfg"
assert_eq "$(overrides | cut -f1-2)" "net.ipv4.conf.all.rp_filter${T}1" "a leading - (ignore a failure) still assigns"
{ base; section /etc/sysctl.d/95-local.conf $'net.ipv4.conf.*.rp_filter = 1\n-net.ipv4.conf.default.rp_filter'; s99; } > "$TMP/catcfg"
assert_eq "$(overrides)" "" "a later glob does not override a key we set by name (systemd-sysctl's rule), nor does an exclusion"
{ base; section /etc/sysctl.d/95-local.conf 'net.ipv6.conf.*.accept_redirects = 1'; s99; } > "$TMP/catcfg"
assert_eq "$(overrides | cut -f1-2)" "net.ipv6.conf.*.accept_redirects${T}1" "... the same glob as ours does"
{ base; s99; section '/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf' 'net.ipv4.fwmark_reflect = 1'; } > "$TMP/catcfg"
assert_eq "$(overrides)" "net.ipv4.fwmark_reflect${T}1${T}/etc/sysctl.d/99-sysctl.conf${T}0${T}/etc/sysctl.d/99-proteus.conf" \
    "99-proteus.conf's keys are checked too (99-sysctl.conf, a symlink here, sorts after it)"
{ base; section /etc/sysctl.d/95-local.conf 'net.ipv4.tcp_fwmark_accept ='; s99; } > "$TMP/catcfg"
assert_eq "$(overrides | cut -f1-3)" "net.ipv4.tcp_fwmark_accept${T}(empty)${T}/etc/sysctl.d/95-local.conf" \
    "an empty value is shown as such and keeps the fields in place"
{ base; section /etc/sysctl.d/95-local.conf 'net.ipv4.ip_forward = 0'; s99; } > "$TMP/catcfg"
assert_eq "$(overrides)" "" "a key 99-proteus.conf sets again after the later file: boot ends on ours"
{ base; section /etc/sysctl.d/95-local.conf "$LOCAL_RPF1"; s99; } > "$TMP/catcfg"
SA=fail
assert_eq "$(overrides; echo "rc=$?")" "rc=0" "systemd-analyze failing: nothing, and no error"
SA=ok

echo "apply_network: warns about a boot override and goes on"
{ base; section /etc/sysctl.d/95-local.conf "$LOCAL_RPF1"; s99; } > "$TMP/catcfg"
reset
rc=$(net)
assert_eq "$rc" "0" "apply_network exits 0"
assert_eq "$(grep -cF "WARN: /etc/sysctl.d/95-local.conf sets net.ipv4.conf.all.rp_filter=1 and loads after $DST90 at boot: the box runs net.ipv4.conf.all.rp_filter=2 now and net.ipv4.conf.all.rp_filter=1 after the next reboot" "$TMP/out" || true)" "1" \
    "names the file, the key, the value running and the value after a reboot"
assert_eq "$(before "install -o root -g root -m 0644 /dev/stdin /etc/sysctl.d/99-proteus.conf" "systemd-analyze --no-pager cat-config sysctl.d")" yes \
    "checked once 99-proteus.conf is written"
assert_eq "$(calls '^script routeguard.sh')" "1" "routeguard.sh still runs"
{ base; s99; } > "$TMP/catcfg"
reset
rc=$(net)
assert_eq "$rc/$(grep -c 'after the next reboot' "$TMP/out" || true)" "0/0" "no override: no warning"
: > "$TMP/catcfg"

echo "apply_files does not write /etc/sysctl.d (it runs before the ruleset loads)"
reset
( PATH="$TMP/bin:$PATH"; install_repo_files ) >/dev/null 2>&1
assert_eq "$(calls ' /etc/sysctl\.d/')" "0" "install_repo_files leaves /etc/sysctl.d alone"
assert_eq "$(awk '/^apply_files\(\) \{/,/^\}/' install/lib/apply.sh | grep -vE '^[[:space:]]*#' | grep -c 'sysctl' || true)" "0" \
    "apply_files has no sysctl step of its own"

summary
