#!/usr/bin/env bash
# tests/nft_restart_safe_test.sh
#
# Debian's nftables.service flushes the ruleset in ExecStop, so a stock
# `systemctl restart nftables` (and the package's try-restart on upgrade) leaves
# the gateway with no firewall until the reload lands, and with none at all if
# it fails. The proteus drop-in clears ExecStop, so a restart is one atomic
# `nft -f`, and runs proteus-nft-repopulate.sh after every start and reload to
# queue the units that refill the sets a full load empties. Pinned here:
#   1. the drop-in: ExecStop cleared, ExecStart untouched, the reload list and
#      its order, the helper '-'-prefixed so it can never fail the unit;
#   2. the helper: a no-op while the system boots, stops or is in rescue, and
#      otherwise a reset of every queued unit's start limit, then exactly one
#      job-queueing systemctl call, a --no-block restart of all four units (a
#      blocking call from inside nftables.service's own job deadlocks: the
#      units it starts are ordered After=nftables.service; a start merges into
#      a run already in progress and refills nothing);
#   3. both ruleset files open with `flush ruleset`, which is what makes a
#      restart without ExecStop an atomic replace;
#   4. systemd-analyze verify of the drop-in over Debian's unit, when available.
# The installer side is install/tests/install_repo_files_test.sh.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DROPIN="$ROOT/etc/systemd/system/nftables.service.d/proteus.conf"
HELPER="$ROOT/etc/proteus/bin/proteus-nft-repopulate.sh"
APPLY="$ROOT/install/lib/apply.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

code_only() { grep -vE '^[[:space:]]*(#|$)' "$1" || true; }
cnt_re() { grep -cE -- "$1" || true; }

# Debian trixie's unit, verbatim (debian/nftables.service in nftables 1.1.3-1;
# pkg-nftables master has since added ConditionFileNotEmpty=, trixie has not).
# The drop-in is written against it: the reload list it replaces, the ExecStart
# it keeps, and the ProtectSystem=full sandbox the helper runs in.
cat > "$WORK/nftables.service" <<'EOF'
[Unit]
Description=nftables
Documentation=man:nft(8) http://wiki.nftables.org
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
StandardInput=null
ProtectSystem=full
ProtectHome=true
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
ExecReload=/usr/sbin/nft -f /etc/nftables.conf
ExecStop=/usr/sbin/nft flush ruleset

[Install]
WantedBy=sysinit.target
EOF

# ---------------------------------------------------------------------------
echo "drop-in: stop never flushes, restart is one atomic load"
[[ -f "$DROPIN" ]] && r=yes || r=no
assert_eq "$r" yes "etc/systemd/system/nftables.service.d/proteus.conf exists"
body=$(code_only "$DROPIN")
assert_eq "$(sed -n 1p <<<"$body")" "[Service]" "the only section is [Service]"
assert_eq "$(cnt_re '^\[' <<<"$body")" "1" "... and there is no other section"
assert_eq "$(grep -E '^ExecStop' <<<"$body")" "ExecStop=" "ExecStop is cleared, and nothing replaces it"
assert_eq "$(cnt_re '^ExecStart=' <<<"$body")" "0" "ExecStart is Debian's, not overridden"
assert_eq "$(grep -E '^ExecStartPost' <<<"$body")" "ExecStartPost=-/etc/proteus/bin/proteus-nft-repopulate.sh" \
    "one ExecStartPost: the helper, '-'-prefixed"

echo "drop-in: the reload list, in order"
assert_eq "$(grep -E '^ExecReload' <<<"$body" | tr '\n' '|')" \
    "ExecReload=|ExecReload=/usr/sbin/nft -f /etc/nftables.conf|ExecReload=-/etc/proteus/bin/proteus-nft-repopulate.sh|" \
    "cleared, then the load, then the helper ('-'-prefixed)"
deb_start=$(sed -n 's/^ExecStart=//p' "$WORK/nftables.service")
assert_eq "$(sed -n 's/^ExecReload=\(\/.*\)/\1/p' <<<"$body")" "$deb_start" \
    "the reload loads exactly what Debian's ExecStart loads"
assert_eq "$(cnt_re '^Exec[A-Za-z]+=[^-].*proteus-nft-repopulate' <<<"$body")" "0" \
    "no line runs the helper without the '-' prefix"
assert_eq "$(grep -oE '/etc/proteus/bin/[^ ]+' <<<"$body" | sort -u)" "/etc/proteus/bin/proteus-nft-repopulate.sh" \
    "the drop-in references only the helper under /etc/proteus/bin"
[[ -f "$HELPER" && -x "$HELPER" ]] && r=yes || r=no
assert_eq "$r" yes "the helper exists in etc/proteus/bin and is executable"
assert_eq "$(head -1 "$HELPER")" "#!/usr/bin/env bash" "helper has a bash shebang"

echo "ruleset files: each opens with 'flush ruleset'"
# With ExecStop cleared nothing flushes before the load, so a restart is an
# atomic replace only because the file's first statement is the flush. Without
# it the load would add its rules to the running ruleset instead of replacing it.
for f in etc/nftables.conf install/templates/nftables.conf.tmpl; do
    assert_eq "$(code_only "$ROOT/$f" | sed -n 1p)" "flush ruleset" "$f: the first statement is exactly 'flush ruleset'"
done

# ---------------------------------------------------------------------------
# A systemctl stub on PATH: records every call, answers is-system-running from
# STUB_STATE and LoadState from STUB_MISSING (space-separated unit names that
# are "not installed"), and fails enqueue calls when STUB_FAIL=1.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$STUB_CALLS"
case "$1" in
    is-system-running)
        echo "$STUB_STATE"
        [[ "$STUB_STATE" == running ]] ;;
    show)
        u=${*: -1}
        if [[ " ${STUB_MISSING:-} " == *" $u "* ]]; then echo not-found; else echo loaded; fi ;;
    *)
        [[ "${STUB_FAIL:-0}" != 1 ]] ;;
esac
EOF
chmod +x "$WORK/bin/systemctl"

# run_helper <state> [missing units]: sets RC, CALLS (queue calls only), LOG
run_helper() {
    local state=$1 missing=${2:-}
    : > "$WORK/calls"
    RC=0
    PATH="$WORK/bin:$PATH" STUB_CALLS="$WORK/calls" STUB_STATE="$state" STUB_MISSING="$missing" \
        STUB_FAIL="${STUB_FAIL:-0}" bash "$HELPER" 2> "$WORK/log" || RC=$?
    CALLS=$(grep -vE '^(is-system-running|show )' "$WORK/calls" || true)
    LOG=$(cat "$WORK/log")
}
UNITS="proteus-wg-peers.service proteus-client-isolation.service proteus-proton-api-whitelist.service proteus-trusted-egress.service"
Q_RESET="reset-failed $UNITS"
Q_RESTART="--no-block restart $UNITS"
Q_ALL="$Q_RESET"$'\n'"$Q_RESTART"

# reset_covers_queued: "yes" when CALLS has a reset-failed naming exactly the
# units its restart call queues, and it comes first.
reset_covers_queued() {
    local reset queued
    reset=$(sed -n 's/^reset-failed //p' <<<"$CALLS" | tr ' ' '\n' | sort)
    queued=$(sed -n 's/^--no-block restart //p' <<<"$CALLS" | tr ' ' '\n' | sort)
    if [[ -n "$queued" && "$reset" == "$queued" && "$(sed -n 1p <<<"$CALLS")" == "reset-failed "* ]]; then
        echo yes
    else
        echo no
    fi
}

echo "helper: on a running system it queues the refill, never waits for it"
for st in running degraded; do
    run_helper "$st"
    assert_eq "$RC" "0" "$st: exits 0"
    assert_eq "$CALLS" "$Q_ALL" "$st: reset every start limit, then one --no-block restart of all four"
done
run_helper running
assert_eq "$(grep -cE '(^| )(start|restart|reload|stop)( |$)' "$WORK/calls" || true)" \
    "$(grep -cE '^--no-block ' "$WORK/calls" || true)" "every job-queueing call carries --no-block"
assert_eq "$(grep -cE '(^| )start( |$)' "$WORK/calls" || true)" "0" \
    "no plain start: it would merge into a run already in progress and refill nothing"
assert_eq "$(reset_covers_queued)" yes "reset-failed covers every queued unit, before the restart"
assert_eq "$(head -1 "$WORK/calls")" "is-system-running" "the state is checked before anything is queued"

echo "helper: during boot the enabled units start in their own order; stopping and rescue queue nothing"
for st in initializing stopping maintenance offline unknown ""; do
    run_helper "$st"
    assert_eq "$RC" "0" "'$st': exits 0 (never fails the nftables unit)"
    assert_eq "$CALLS" "" "'$st': nothing queued"
done
run_helper stopping
assert_eq "$(cnt_re "system state is 'stopping'" <<<"$LOG")" "1" "the skip is logged with the state"

echo "helper: 'starting' still queues (it can outlast the boot jobs; queued jobs merge into pending ones)"
run_helper starting
assert_eq "$CALLS" "$Q_ALL" "starting: the same calls"

echo "helper: units a box does not have are left out, the rest still queued"
run_helper running "proteus-trusted-egress.service"
three="proteus-wg-peers.service proteus-client-isolation.service proteus-proton-api-whitelist.service"
assert_eq "$CALLS" "reset-failed $three"$'\n'"--no-block restart $three" "no trusted-egress unit -> the other three, reset and restarted"
assert_eq "$(reset_covers_queued)" yes "... and reset-failed still covers exactly the queued units"
assert_eq "$(cnt_re 'proteus-trusted-egress.service is not installed; skipped' <<<"$LOG")" "1" "the skipped unit is named in the log"
run_helper running "proteus-wg-peers.service proteus-client-isolation.service"
two="proteus-proton-api-whitelist.service proteus-trusted-egress.service"
assert_eq "$CALLS" "reset-failed $two"$'\n'"--no-block restart $two" "only the whitelist and trusted-egress -> those two"
assert_eq "$(reset_covers_queued)" yes "... and reset-failed covers both"
run_helper running "$UNITS"
assert_eq "$RC:$CALLS" "0:" "none installed -> exits 0, queues nothing"

echo "helper: a failed enqueue is reported, and the '-' prefix keeps it from failing the unit"
STUB_FAIL=1 run_helper running
assert_eq "$RC" "1" "helper exits 1 when systemctl cannot queue"
assert_eq "$CALLS" "$Q_ALL" "... after the reset (whose failure is not fatal) and the queueing call"
assert_eq "$(cnt_re 'could not queue the whole set refill' <<<"$LOG")" "1" "the failure is logged"

echo "helper: the refill list matches the installer's (REPOPULATE_CMD)"
# REPOPULATE_CMD runs two of the four as scripts; each maps to the unit that runs it.
repop=$(grep -E '^REPOPULATE_CMD=' "$APPLY")
for pair in "repopulate-wg-peers.sh:proteus-wg-peers.service" \
            "proteus-proton-api-whitelist.service:proteus-proton-api-whitelist.service" \
            "proteus-client-isolation.service:proteus-client-isolation.service" \
            "proteus-trusted-egress.sh:proteus-trusted-egress.service"; do
    step=${pair%%:*} unit=${pair#*:}
    [[ "$repop" == *"$step"* ]] && a=yes || a=no
    [[ "$Q_RESTART " == *" $unit "* ]] && b=yes || b=no
    assert_eq "$a$b" yesyes "$step (installer) <-> $unit (helper)"
done
for pair in "proteus-wg-peers.service:/etc/proteus/bin/repopulate-wg-peers.sh" \
            "proteus-trusted-egress.service:/etc/proteus/bin/proteus-trusted-egress.sh"; do
    unit=${pair%%:*} script=${pair#*:}
    assert_eq "$(sed -n 's/^ExecStart=//p' "$ROOT/etc/systemd/system/$unit")" "$script" "$unit runs $(basename "$script")"
done
for unit in proteus-wg-peers.service proteus-client-isolation.service proteus-proton-api-whitelist.service proteus-trusted-egress.service; do
    assert_eq "$(cnt_re '^After=.*nftables\.service' < "$ROOT/etc/systemd/system/$unit")" "1" \
        "$unit is After=nftables.service (why the helper must not block)"
done

# ---------------------------------------------------------------------------
echo "systemd-analyze verify: the drop-in over Debian's unit"
# Verify also checks that each non-'-' command exists, so it needs /usr/sbin/nft
# (Debian's path) on the machine running the test.
if command -v systemd-analyze >/dev/null 2>&1 && [[ -x /usr/sbin/nft ]]; then
    mkdir -p "$WORK/units/nftables.service.d"
    cp "$WORK/nftables.service" "$WORK/units/nftables.service"
    cp "$DROPIN" "$WORK/units/nftables.service.d/proteus.conf"
    # Control first: a deliberately bad copy must draw a complaint, or this
    # systemd does not read drop-ins next to a unit given by path and a clean
    # result below would prove nothing.
    { cat "$DROPIN"; echo "ProteusBogusKey=1"; } > "$WORK/units/nftables.service.d/zz-control.conf"
    ctl=$(systemd-analyze verify --man=no "$WORK/units/nftables.service" 2>&1 || true)
    rm -f "$WORK/units/nftables.service.d/zz-control.conf"
    if grep -q 'ProteusBogusKey' <<<"$ctl"; then
        out=$(systemd-analyze verify --man=no "$WORK/units/nftables.service" 2>&1) && vrc=0 || vrc=$?
        assert_eq "$vrc" "0" "verify exits 0"
        assert_eq "$(grep -F 'proteus.conf' <<<"$out" || true)" "" "no warning about the drop-in"
    else
        echo "  - SKIPPED: this systemd-analyze does not read drop-ins beside a unit path"
    fi
else
    echo "  - SKIPPED: systemd-analyze or /usr/sbin/nft not available"
fi

summary
