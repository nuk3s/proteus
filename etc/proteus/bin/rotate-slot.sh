#!/usr/bin/env bash
# Rotate a proteus slot to a freshly-minted Proton WG config.
#
# Usage: rotate-slot.sh <slot>      e.g. proton-1
#
# Flow (per attempt; up to MAX_ATTEMPTS):
#   1. Mint a new WG config via proton-mint. NOTE: since 2026-08, each slot owns
#      a PERSISTENT per-slot WG key (proton-mint reuses it); a "mint" now only
#      rotates the SERVER, not the key. See gotchas.md "Per-slot persistent WG
#      keys". Caveat: staging (step 2) briefly runs this slot's key on a 2nd
#      server alongside the live one, so the slot self-collides for the ~30s
#      staging window — only this rotating slot, and MAX_ATTEMPTS absorbs it.
#   2. Stage it in a parallel namespace ($slot-s) at index +100.
#   3. Verify handshake + basic TLS egress in the staging namespace.
#   4. Run reputation-probe.sh inside the staging ns.
#   5. If probe fails: tear down staging, delete the config, loop (transient
#      failures do not count against MAX_ATTEMPTS). With PROTEUS_CF_TIER=
#      mandatory (the default) a candidate that fails a Cloudflare canary is
#      never promoted: when no candidate passes, the rotation ends all-fail
#      and the current exit stays. In the advisory tier the canaries do not
#      gate, so a promoted candidate can have a flagged canary.
# After a successful attempt:
#   6. Promote: replace the live slot via vpnns-up (idempotent in-place
#      reconfigure), SIGHUP the dispatcher.
#   7. Prune old auto-mints for this slot (keep newest 2 as rollback).
#
# Exit codes:
#   0  rotated successfully
#   1  bad args / preconditions
#   2  all mint attempts failed (see MAX_ATTEMPTS)
#   5  promote failed (should not happen — preconditions validated in staging)
set -euo pipefail

SLOT="${1:?slot required, e.g. proton-1}"
[[ "$SLOT" =~ ^proton-([1-9][0-9]?)$ ]] || {
    echo "slot must match proton-N (1-99): $SLOT" >&2
    exit 1
}
SLOT_IDX="${BASH_REMATCH[1]}"
# Staging uses a short suffix (-s) to stay under the 15-char veth name limit:
#   v-proton-1-s-ns = 15 chars, OK; v-proton-1-new-ns = 16, rejected.
STAGE_NAME="${SLOT}-s"
STAGE_IDX=$((100 + SLOT_IDX))
STAGE_NS="ns-${STAGE_NAME}"

# MAX_ATTEMPTS counts VERDICT attempts only (reputation FAIL or throughput
# reject). Transient failures (mint error, endpoint collision, staging or
# handshake failure, egress-probe failure) are not verdicts about the exit and
# no longer burn an attempt; MAX_TOTAL_ATTEMPTS bounds the loop regardless.
# 8 verdicts, not the old 5: while transients still consumed attempts, five was
# a budget for failures of every kind, and a rotation could give up having
# judged two exits. Now that it buys eight real verdicts, spend them — the
# wall-clock deadline below, not the count, is what bounds a rotation.
MAX_ATTEMPTS="${MAX_ATTEMPTS:-8}"
MAX_TOTAL_ATTEMPTS="${MAX_TOTAL_ATTEMPTS:-14}"
# Wall-clock stop, 25 min: attempts are minutes long now, so a bound on
# their count is not a bound on their duration. The unit's
# TimeoutStartSec=45min is the backstop — worst case here is one in-flight
# attempt starting just under the deadline, which lands well inside it.
ROTATION_DEADLINE_S="${ROTATION_DEADLINE_S:-1500}"
RETRY_SLEEP="${RETRY_SLEEP:-3}"
# Overridable so the test harness can run this script against a temp tree.
BIN="${PROTEUS_BIN:-/etc/proteus/bin}"
STATE_DIR="${PROTEUS_STATE_DIR:-/etc/proteus/state}"
RUN_DIR="${PROTEUS_RUN_DIR:-/run/proteus}"
HEALTH_DIR="${HEALTH_DIR:-/run/proteus-slot-health}"
AUTO_DIR="${AUTO_DIR:-/etc/proteus/wg/proton/auto}"
LOCAL_ENV="${PROTEUS_LOCAL_ENV:-/etc/proteus/proteus-local.env}"
LOG_TAG="rotate-${SLOT}"

# This script has no other proteus.env dependency (vpnns-up.sh, called below,
# sources its own config). It's always launched fresh by systemd
# (ExecStart=, no EnvironmentFile=), so it can't inherit anything from a
# parent shell. Load the UI-managed overlay directly so operator-set knobs
# reach this process.
# shellcheck source=/dev/null
[ -f "$LOCAL_ENV" ] && . "$LOCAL_ENV"

# shellcheck source=/dev/null
. "$BIN/history.sh"
# shellcheck source=/dev/null
. "$BIN/checklib.sh"

MINT_POOL_TARGET="${PROTEUS_MINT_POOL_TARGET:-20}"
MINT_EXPLORE="${PROTEUS_MINT_EXPLORE:-0.5}"
MINT_REUSE_MIN_S="${PROTEUS_MINT_REUSE_MIN_S:-604800}"

# Streaming gate: reject an exit that can't sustain streaming-grade bandwidth so
# every promoted slot is streaming-capable. 4K needs ~25 Mbps; surveyed exits do
# 44-289, so this rarely bites but stops the occasional dud. 25 MB probe (1 MB
# rides slow-start; see the throughput-probe-artifact findings).
STREAMING_MIN_MBPS="${PROTEUS_STREAMING_MIN_MBPS:-${STREAMING_MIN_MBPS:-25}}"
TPUT_URL="https://speed.cloudflare.com/__down?bytes=26214400"

log() { logger -t "$LOG_TAG" -- "$*"; echo "[$(date -Iseconds)] $*"; }

# Best-of-two sustained throughput (Mbps) through a staging ns. Two pulls: the
# first hit to a fresh exit rides slow-start + the cold-catch, the second
# reaches steady state. Echoes the better value, or empty if neither pull
# downloaded enough to measure (caller treats empty as "unknown, don't block").
measure_throughput() {
    local ns=$1 best="" i out size t mbps
    for i in 1 2; do
        out=$(ip netns exec "$ns" curl -s -o /dev/null --connect-timeout 8 \
              --max-time 30 -w "%{size_download} %{time_total}" "$TPUT_URL" 2>/dev/null)
        size=$(awk '{print $1+0}' <<<"$out"); t=$(awk '{print $2+0}' <<<"$out")
        if awk -v s="$size" -v tt="$t" 'BEGIN{exit !(s>1000000 && tt>0)}'; then
            mbps=$(awk -v s="$size" -v tt="$t" 'BEGIN{printf "%.1f",(s*8)/(tt*1000000)}')
            if [[ -z "$best" ]] || awk -v a="$mbps" -v b="$best" 'BEGIN{exit !(a>b)}'; then
                best=$mbps
            fi
        fi
    done
    printf '%s' "$best"
}

mkdir -p "$AUTO_DIR"
chmod 700 "$AUTO_DIR"

# Always refresh Proton API whitelist once per rotation (cheap, idempotent).
log "starting rotation for slot=$SLOT stage=$STAGE_NAME idx=$STAGE_IDX max_attempts=$MAX_ATTEMPTS"
systemctl start proteus-proton-api-whitelist.service || {
    log "WARN: proton-api-whitelist service failed — continuing with cached set"
}

cleanup_staging() {
    "$BIN"/vpnns-down.sh "$STAGE_NAME" >/dev/null 2>&1 || true
}
# A worst-case probe (three canaries plus the checks) runs several minutes, so a
# rotation can outlive the unit's TimeoutStartSec and get killed mid-attempt.
# Untrapped, that leaves the staging tunnel and its namespace up and the slot
# self-collides until the next run. cleanup_staging is idempotent, so the EXIT
# trap firing after the promote path already called it is a no-op.
trap 'cleanup_staging' EXIT
trap 'log "terminated by signal — cleaning up staging"; exit 143' TERM INT

# Trigger attribution: the broker (manual, via the web UI) or slot-warmup.sh
# (health, Tier-2) drop a one-shot trigger file before starting this unit;
# absent that, treat the run as the timer-scheduled default. Consume (rm) it
# immediately so a stale file can never mis-attribute a later run.
# NOTE: filename is the bare slot name (no "trigger-" prefix) — this must
# match proteus-ui-apply's TRIGGER_DIR/slot convention (see
# etc/proteus/bin/proteus-ui-apply, cmd=="rotate": os.path.join(trigger_dir,
# slot)), which is what actually writes "manual" for a UI-initiated rotation.
TRIGGER_FILE="$RUN_DIR/$SLOT"
TRIGGER=$(cat "$TRIGGER_FILE" 2>/dev/null || echo scheduled)
rm -f "$TRIGGER_FILE"
if [ -f "$STATE_DIR"/rotation-paused ] && [ "$TRIGGER" != "manual" ]; then
    log "rotation paused; skipping (trigger=$TRIGGER)"
    exit 0
fi
OLD_LOGICAL=$(grep -s '^LOGICAL_NAME=' "$STATE_DIR/$SLOT.meta" | cut -d= -f2- || true)

# --- probe trailer + ledger helpers ---------------------------------------------
# parse_probe_trailer <probe-output>: reads the CANARY/CHECK/STANDING lines
# reputation-probe.sh prints and sets probe_standing probe_of probe_canaries
# probe_checks probe_failing. probe_failing lists the canaries whose class is
# challenge or block-*, the fail classes ledger.is_fail_class names. Any other
# class (clean, transport, not-cloudflare, empty or unknown) is no flag. A
# CANARY line with a fourth token (quarantined) does not count toward the
# standard, so it never enters probe_failing. probe_canaries keeps it with its
# class: the ledger needs that result to lift the quarantine.
parse_probe_trailer() {
    local out=$1 line std
    probe_standing=0; probe_of=0
    probe_canaries=""; probe_checks=""; probe_failing=""
    # Trailer lines are three whitespace-free tokens by construction (four for
    # a quarantined canary), but the probe may be killed mid-line, so every
    # field is read with a default rather than trusting the count under `set -u`.
    while IFS= read -r line; do
        case "$line" in
            "CANARY "*)
                set -- $line
                probe_canaries="$probe_canaries${probe_canaries:+,}${2:-}=${3:-}"
                [[ -z "${4:-}" ]] || continue
                case "${3:-}" in challenge|block-*)
                    probe_failing="$probe_failing${probe_failing:+,}${2:-}" ;; esac ;;
            "CHECK "*)
                set -- $line
                probe_checks="$probe_checks${probe_checks:+,}${2:-}=${3:-}" ;;
            "STANDING "*)
                set -- $line
                std=${2:-0/0}
                probe_standing=${std%%/*}; probe_of=${std##*/} ;;
        esac
    done <<<"$out"
}

# ledger_gate <pass|fail> <exit_ip> <entry_ip> <logical>
ledger_gate() {
    ledger_record --source gate --slot "$SLOT" --verdict "$1" --exit-ip "$2" \
        --entry-ip "$3" --logical="$4" --canaries "$probe_canaries" \
        --checks "$probe_checks" --standing "$probe_standing" --of "$probe_of"
}

# Comma-separated WG endpoints held right now by this slot and its siblings.
# Two slots on the same physical server share an exit IP (privacy regression)
# and exit-side flow state (cold-SYN drops). This slot's own server is excluded
# for a harder reason: the slot has ONE persistent WireGuard key, so staging it
# against the server the live tunnel already uses makes Proton rebind the peer
# to the staging tunnel and blacks out the live slot until the rotation ends.
# mint excludes all of them up front; try_candidate keeps the check as a
# backstop for a mint that ignored the flag.
own_and_sibling_endpoints() {
    local state sibling ep out=""
    for state in "$STATE_DIR"/proton-*.state; do
        [[ -r "$state" ]] || continue
        sibling=$(basename "$state" .state)
        [[ "$sibling" =~ ^proton-[0-9]+$ ]] || continue
        ep=$(awk -F= '/^WG_ENDPOINT_IP=/ {print $2; exit}' "$state")
        [[ -n "$ep" ]] && out="$out${out:+,}$ep"
    done
    printf '%s' "$out"
}

# try_candidate <conf>: stage, verify handshake + egress, run the reputation
# probe (recording the ledger either way), then the throughput gate.
# Sets: new_endpoint new_logical exit_ip probe_out (+ parse_probe_trailer vars).
# Returns 0 promotable, 10 transient (no verdict), 11 reputation FAIL,
# 12 throughput reject. Staging is torn down on every non-zero return.
try_candidate() {
    local conf=$1 state sibling sibling_ep own_ep i hs age trace rc verdict tput
    new_endpoint=$(awk -F'[ =:]+' '/^Endpoint = / {print $2; exit}' "$conf")
    new_logical=$(sed -n 's/^# logical=//p' "$conf" | head -n1 | tr -d '\000-\037')
    if [[ -z "$new_endpoint" ]]; then
        log "could not parse Endpoint from $conf"; return 10
    fi
    # Our own current server: staging this slot's one persistent key against it
    # de-auths the live tunnel (see own_and_sibling_endpoints). Transient, not a
    # verdict — the server itself may be perfectly good, we just cannot test it
    # from here while we are on it.
    own_ep=$(awk -F= '/^WG_ENDPOINT_IP=/ {print $2; exit}' "$STATE_DIR/$SLOT.state" 2>/dev/null)
    if [[ -n "$own_ep" && "$own_ep" == "$new_endpoint" ]]; then
        log "candidate is the slot's current server — discarding"
        return 10
    fi
    for state in "$STATE_DIR"/proton-*.state; do
        [[ -r "$state" ]] || continue
        sibling=$(basename "$state" .state)
        [[ "$sibling" == "$SLOT" ]] && continue
        [[ "$sibling" =~ ^proton-[0-9]+$ ]] || continue
        sibling_ep=$(awk -F= '/^WG_ENDPOINT_IP=/ {print $2; exit}' "$state")
        if [[ "$sibling_ep" == "$new_endpoint" ]]; then
            log "endpoint $new_endpoint collides with $sibling — discarding"
            return 10
        fi
    done
    if ! "$BIN"/vpnns-up.sh "$STAGE_NAME" "$conf" "$STAGE_IDX"; then
        # vpnns-up brings wg0 up before the later steps that can fail, so a
        # partial bring-up would strand this slot's persistent key on a second
        # server for the rest of the rotation. Tear it down before retrying.
        log "staging vpnns-up failed"; cleanup_staging; return 10
    fi
    local handshake_ok=0
    for i in {1..10}; do
        sleep 2
        hs=$(ip netns exec "$STAGE_NS" wg show wg0 latest-handshakes 2>/dev/null \
             | awk '{print $2}' | head -n1)
        if [[ -n "${hs:-}" && "$hs" -gt 0 ]]; then
            age=$(( $(date +%s) - hs ))
            (( age < 60 )) && { handshake_ok=1; log "handshake ok (${age}s ago) after $((i*2))s"; break; }
        fi
    done
    if (( handshake_ok == 0 )); then
        log "no handshake in 20s"; cleanup_staging; return 10
    fi
    # The URL is an IP literal on purpose: nothing in this probe needs a
    # resolver. A staging namespace resolves through the tunnel that was just
    # built, and on some exits that resolver never answers, so the Amazon
    # checkip fetch this replaced (dropped 2026-09-04) died on name resolution
    # and spent the full retry budget (~45s) on a failure that says nothing
    # about the exit.
    # Cloudflare's trace endpoint reports the source address as an "ip=" line.
    if ! trace=$(ip netns exec "$STAGE_NS" timeout 60 curl -sS \
        --retry 3 --retry-all-errors --retry-delay 2 --max-time 12 \
        https://1.1.1.1/cdn-cgi/trace 2>&1); then
        log "egress probe failed: $trace"; cleanup_staging; return 10
    fi
    # When curl's --retry papers over a flaky tunnel the blob also carries retry
    # error lines and, on a retried fetch, more than one trace body, so take the
    # last ip= line. `|| true` keeps `set -e` out of it.
    exit_ip=$(grep -oE '^ip=([0-9]{1,3}\.){3}[0-9]{1,3}' <<<"$trace" | cut -d= -f2 | tail -n1 || true)
    if [[ -z "$exit_ip" ]]; then
        log "trace ok but no ip= field"; cleanup_staging; return 10
    fi
    log "staging egress ip=$exit_ip"

    rc=0
    # Hard cap on the probe: the canary basket plus the checks can run several
    # minutes, and a hung probe would otherwise burn the whole unit timeout on
    # one candidate. A timeout says nothing about the exit, so rc 124 is a
    # transient, not a verdict, and no ledger record is written.
    probe_out=$(timeout "${PROBE_TIMEOUT_S:-420}" "$BIN"/reputation-probe.sh "$STAGE_NS" 2>&1) || rc=$?
    if (( rc == 124 )); then
        log "reputation probe timed out after ${PROBE_TIMEOUT_S:-420}s"
        cleanup_staging; return 10
    fi
    # 0 (PASS) and 1 (FAIL) are the only verdicts. Anything else — a usage
    # error, a missing staging netns, an interpreter that died — is a fault in
    # the probe, and a broken probe must not be recorded as a judgement on the
    # exit or burn a verdict attempt. Same reasoning as the timeout above.
    if (( rc != 0 && rc != 1 )); then
        log "reputation probe error (rc=$rc)"
        cleanup_staging; return 10
    fi
    parse_probe_trailer "$probe_out"
    verdict=$(grep -E "^VERDICT " <<<"$probe_out" | head -n1)
    if (( rc )); then
        ledger_gate fail "$exit_ip" "$new_endpoint" "$new_logical"
        log "reputation probe failed ($exit_ip): $verdict"
        echo "$probe_out" | while IFS= read -r line; do log "  $line"; done
        cleanup_staging; return 11
    fi
    log "reputation probe OK ($exit_ip): $verdict"

    # Streaming gate — every promoted slot must sustain streaming-grade
    # bandwidth. Unmeasurable throughput passes on the reputation result
    # rather than blocking rotation on a transient.
    tput=$(measure_throughput "$STAGE_NS")
    if [[ -z "$tput" ]]; then
        log "throughput unmeasurable — passing on reputation alone"
    elif awk -v t="$tput" -v m="$STREAMING_MIN_MBPS" 'BEGIN{exit !(t>=m)}'; then
        log "throughput ${tput} Mbps >= ${STREAMING_MIN_MBPS} (streaming-capable)"
    else
        # A slow exit is a real property of the exit, so it is a verdict: record
        # the gate as a fail. Otherwise mint keeps this IP in the known-good
        # pool and hands it back on the next rotation, and the next, for the
        # 24h the pass record would have been trusted.
        log "throughput ${tput} Mbps < ${STREAMING_MIN_MBPS} — rejecting exit"
        ledger_gate fail "$exit_ip" "$new_endpoint" "$new_logical"
        cleanup_staging; return 12
    fi
    # Written only once the candidate is promotable, so a "pass" in the ledger
    # means it cleared every gate, not just the reputation probe.
    ledger_gate pass "$exit_ip" "$new_endpoint" "$new_logical"
    return 0
}

# --- attempt loop ------------------------------------------------------------------
good_conf=""; good_exit_ip=""; good_endpoint=""
verdict_attempts=0; total=0
sibling_eps=$(own_and_sibling_endpoints)
while (( verdict_attempts < MAX_ATTEMPTS && total < MAX_TOTAL_ATTEMPTS && SECONDS < ROTATION_DEADLINE_S )); do
    total=$((total + 1))
    log "attempt $total (verdict $((verdict_attempts + 1))/$MAX_ATTEMPTS)"

    if ! new_conf=$("$BIN"/proton-mint --slot "$SLOT" --out-dir "$AUTO_DIR" \
            --ledger "$LEDGER_FILE" --attempt $((verdict_attempts + 1)) \
            --pool-target "$MINT_POOL_TARGET" --explore "$MINT_EXPLORE" \
            --reuse-min-s "$MINT_REUSE_MIN_S" \
            --quarantine-min-exits "$CF_QUARANTINE_MIN_EXITS" \
            --canaries-file "$CANARIES_FILE" --cf-tier "$CF_TIER" \
            ${sibling_eps:+--exclude-endpoints "$sibling_eps"}); then
        log "attempt $total: mint failed"
        sleep "$RETRY_SLEEP"; continue
    fi
    if [[ -z "$new_conf" || ! -r "$new_conf" ]]; then
        log "attempt $total: mint returned no readable path: '$new_conf'"
        sleep "$RETRY_SLEEP"; continue
    fi
    log "minted: $new_conf"

    rc=0; try_candidate "$new_conf" || rc=$?
    case "$rc" in
        0)
            good_conf="$new_conf"; good_exit_ip="$exit_ip"
            good_endpoint="$new_endpoint"
            break ;;
        11|12)
            verdict_attempts=$((verdict_attempts + 1))
            rm -f "$new_conf"; sleep "$RETRY_SLEEP" ;;
        *)
            rm -f "$new_conf"; sleep "$RETRY_SLEEP" ;;
    esac
done

if [[ -z "$good_conf" ]] && (( SECONDS >= ROTATION_DEADLINE_S )); then
    log "deadline reached after ${SECONDS}s"
fi
if [[ -z "$good_conf" ]]; then
    log "ERR: no promotable candidate after $total attempts ($verdict_attempts verdicts) — leaving current slot untouched"
    history_append "$SLOT" "${OLD_LOGICAL:-?}" "${OLD_LOGICAL:-?}" "$TRIGGER" "all-fail" "$total"
    exit 2
fi

# 5/6) Promote: teardown staging, replace live slot, SIGHUP dispatcher.
cleanup_staging

old_conf=""
if [[ -r "$STATE_DIR/${SLOT}.state" ]]; then
    old_conf=$(awk -F= '/^WG_CONF=/ {print $2; exit}' "$STATE_DIR/${SLOT}.state")
fi

if ! "$BIN"/vpnns-up.sh "$SLOT" "$good_conf"; then
    log "ERR: promote vpnns-up failed — slot may be degraded"
    exit 5
fi

# --kill-who=main: the default (all) signals every process in the unit,
# including the dispatcher's nft children and, while the unit is starting,
# its routeguard.sh ExecStartPre. None of them handle SIGHUP, so it kills
# them: a map write fails, or routeguard.sh stops part way through.
# Spelled --kill-who, not the newer --kill-whom: older systemd rejects the
# new name, and current releases accept both.
systemctl kill --kill-who=main --signal=HUP proteus-dispatcher.service 2>/dev/null || \
    log "WARN: dispatcher SIGHUP failed (not running?)"

ln -sfn "$good_conf" "${AUTO_DIR}/${SLOT}.conf"
# Verdicts recorded against the OLD exit say nothing about this one.
rm -f "$HEALTH_DIR/.playability-state.$SLOT"
# The live watches' consecutive-failure counters belong to the OLD exit too: a
# fresh one must not inherit a streak and rotate again on its first bad check.
# The trailing dot keeps the glob off sibling slots (proton-1 vs proton-10).
rm -f "$HEALTH_DIR/.playability-fails.$SLOT" "$HEALTH_DIR/.livecheck-fails.$SLOT."*
log "promoted $SLOT -> $good_conf (exit_ip=$good_exit_ip)"

# Display metadata for the web UI. proton-mint stamps every minted conf with
# "# logical=" / "# exit_country=" header comments (see proton-mint's
# out_path header) — read those back rather than re-deriving them.
#
# SECURITY: this metadata is THIRD-PARTY data (Proton's server names, via
# their API) and MUST NOT go anywhere that gets dot-sourced as shell. The
# .state file is sourced as root by repopulate-wg-peers.sh (every boot) and
# vpnns-down.sh (every teardown) — a logical name like
# "US-FREE#1$(touch /tmp/pwned)" would execute on source. So the display
# metadata lives in a SEPARATE sidecar (.meta) that nothing sources, only
# parsed as KEY=value by the daemon (proteus-ui / ui_logic.parse_kv). We also
# strip control/newline chars as defense in depth, since a newline could
# otherwise inject an extra KEY=value line into the sidecar.
logical=$(sed -n 's/^# logical=//p' "$good_conf" | head -n1)
exit_country=$(sed -n 's/^# exit_country=//p' "$good_conf" | head -n1)
domain=$(sed -n 's/^# physical_domain=//p' "$good_conf" | head -n1)
logical_clean=$(printf '%s' "$logical" | tr -d '\000-\037')
country_clean=$(printf '%s' "$exit_country" | tr -d '\000-\037')
domain_clean=$(printf '%s' "$domain" | tr -d '\000-\037')
meta="$STATE_DIR/$SLOT.meta"
{
    echo "LOGICAL_NAME=$logical_clean"
    echo "EXIT_COUNTRY=$country_clean"
    echo "PHYSICAL_DOMAIN=$domain_clean"
    echo "EXIT_IP=$good_exit_ip"
    echo "MINTED_AT=$(date -Is)"
} > "$meta"
chgrp proteus-ui "$meta" 2>/dev/null || true
chmod 640 "$meta" 2>/dev/null || true
# The Cloudflare verdict is the one the gate just observed on this exit. It is
# written after the .meta file above, which records the new EXIT_IP. A live
# check discards a run that ends during a rotation or after the exit changed,
# so it cannot overwrite this verdict. In the mandatory tier a promoted
# candidate has no flagged canary. In the advisory tier it can have one, and
# the card must show it, so a flagged canary writes CF_CLEAN=no. The gate
# counts an unreachable canary as SKIP, so STANDING below OF means at least
# one canary was never seen: leave the slot unchecked, and the next live-check
# turn checks it first. The slot is promoted already, so nothing here may
# abort the script. If the write fails, drop the old file: the old exit's flag
# must not outlive it.
cf_line=""
if [[ -n "$probe_failing" ]]; then
    log "promoted with flagged canaries ($probe_failing); cf ok is not required"
    cf_line="CF_CLEAN=no"
elif (( probe_of == probe_standing )); then
    (( probe_of > 0 )) || log "no active canary at the gate; $SLOT is cf ok by default"
    cf_line="CF_CLEAN=yes"
fi
if [[ -n "$cf_line" ]]; then
    { mkdir -p "$HEALTH_DIR" \
        && printf '%s\nAT=%s\nFAILING=%s\n' "$cf_line" "$(date +%s)" "$probe_failing" > "$HEALTH_DIR/.cf-state.$SLOT.tmp" \
        && mv "$HEALTH_DIR/.cf-state.$SLOT.tmp" "$HEALTH_DIR/.cf-state.$SLOT"; } \
        || { rm -f "$HEALTH_DIR/.cf-state.$SLOT" 2>/dev/null || true
             log "WARN: could not write the cf verdict for $SLOT; it stays unchecked"; }
else
    rm -f "$HEALTH_DIR/.cf-state.$SLOT" || log "WARN: could not remove the old cf verdict for $SLOT"
fi
history_append "$SLOT" "${OLD_LOGICAL:-?}" "$logical_clean" "$TRIGGER" "promoted" "$total"
ledger_record --source promote --slot "$SLOT" --verdict pass \
    --exit-ip "$good_exit_ip" --entry-ip "$good_endpoint" --logical="$logical_clean"

# 7) Prune — keep newest 2 auto-mints per slot.
mapfile -t stale < <(
    ls -1t "${AUTO_DIR}/${SLOT}-"*.conf 2>/dev/null | tail -n +3
)
for f in "${stale[@]}"; do
    [[ "$f" == "$good_conf" || "$f" == "$old_conf" ]] && continue
    rm -f -- "$f"
    log "pruned $f"
done

exit 0
