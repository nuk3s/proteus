#!/bin/bash
# Fire a short TLS hit to proton.me through every rotating-pool slot, IN PARALLEL,
# to keep Proton's exit-side NAT/flow state warm. Without this, the first client
# SYN through an idle slot gets dropped and takes 10-20s of TCP retries. proton.me
# is the warmup target because Proton already sees the WG handshake every 25s
# (PersistentKeepalive) -- no third party involved.
#
# Each pass also writes a per-slot health state file under
# /run/proteus-slot-health/<slot>.state. The dispatcher reads these and
# skips DEGRADED slots when picking a new flow's destination — so a slot
# that's currently failing warmup doesn't get fresh traffic mapped to it.
#
# When a slot has been DEGRADED long enough (FAIL_STREAK >= ROT_THRESHOLD
# and the cooldown has elapsed), this script also asks systemd to fire an
# unscheduled rotation for it.
set -u
LOG_TAG=slot-warmup
HEALTH_DIR=/run/proteus-slot-health
# DNS netns name from the installer env; fall back to production's dns-6.
[[ -r /etc/proteus/proteus.env ]] && source /etc/proteus/proteus.env
# UI-set overrides survive installer re-runs
[ -f /etc/proteus/proteus-local.env ] && . /etc/proteus/proteus-local.env
DNS_NS="ns-${PROTEUS_DNS_INSTANCE:-dns-6}"
# The slot probe is DNS-free: the netns resolvers are reached through the very
# tunnel being probed, so a resolver rate-limiting that slot's exit IP (seen
# live 2026-07 with the public resolvers the netns files still point at: Quad9
# dropping UDP/53 from certain Proton exits) turned into ALL_FAIL streaks that
# poisoned slot health while the data plane was fine. The target is resolved once per pass via local unbound (which
# egresses over the dedicated DNS tunnel, never the probed slot), cached under
# HEALTH_DIR, with a pinned last-resort IP. curl --resolve keeps SNI/Host
# correct, so the TLS hit is unchanged from the exit's point of view.
WARMUP_HOST="${PROTEUS_WARMUP_HOST:-proton.me}"
WARMUP_IP_FALLBACK="${PROTEUS_WARMUP_IP_FALLBACK:-185.70.42.45}"
WARMUP_IP_CACHE="$HEALTH_DIR/.warmup-target-ip"
DEGRADED_AFTER="${PROTEUS_DEGRADED_AFTER:-2}"    # consecutive ALL_FAILs before a slot is DEGRADED
ROT_THRESHOLD="${PROTEUS_ROT_THRESHOLD:-5}"      # consecutive ALL_FAILs before auto-rotation fires
ROT_COOLDOWN="${PROTEUS_ROT_COOLDOWN:-300}"      # seconds between auto-rotation triggers per slot

# --- composite scoring (see the design notes)
JITTER_WINDOW_SAMPLES=15                                                   # ~5min @20s passes
# Throughput probe: 25 MB, not 1 MB. A 1 MB download completes inside TCP
# slow-start over the tunnel RTT and reports ~15 Mbps for an exit that sustains
# 120+; 25 MB reaches steady state (see
# the design notes).
# The bigger pull is ~25x the bytes, so probe far less often — capacity is
# stable, so once per slot every ~50 min is ample and keeps daily probe traffic
# to a few GB. (EVERY_N=60 passes x 10s = one slot probed per 10 min, cycling
# 5 slots -> each ~every 50 min.)
THROUGHPUT_EVERY_N_PASSES=60
THROUGHPUT_TARGET_URL="https://speed.cloudflare.com/__down?bytes=26214400"
THROUGHPUT_TIMEOUT_S=30
PASS_COUNTER_FILE="$HEALTH_DIR/.pass-counter"

# --- ongoing playability (streaming reputation) -------------------------------
# rotate-slot.sh gates a CANDIDATE on playability before promoting it, but an
# exit that passed can be bot-gated days later — Proton IPs get flagged over
# time. Nothing else here would notice: the throughput probe above pulls from
# speed.cloudflare.com, which a bot-gated exit serves perfectly, so the slot
# keeps reporting STATUS=ok while YouTube refuses to play on it. Observed live
# 2026-08-14: 3 of 5 slots LOGIN_REQUIRED, all STATUS=ok, one of them promoted
# (and therefore gate-passed) only hours earlier.
#
# So: re-check the promoted exit periodically and rotate it out when it goes
# bad. Deliberately NOT wired into FAIL_STREAK/DEGRADED — a bot-gated exit is
# perfectly good for everything except streaming, and degrading it would evict
# its client pins and concentrate everyone onto the remaining slots, which is a
# worse outcome than a slow YouTube fix. It triggers a rotation and nothing
# else; the slot keeps serving until a replacement passes the gate.
PLAYABILITY_CHECK="${PROTEUS_PLAYABILITY_CHECK:-on}"          # on|off
# One slot per N passes, round-robin, so each slot is re-checked every
# N x <slots> passes: 20 x 5 x ~10s ~= every 17 min per slot. The page is
# ~900KB, so this is ~3KB/s of background traffic, not the ~450KB/s that
# checking every slot every pass would cost.
PLAYABILITY_EVERY_N_PASSES=20
PLAYABILITY_URL="${PROTEUS_PLAYABILITY_URL:-https://www.youtube.com/watch?v=jNQXAC9IVRw}"
PLAYABILITY_MUST_CONTAIN='"playabilityStatus":{"status":"OK"'
# PINNED desktop UA, load-bearing in both directions (measured 2026-08-08):
# a mobile UA 302s to m.youtube.com, whose body lacks the marker, so a healthy
# exit would look broken; and m.youtube.com does not bot-gate at all, so a
# genuinely gated exit would look fine. Do not rotate this UA.
PLAYABILITY_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
PLAYABILITY_TIMEOUT_S=20
# Two consecutive failures, ~17 min apart, before acting — one transient fetch
# failure must not rotate a healthy exit.
PLAYABILITY_FAILS_BEFORE_ROTATE="${PROTEUS_PLAYABILITY_FAILS:-2}"
# Per-slot floor between playability-triggered rotations. A SUCCESSFUL rotation
# yields a playable exit by construction (rotate-slot.sh won't promote one that
# fails the gate), so this only throttles the all-fail case — where no candidate
# in 5 tries was playable and retrying immediately would just burn Proton API
# mints for nothing. The stamp file (.live-lastrot.<slot>) is shared with the
# live checks below, so two different watches cannot rotate one slot twice in
# quick succession.
PLAYABILITY_ROT_COOLDOWN="${PROTEUS_PLAYABILITY_ROT_COOLDOWN:-3600}"

# --- live checks: Cloudflare canaries + mandatory custom checks ----------------
# The playability watch, generalised. The candidate gate's Cloudflare canaries
# and the operator's mandatory custom checks are re-run on promoted slots, one
# slot per LIVECHECK_EVERY_N_PASSES round-robin, and a slot that keeps failing
# one of them is rotated out. "cf ok" is required by default
# (PROTEUS_CF_TIER=mandatory, read in checklib.sh): the first flagged canary
# writes CF_CLEAN=no and the dispatcher gives the slot no new clients from that
# moment. The slot gets a quick second check at the next turn
# (livecheck_quick_slots) and a confirmed flag rotates it. PROTEUS_CF_TIER=advisory
# records and shows the canaries only: CF_CLEAN is still written for the tunnel
# card, but a flag does not fail the exit in the ledger, gets no quick check and
# rotates nothing. The mandatory custom checks act in both tiers. Same rules as
# playability otherwise: never touches FAIL_STREAK/STATUS (degrading a
# challenged exit would evict its pins), two consecutive failures before
# acting, one shared per-slot cooldown for every live-triggered rotation.
# Canary-triggered rotations are also held while the ledger says the standard
# is not attainable fleet-wide. Design: architecture.md, "Cloudflare canaries,
# live checks and the exit ledger"
LIVECHECK="${PROTEUS_LIVECHECK:-on}"                                  # on|off
LIVECHECK_EVERY_N_PASSES=20
LIVECHECK_FAILS_BEFORE_ROTATE="${PROTEUS_LIVECHECK_FAILS:-2}"
LIVECHECK_ROT_COOLDOWN="${PROTEUS_LIVECHECK_ROT_COOLDOWN:-3600}"
STATE_DIR="${PROTEUS_STATE_DIR:-/etc/proteus/state}"
RUN_DIR="${PROTEUS_RUN_DIR:-/run/proteus}"
# probe(), cf_probe_canary, cf_canaries, custom_checks and the ledger wrappers.
# shellcheck source=/dev/null
. "$(dirname "${BASH_SOURCE[0]}")/checklib.sh"

# shellcheck source=/dev/null
source /etc/proteus/bin/scoring.sh

mkdir -p "$HEALTH_DIR"
chmod 0755 "$HEALTH_DIR"

# Read a single key=value field from a slot's health state file.
# Empty string if file or key is missing.
_health_get() {
    local file=$1 key=$2
    [[ -r "$file" ]] || { echo ""; return; }
    awk -F= -v k="$key" '$1==k {print $2; exit}' "$file"
}

# Write the slot's health state atomically and (if appropriate) trigger
# auto-rotation. Args: <inst> <outcome> <latency_ms> [<throughput_mbps>]
# where outcome is ok|warmed|all_fail. throughput is optional; if missing
# the previous value is retained.
_update_health() {
    local inst=$1 outcome=$2 latency_ms=${3:-0} throughput_mbps=${4:-}
    local file="$HEALTH_DIR/$inst.state"
    local hist_file="$HEALTH_DIR/$inst.lat-history"
    local now
    now=$(date +%s)

    local prev_streak prev_rot prev_tp
    prev_streak=$(_health_get "$file" FAIL_STREAK)
    prev_rot=$(_health_get "$file" LAST_ROT_TRIGGER_AT)
    prev_tp=$(_health_get "$file" THROUGHPUT_MBPS)
    : "${prev_streak:=0}"
    : "${prev_rot:=0}"

    local fail_streak status
    if [[ "$outcome" == "all_fail" ]]; then
        fail_streak=$((prev_streak + 1))
    else
        fail_streak=0
    fi
    if (( fail_streak >= DEGRADED_AFTER )); then
        status=degraded
    else
        status=ok
    fi

    # Decide whether to trigger auto-rotation BEFORE writing the file so the
    # write captures the new LAST_ROT_TRIGGER_AT.
    local rot_at=$prev_rot
    local triggered=0
    if (( fail_streak >= ROT_THRESHOLD )) && (( now - prev_rot > ROT_COOLDOWN )); then
        rot_at=$now
        triggered=1
    fi

    # Update latency history. Only first-try ("ok") successes represent
    # warm-path latency; a "warmed" retry's time_connect includes the cold
    # window and would poison the rolling mean/jitter (see scoring.sh
    # should_record_latency). On a skipped pass the ring is unchanged, so
    # mean/jitter carry forward the last N warm samples.
    local mean_lat=0 jitter=0 median_lat=0 mad=0
    if should_record_latency "$outcome" && [[ -n "$latency_ms" ]]; then
        update_lat_history "$hist_file" "$latency_ms" "$JITTER_WINDOW_SAMPLES"
    fi
    local hist=""
    [[ -r "$hist_file" ]] && hist=$(<"$hist_file")
    # median/MAD drive the score (robust to occasional cold-catch spikes);
    # mean/stddev are kept for observability — a large mean-vs-median gap is a
    # useful cold-catch-rate signal.
    mean_lat=$(compute_mean "$hist")
    jitter=$(compute_jitter "$hist")
    median_lat=$(compute_median "$hist")
    mad=$(compute_mad "$hist")

    # Throughput: use new value if measured this pass, else carry forward.
    local tp=${throughput_mbps:-$prev_tp}
    [[ -z "$tp" ]] && tp=0

    local score
    score=$(compute_score "$status" "$median_lat" "$mad" "$tp")

    local tmp="$file.tmp.$$"
    cat > "$tmp" <<EOF
INSTANCE=$inst
STATUS=$status
LAST_OUTCOME=$outcome
LAST_PASS_AT=$now
FAIL_STREAK=$fail_streak
LAST_ROT_TRIGGER_AT=$rot_at
LATENCY_MEAN_MS=$mean_lat
LATENCY_JITTER_MS=$jitter
LATENCY_MEDIAN_MS=$median_lat
LATENCY_MAD_MS=$mad
THROUGHPUT_MBPS=$tp
COMPOSITE_SCORE=$score
SCORE_UPDATED_AT=$now
EOF
    mv "$tmp" "$file"

    if (( triggered )); then
        if [[ -f /etc/proteus/state/rotation-paused ]]; then
            logger -t "$LOG_TAG" "$inst tier-2 rotation suppressed (paused, fail_streak=$fail_streak)"
        else
            logger -t "$LOG_TAG" "$inst auto-rotation triggered (fail_streak=$fail_streak)"
            # Filename matches proteus-ui-apply's trigger convention (bare
            # slot name under /run/proteus, no "trigger-" prefix) so
            # rotate-slot.sh's single trigger-file read path works for both.
            mkdir -p /run/proteus && echo health > "/run/proteus/$inst"
            systemctl start --no-block "proteus-rotate-slot@$inst.service" || \
                logger -t "$LOG_TAG" "$inst auto-rotation failed to start"
        fi
    fi
}

# Re-check that a PROMOTED slot can still stream, and rotate it out if not.
# Runs for at most one slot per pass (see the round-robin pick in the main
# loop). Never touches FAIL_STREAK, STATUS or the composite score — see the
# rationale at PLAYABILITY_CHECK above.
playability_check() {
    local inst=$1 ns="ns-$1"
    local fails_file="$HEALTH_DIR/.playability-fails.$inst"
    local last_rot_file="$HEALTH_DIR/.live-lastrot.$inst"
    local fails=0 body ok=0
    [[ -r "$fails_file" ]] && fails=$(<"$fails_file")

    body=$(ip netns exec "$ns" curl -sL -A "$PLAYABILITY_UA" \
            -H "Accept: text/html,*/*" \
            --max-time "$PLAYABILITY_TIMEOUT_S" --connect-timeout 8 \
            -- "$PLAYABILITY_URL" 2>/dev/null) || true
    # A fetch that returns nothing at all is a transport problem, not a verdict:
    # the slot may simply be mid-rotation. Treat it like a failure for counting
    # purposes but say so distinctly, so the log doesn't blame the exit's
    # reputation for what was a dead socket.
    if [[ -z "$body" ]]; then
        fails=$((fails + 1))
        logger -t "$LOG_TAG" "$inst playability probe unreachable (${fails}/${PLAYABILITY_FAILS_BEFORE_ROTATE})"
    elif grep -qF -e "$PLAYABILITY_MUST_CONTAIN" <<<"$body"; then
        ok=1
    else
        fails=$((fails + 1))
        local why="not playable"
        grep -qiE "sign in to confirm you.{0,3}re not a bot" <<<"$body" && why="bot-gated"
        logger -t "$LOG_TAG" "$inst playability FAIL ($why) (${fails}/${PLAYABILITY_FAILS_BEFORE_ROTATE})"
    fi

    # Record the verdict for the dispatcher, which biases NEW client pins away
    # from slots that cannot stream (dispatcher_logic.is_playable). Written on
    # every check, including the transient-failure passes that do not yet
    # justify a rotation — a client picking a slot right now cares about the
    # last observation, not about whether we have decided to act on it.
    _write_verdict() {
        local v=$1 f="$HEALTH_DIR/.playability-state.$inst"
        printf 'PLAYABLE=%s\nAT=%s\n' "$v" "$(date +%s)" > "$f.tmp" && mv "$f.tmp" "$f"
    }

    if (( ok )); then
        [[ "$fails" != "0" ]] && logger -t "$LOG_TAG" "$inst playability recovered"
        echo 0 > "$fails_file.tmp" && mv "$fails_file.tmp" "$fails_file"
        _write_verdict yes
        return 0
    fi

    echo "$fails" > "$fails_file.tmp" && mv "$fails_file.tmp" "$fails_file"
    _write_verdict no
    (( fails < PLAYABILITY_FAILS_BEFORE_ROTATE )) && return 0

    if [[ -f "$STATE_DIR/rotation-paused" ]]; then
        logger -t "$LOG_TAG" "$inst playability rotation suppressed (paused)"
        return 0
    fi
    local now last=0
    now=$(date +%s)
    [[ -r "$last_rot_file" ]] && last=$(<"$last_rot_file")
    if (( now - last < PLAYABILITY_ROT_COOLDOWN )); then
        logger -t "$LOG_TAG" "$inst playability rotation on cooldown ($((now - last))s < ${PLAYABILITY_ROT_COOLDOWN}s)"
        return 0
    fi
    echo "$now" > "$last_rot_file.tmp" && mv "$last_rot_file.tmp" "$last_rot_file"
    echo 0 > "$fails_file.tmp" && mv "$fails_file.tmp" "$fails_file"
    logger -t "$LOG_TAG" "$inst playability rotation triggered (fails=$fails)"
    mkdir -p "$RUN_DIR" && echo playability > "$RUN_DIR/$inst"
    systemctl start --no-block "proteus-rotate-slot@$inst.service" || \
        logger -t "$LOG_TAG" "$inst playability rotation failed to start"
}

_meta_get() { # <inst> <key> from the display sidecar (untrusted data: read, never sourced)
    awk -F= -v k="$2" '$1==k {print $2; exit}' "$STATE_DIR/$1.meta" 2>/dev/null
}

# _live_fail <inst> <checkid> <why>: bump the per-check streak. Returns 0 when
# the streak has reached the rotation threshold; the caller decides whether
# the trigger is allowed right now.
_live_fail() {
    local inst=$1 id=$2 why=$3 fails=0
    # Separate declaration: bash 5.3 does not expose a local to later
    # assignments in the SAME local command ("inst: unbound variable" under -u).
    local f="$HEALTH_DIR/.livecheck-fails.$inst.$id"
    [[ -r "$f" ]] && fails=$(<"$f")
    fails=$((fails + 1))
    echo "$fails" > "$f.tmp" && mv "$f.tmp" "$f"
    if [[ "$why" == "transport" ]]; then
        logger -t "$LOG_TAG" "$inst live check $id unreachable (${fails}/${LIVECHECK_FAILS_BEFORE_ROTATE})"
    else
        logger -t "$LOG_TAG" "$inst live check $id FAIL ($why) (${fails}/${LIVECHECK_FAILS_BEFORE_ROTATE})"
    fi
    (( fails >= LIVECHECK_FAILS_BEFORE_ROTATE ))
}

_live_ok() { # <inst> <checkid>
    local inst=$1 id=$2
    local f="$HEALTH_DIR/.livecheck-fails.$inst.$id"
    if [[ -r "$f" && "$(<"$f")" != "0" ]]; then
        logger -t "$LOG_TAG" "$inst live check $id recovered"
    fi
    echo 0 > "$f.tmp" && mv "$f.tmp" "$f"
}

# True while slot $1 has a rotation running. `systemctl is-active` exits 3 for
# a oneshot unit that is still running ("activating"), so read the state it
# prints, not its exit status.
_rotating() {
    case "$(systemctl is-active "proteus-rotate-slot@$1.service" 2>/dev/null)" in
        active|activating|deactivating|reloading) return 0 ;;
    esac
    return 1
}

# Re-run the Cloudflare canaries and the mandatory custom checks on a PROMOTED
# slot. Writes .cf-state.<inst> in both tiers (the tunnel card shows it; the
# dispatcher's cf ok rule reads it in mandatory) when the run
# observed every active canary or flagged one, and a live ledger record on every
# run; triggers a rotation only after LIVECHECK_FAILS_BEFORE_ROTATE consecutive
# failures of one check and every gate below passes.
live_check() {
    local inst=$1 ns="ns-$1" now url host cls r entry_exit_ip
    local canaries="" checks="" failing="" active_hosts="" n_active=0 n_clean=0
    local trigger="" custom_bad=0 c_tier c_url c_body
    local n_unreached=0
    # A slot mid-rotation has no stable exit — the netns is being rebuilt and any
    # verdict would describe the outgoing one. systemd serialises repeat starts
    # of this unit but knows nothing about the rotation unit, so ask.
    if _rotating "$inst"; then
        logger -t "$LOG_TAG" "$inst live check skipped: rotation in progress"
        return 0
    fi
    now=$(date +%s)
    # The exit these verdicts will describe. A full basket takes minutes, which
    # is long enough for a health-triggered rotation to replace it underneath us.
    entry_exit_ip=$(_meta_get "$inst" EXIT_IP)

    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        host=$(cf_host "$url")
        cls=$(cf_probe_canary "$ns" "$url")
        canaries="$canaries${canaries:+,}$host=$cls"
        # Off Cloudflare: not counted. A streak from when it was on Cloudflare
        # goes too, or it would pin the slot at the threshold until promotion.
        [[ "$cls" == "not-cloudflare" ]] && { _live_ok "$inst" "cf:$host"; continue; }
        # Quarantined: probed (that is how it recovers) but never counted, and
        # any count from before the quarantine goes with it.
        cf_quarantined "$host" && { _live_ok "$inst" "cf:$host"; continue; }
        n_active=$((n_active + 1)); active_hosts="$active_hosts${active_hosts:+,}$host"
        case "$cls" in
            clean) n_clean=$((n_clean + 1)); _live_ok "$inst" "cf:$host" ;;
            # Reachability is the warmup health path's job: it degrades a slot
            # whose exit is dead. Count the streak so the log shows it, but never
            # rotate on it and never let it colour the verdict — a lost socket
            # says nothing about the exit's Cloudflare standing, and calling it a
            # failure would drop the exit out of ledger.pool() for 24h.
            transport)
                   n_unreached=$((n_unreached + 1))
                   _live_fail "$inst" "cf:$host" transport ;;
            *)     failing="$failing${failing:+,}$host"
                   _live_fail "$inst" "cf:$host" "$cls" && trigger="${trigger:-cf-canary}" ;;
        esac
    done < <(cf_canaries)

    # Mandatory custom checks, through the same probe() the gate uses.
    # shellcheck disable=SC2034  # NS is what probe() in checklib.sh reads.
    local NS=$ns
    # shellcheck disable=SC2034  # c_tier is already filtered by custom_checks.
    while IFS=$'\t' read -r c_tier c_url c_body; do
        [[ -n "$c_url" ]] || continue
        host=$(cf_host "$c_url")
        r=$(probe "custom:${host:0:40}" "$c_url" '[23][0-9][0-9]' "${c_body:-}")
        # Same rule as the canaries, matched on the raw probe line before
        # result_class collapses transport-fail into a plain "error".
        if [[ "$r" == ERROR*transport-fail ]]; then
            checks="$checks${checks:+,}custom:$host=transport"
            _live_fail "$inst" "custom:$host" transport
            continue
        fi
        cls=$(result_class "$r"); cls=${cls#* }
        checks="$checks${checks:+,}custom:$host=$cls"
        case "$cls" in
            clean|skip) _live_ok "$inst" "custom:$host" ;;
            *)          custom_bad=1
                        _live_fail "$inst" "custom:$host" "$cls" && trigger="custom-check" ;;
        esac
    done < <(custom_checks mandatory)

    # A rotation that started while we were probing has already replaced the
    # exit, so everything above describes an IP this slot no longer holds.
    # Publishing it would bias the dispatcher against a fresh exit and file the
    # old exit's verdict in the ledger under the new one; the next scheduled
    # check re-measures in a few minutes, so drop the run instead. The counters
    # already bumped stay: rotation clears them on promotion anyway.
    if _rotating "$inst" \
       || [[ "$(_meta_get "$inst" EXIT_IP)" != "$entry_exit_ip" ]]; then
        logger -t "$LOG_TAG" "$inst live check discarded: exit changed during the run"
        return 0
    fi

    # Verdict for the dispatcher. A flag is written at once: from now on the
    # dispatcher gives the slot no new clients. "cf ok" needs an observation, so
    # a run that flagged nothing but could not reach a canary leaves the
    # previous verdict (or the lack of one) in place.
    local v=""
    if [[ -n "$failing" ]]; then
        v=no
    elif (( n_unreached == 0 )); then
        v=yes
    fi
    if [[ -n "$v" ]]; then
        printf 'CF_CLEAN=%s\nAT=%s\nFAILING=%s\n' "$v" "$now" "$failing" > "$HEALTH_DIR/.cf-state.$inst.tmp" \
            && mv "$HEALTH_DIR/.cf-state.$inst.tmp" "$HEALTH_DIR/.cf-state.$inst"
    fi
    # The ledger verdict is what mint reads. In advisory a canary must not reach
    # it: a fail takes the exit out of the known-good pool for 24h, so the
    # canaries would steer the draw after all. The operator's own mandatory
    # checks fail the exit in both tiers. .cf-state above is written the same
    # way in both tiers.
    local verdict=pass
    if (( custom_bad )) || { [[ "$CF_TIER" == "mandatory" && -n "$failing" ]]; }; then
        verdict=fail
    fi
    ledger_record --source live --slot "$inst" --verdict "$verdict" \
        --exit-ip "$entry_exit_ip" \
        --entry-ip "$(_health_get "$STATE_DIR/$inst.state" WG_ENDPOINT_IP)" \
        --logical "$(_meta_get "$inst" LOGICAL_NAME)" \
        --canaries "$canaries" --checks "$checks" --standing "$n_clean" --of "$n_active"

    # In advisory nothing acts on a canary. Clear the canary streaks on every
    # run, so a later switch to mandatory starts from zero and needs two fresh
    # failures. This comes before the pause gate, so a pause keeps no streak.
    # A custom-check trigger goes on to the gates below.
    if [[ "$CF_TIER" != "mandatory" ]]; then
        rm -f "$HEALTH_DIR/.livecheck-fails.$inst.cf:"*
        if [[ "$trigger" == "cf-canary" ]]; then
            logger -t "$LOG_TAG" "$inst canary failing but cf ok is not required (PROTEUS_CF_TIER=$CF_TIER); not rotating"
            return 0
        fi
    fi
    [[ -n "$trigger" ]] || return 0
    if [[ -f "$STATE_DIR/rotation-paused" ]]; then
        logger -t "$LOG_TAG" "$inst live-check rotation suppressed (paused)"; return 0
    fi
    if [[ "$trigger" == "cf-canary" ]] && ! cf_attainable "$active_hosts" "$(live_slot_count)"; then
        logger -t "$LOG_TAG" "$inst canary failing but the standard is not attainable fleet-wide; not rotating"
        return 0
    fi
    local last=0 lf="$HEALTH_DIR/.live-lastrot.$inst"
    [[ -r "$lf" ]] && last=$(<"$lf")
    if (( now - last < LIVECHECK_ROT_COOLDOWN )); then
        logger -t "$LOG_TAG" "$inst live-check rotation on cooldown ($((now - last))s < ${LIVECHECK_ROT_COOLDOWN}s)"
        return 0
    fi
    echo "$now" > "$lf.tmp" && mv "$lf.tmp" "$lf"
    rm -f "$HEALTH_DIR/.livecheck-fails.$inst."*
    logger -t "$LOG_TAG" "$inst live-check rotation triggered ($trigger)"
    mkdir -p "$RUN_DIR" && echo "$trigger" > "$RUN_DIR/$inst"
    systemctl start --no-block "proteus-rotate-slot@$inst.service" || \
        logger -t "$LOG_TAG" "$inst live-check rotation failed to start"
}

# Slots that get a live check at this turn besides the round-robin one: a slot
# with no Cloudflare verdict yet (a reboot or a promotion that could not see
# every canary), and a slot whose flag no second check has confirmed. A verdict
# file that does not say CF_CLEAN=yes counts as no verdict, as in the
# dispatcher and the UI, so a malformed file gets a quick check. The
# dispatcher already keeps new clients off a flagged slot; this confirms the
# flag (and rotates the slot) or clears it in one turn instead of a full round.
# Both cases stop at the canary streak threshold. A flagged slot there waits on
# a rotation gate (cooldown, attainability, pause) or kept a flag that a later
# unreachable canary could not clear. A slot with no verdict there has a canary
# it cannot reach, and an unreachable canary must not cost a quick check at
# every turn. Either way the slot gets its normal turn only. Transport results
# count in the same streak; promotion and reboot clear it. A rotating slot is
# never quick: its live check would only log "skipped".
livecheck_quick_slots() { # <slot_list>
    local inst f c n max
    for inst in $1; do
        _rotating "$inst" && continue
        f="$HEALTH_DIR/.cf-state.$inst"
        [[ -e "$f" ]] && grep -qx 'CF_CLEAN=yes' "$f" 2>/dev/null && continue
        max=0
        for c in "$HEALTH_DIR/.livecheck-fails.$inst.cf:"*; do
            [[ -r "$c" ]] || continue
            n=$(<"$c")
            [[ "$n" =~ ^[0-9]+$ ]] || continue
            (( n > max )) && max=$n
        done
        (( max < LIVECHECK_FAILS_BEFORE_ROTATE )) && echo "$inst"
    done
    return 0
}

# The slots to live-check at this turn: the round-robin slot first, then each
# quick slot, each once. Each runs as its own proteus-livecheck@ unit. Quick
# slots only when cf ok is required: in advisory nothing acts on a flag, so a
# quick check has no use.
livecheck_turn_slots() { # <round-robin slot> <slot_list>
    {
        echo "$1"
        if [[ "$CF_TIER" == "mandatory" ]]; then livecheck_quick_slots "$2"; fi
    } | awk 'NF && !seen[$0]++'
}

# With PROTEUS_LIVECHECK=off nothing confirms or clears a flag, so a flag from
# before the switch would keep its slot from new clients until the next
# rotation. Drop it: the slot is unchecked, as after a reboot. A cf ok verdict
# from a promotion stays.
livecheck_off_clear_flags() { # <slot_list>
    local inst
    for inst in $1; do
        if grep -qx 'CF_CLEAN=no' "$HEALTH_DIR/.cf-state.$inst" 2>/dev/null; then
            rm -f "$HEALTH_DIR/.cf-state.$inst"
        fi
    done
    return 0
}

# Resolve the warmup target without touching any slot's tunnel: local unbound
# first (fresh answer, cached for later passes), else the cached answer from a
# previous pass, else the pinned fallback. Never blocks more than ~1s.
_warmup_ip() {
    local ip
    ip=$(dig @127.0.0.1 +time=1 +tries=1 +short "$WARMUP_HOST" A 2>/dev/null \
         | grep -m1 -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$') || true
    if [[ -n "$ip" ]]; then
        echo "$ip" > "$WARMUP_IP_CACHE.tmp.$$" && mv "$WARMUP_IP_CACHE.tmp.$$" "$WARMUP_IP_CACHE"
        echo "$ip"
        return
    fi
    if [[ -r "$WARMUP_IP_CACHE" ]]; then
        cat "$WARMUP_IP_CACHE"
        return
    fi
    echo "$WARMUP_IP_FALLBACK"
}

# Args: <inst> [<run_throughput>]   run_throughput=1 means probe throughput too.
warm_one() {
    local inst=$1 run_tp=${2:-0}
    local ns=ns-$inst
    local out="" latency_ms=0 connect_s=""
    local throughput_mbps=""

    # Multi-probe per pass (existing behavior).
    for try in 1 2 3; do
        out=$(ip netns exec "$ns" curl -s -o /dev/null -I \
              --resolve "${WARMUP_HOST}:443:${WARMUP_IP}" \
              --connect-timeout 5 --max-time 6 \
              -w "code=%{http_code} connect=%{time_connect}s total=%{time_total}s" \
              "https://${WARMUP_HOST}/" 2>&1) || true
        case "$out" in
            *"code=2"*|*"code=3"*)
                # Extract connect time in seconds, convert to ms. If the
                # sed match fails (curl format drift or unusual output),
                # latency_ms stays empty so _update_health's guard skips
                # poisoning the lat-history with a fake 0.0 sample.
                connect_s=$(echo "$out" | sed -n 's/.*connect=\([0-9.]\+\)s.*/\1/p')
                if [[ -n "$connect_s" ]]; then
                    latency_ms=$(awk -v s="$connect_s" 'BEGIN{ printf "%.1f", s*1000 }')
                else
                    latency_ms=""
                fi

                # Throughput probe (only the slot picked for this pass).
                if (( run_tp )); then
                    local tp_out
                    tp_out=$(ip netns exec "$ns" curl -s -o /dev/null \
                            --connect-timeout 5 --max-time "$THROUGHPUT_TIMEOUT_S" \
                            -w "size=%{size_download} time=%{time_total}s" \
                            "$THROUGHPUT_TARGET_URL" 2>&1) || true
                    local size t
                    size=$(echo "$tp_out" | sed -n 's/.*size=\([0-9]\+\).*/\1/p')
                    t=$(   echo "$tp_out" | sed -n 's/.*time=\([0-9.]\+\)s.*/\1/p')
                    if [[ -n "$size" && -n "$t" ]] && awk -v t="$t" 'BEGIN{exit !(t>0)}'; then
                        # Mbps = (bytes * 8) / (seconds * 1e6)
                        throughput_mbps=$(awk -v sz="$size" -v t="$t" \
                            'BEGIN{ printf "%.2f", (sz * 8) / (t * 1000000) }')
                        logger -t "$LOG_TAG" "$inst throughput=$throughput_mbps Mbps ($size bytes / ${t}s)"
                    else
                        logger -t "$LOG_TAG" "$inst throughput probe failed: $tp_out"
                    fi
                fi

                if (( try > 1 )); then
                    logger -t "$LOG_TAG" "$inst try=$try (warmed) lat=${latency_ms}ms $out"
                    _update_health "$inst" warmed "$latency_ms" "$throughput_mbps"
                else
                    logger -t "$LOG_TAG" "$inst lat=${latency_ms}ms $out"
                    _update_health "$inst" ok "$latency_ms" "$throughput_mbps"
                fi
                return
                ;;
        esac
        sleep 1
    done
    logger -t "$LOG_TAG" "$inst ALL_FAIL last=$out"
    _update_health "$inst" all_fail
}

# Keep the dedicated DNS tunnel (dns-6) warm too. It's not in the rotating
# pool (no scoring/health state), but its Proton exit-side flow-state goes cold
# after ~25-35s idle exactly like the slots — so under light DNS load the first
# query after an idle gap hits the cold-catch and times out (SERVFAIL/no reply)
# before a retry warms it. A cheap neutral query (root NS, answered straight out
# of the in-tunnel resolver's cache) through the tunnel keeps that path warm.
# Best-effort: if dns-6 is mid-rotation the netns is briefly gone and this
# no-ops.
warm_dns6() {
    # UDP, matching unbound's forward-zone to 10.2.0.1 — UDP flow state is what
    # needs warming again. This was +tcp @9.9.9.9 for a real reason worth
    # remembering: unbound used to forward over DoT (tcp/853), and the
    # every-pass UDP dig (~6,500 queries/day per exit) was itself the abuse
    # signal that tripped Quad9's UDP limiter and blackholed the exit. That
    # hazard is gone for an in-tunnel resolver — Proton does not rate-limit its
    # own gateway address and the query never leaves the tunnel — so if this
    # ever forwards to a public resolver again, restore +tcp first.
    ip netns exec "$DNS_NS" dig @10.2.0.1 +time=2 +tries=1 . NS \
        >/dev/null 2>&1 || true
}

# One-slot entrypoint for proteus-livecheck@<slot>.service. A canary basket can
# take minutes, so the live check runs as its own unit rather than inside the
# 10s warmup pass, which systemd cannot start again until the previous one
# exits — a slow check there would stall every slot's warmup and age the health
# files past the dispatcher's freshness window.
if [[ "${1:-}" == "--live-check" ]]; then
    if [[ "${2:-}" =~ ^proton-[0-9]+$ ]]; then
        live_check "$2"
        exit 0
    fi
    echo "usage: ${0##*/} --live-check <proton-N>" >&2
    exit 1
fi

# Bump the persisted pass counter and decide which slot (if any) gets the
# throughput probe this pass.
[[ -r "$PASS_COUNTER_FILE" ]] && pass_counter=$(<"$PASS_COUNTER_FILE") || pass_counter=0
pass_counter=$((pass_counter + 1))
echo "$pass_counter" > "$PASS_COUNTER_FILE.tmp"
mv "$PASS_COUNTER_FILE.tmp" "$PASS_COUNTER_FILE"

slot_list=""
for state in /etc/proteus/state/proton-*.state; do
    inst=$(basename "$state" .state)
    [[ "$inst" =~ ^proton-[0-9]+$ ]] || continue
    slot_list="$slot_list $inst"
done
slot_list=${slot_list# }

tp_slot=$(pick_throughput_slot "$pass_counter" "$THROUGHPUT_EVERY_N_PASSES" "$slot_list")

# Same round-robin picker (it is generic despite the name), offset by 10 passes
# so a playability fetch and a 25MB throughput pull never land on the same slot
# in the same pass: throughput fires at pass%60==0, playability at pass%20==10.
pl_slot=""
if [[ "$PLAYABILITY_CHECK" == "on" ]]; then
    pl_slot=$(pick_throughput_slot "$((pass_counter + 10))" "$PLAYABILITY_EVERY_N_PASSES" "$slot_list")
fi

# Offset by 5 more passes: throughput fires at pass%60==0, playability at
# pass%20==10, live checks at pass%20==15, so no slot ever gets two heavy
# probes in one pass.
lc_slot=""; lc_slots=""
if [[ "$LIVECHECK" == "on" ]]; then
    lc_slot=$(pick_throughput_slot "$((pass_counter + 5))" "$LIVECHECK_EVERY_N_PASSES" "$slot_list")
    [[ -n "$lc_slot" ]] && lc_slots=$(livecheck_turn_slots "$lc_slot" "$slot_list")
else
    livecheck_off_clear_flags "$slot_list"
fi

# The web UI runs unprivileged and cannot ask WireGuard anything, so record the
# UDM tunnel's liveness here, where we are already root once every pass. Absent
# interface means the feature is off and the file is removed, so a stale age can
# never outlive the tunnel.
if [[ -e /sys/class/net/wg-udm ]]; then
    _hs=$(wg show wg-udm latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    # Shape first, then value. `[[ x -gt 0 ]]` evaluates x as arithmetic, where a
    # non-numeric word is a variable NAME — and under this script's `set -u` an
    # unset one aborts the whole pass, so an unexpected line from `wg` would cost
    # every slot its warmup and its health write, not just this file.
    if [[ "${_hs:-}" =~ ^[0-9]+$ ]] && (( _hs > 0 )); then
        printf 'HANDSHAKE_AGE_S=%s\n' "$(( $(date +%s) - _hs ))" > "$HEALTH_DIR/.udm-tunnel.tmp"
    else
        printf 'HANDSHAKE_AGE_S=\n' > "$HEALTH_DIR/.udm-tunnel.tmp"
    fi
    mv "$HEALTH_DIR/.udm-tunnel.tmp" "$HEALTH_DIR/.udm-tunnel"
else
    rm -f "$HEALTH_DIR/.udm-tunnel"
fi

# One resolution per pass, shared by every warm_one job below.
WARMUP_IP=$(_warmup_ip)

for inst in $slot_list; do
    if [[ "$inst" == "$tp_slot" ]]; then
        warm_one "$inst" 1 &
    else
        warm_one "$inst" 0 &
    fi
done
warm_dns6 &
# Backgrounded like the rest: a slow YouTube fetch must not delay the pass.
[[ -n "$pl_slot" ]] && playability_check "$pl_slot" &
# Not backgrounded here: its own unit, so a long canary run cannot hold the pass
# open. systemd serialises repeat starts for the same slot by itself.
for s in $lc_slots; do
    systemctl start --no-block "proteus-livecheck@$s.service"
done
wait
