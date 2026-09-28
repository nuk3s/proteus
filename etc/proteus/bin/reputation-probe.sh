#!/usr/bin/env bash
# reputation-probe.sh — empirical reputation check for a VPN exit by probing
# real-world endpoints from inside its namespace. No third-party API, no
# correlation leak to a reputation vendor.
#
# Usage: reputation-probe.sh <netns>
#
# Probes are classified into two tiers:
#   mandatory — must pass; any definitive block or too many errors => FAIL
#   advisory  — logged for visibility but does NOT gate the verdict (e.g. Reddit,
#               which blocks many Proton streaming IPs as a policy choice rather
#               than for abuse-reputation reasons)
#
# Mandatory PASS rule:
#   no mandatory BLOCK AND mandatory_pass >= MIN_MANDATORY_PASS
#     AND mandatory_error < MAX_MANDATORY_ERRORS
#
# Exit codes:
#   0 = PASS
#   1 = FAIL
#   2 = usage error

set -euo pipefail

NS="${1:?netns required}"

# This script has no proteus.env dependency of its own (it only reads the two
# thresholds below), but it's invoked as a subprocess — not sourced — by
# rotate-slot.sh, so it can't inherit anything rotate-slot.sh sourced. Load
# the UI-managed overlay directly so an operator-set PROTEUS_REP_* knob
# reaches this process.
[ -f /etc/proteus/proteus-local.env ] && . /etc/proteus/proteus-local.env

# Defaults are tuned for the 5-probe mandatory tier we run (github, google204,
# ddg, cloudflare, youtube) plus the Cloudflare canaries. A "gold standard" exit
# must reach the popular consumer services that user traffic actually hits, not
# just Google's captive-portal probe. Override via env if you're tweaking at the CLI.
#
# MAX_MANDATORY_ERRORS is an exclusive bound: the test below is
# `m_error >= MAX_MANDATORY_ERRORS`, so the default of 1 tolerates ZERO errors.
# The value that tolerates one error is 2. Counter-intuitive, but changing the
# comparison now would silently loosen every deployment that has tuned this.
MIN_MANDATORY_PASS="${PROTEUS_REP_MIN_MANDATORY_PASS:-${MIN_MANDATORY_PASS:-4}}"
MAX_MANDATORY_ERRORS="${PROTEUS_REP_MAX_MANDATORY_ERRORS:-${MAX_MANDATORY_ERRORS:-1}}"

# probe(), the UA pool, the Cloudflare classifier and the canary list live in
# checklib.sh, shared with slot-warmup.sh so the gate and the live watch judge
# an exit identically.
# shellcheck source=/dev/null
. "$(dirname "${BASH_SOURCE[0]}")/checklib.sh"

ip netns list | awk '{print $1}' | grep -qx "$NS" || {
    echo "netns '$NS' not found" >&2
    exit 2
}

# Pre-warm the WG exit path so the first real probe isn't catching Proton's
# 25-35s exit-side cold window. proton.me is the same target slot-warmup uses;
# already correlated via the WG handshake, so no third-party leak. Failure here
# is non-fatal — the per-probe retries will still ride out a cold catch.
ip netns exec "$NS" curl -sI -o /dev/null --max-time 8 https://proton.me/ 2>/dev/null || true

# Warm DNS once so curl's per-probe timers aren't soaked up by cold-path
# resolution. `ip netns exec` uses /etc/netns/<ns>/resolv.conf; queries exit
# via the default wg0 route so they transit the VPN (no leak).
for host in api.github.com www.google.com www.reddit.com duckduckgo.com www.cloudflare.com www.youtube.com; do
    ip netns exec "$NS" getent ahostsv4 "$host" >/dev/null 2>&1 || true
done

mandatory_results=()
advisory_results=()

# MANDATORY — general-web usability; block here is a genuine reputation signal.
# The cloudflare and youtube probes exist because google's generate_204 endpoint
# is much more permissive than the consumer services users actually hit. An exit
# that passes generate_204 but gets TLS-reset by Cloudflare or YouTube is exactly
# the "looks fine on paper, broken in practice" case we want to reject at mint.
mandatory_results+=( "$(probe github     "https://api.github.com/zen"                  '200')" )
mandatory_results+=( "$(probe google204  "https://www.google.com/generate_204"         '204')" )
mandatory_results+=( "$(probe ddg        "https://duckduckgo.com/?q=test&format=json"  '200')" )
mandatory_results+=( "$(probe cloudflare "https://www.cloudflare.com/"                 '200|301|302|308')" )
# YouTube: assert a video is actually PLAYABLE, not merely that the site loads.
# The homepage returns 200 from exits that cannot play anything — measured
# 2026-08-08, two of five live slots served 200 on / while every watch page came
# back playabilityStatus=LOGIN_REQUIRED ("Sign in to confirm you're not a bot").
# Datacenter ranges get bot-gated per-IP, so this is the single most useful
# reputation signal available and the homepage probe is blind to it.
# The video is "Me at the zoo" (the oldest video on the site): not age-restricted,
# not region-locked, and about as unlikely to be removed as anything on YouTube.
# If it ever does disappear, this check fails closed (ERROR body-missing) —
# swap the ID rather than dropping the assertion.
#
# The UA is PINNED to a desktop browser, and that is load-bearing in BOTH
# directions (measured 2026-08-08 across five live exits):
#   * a mobile UA gets a 302 to m.youtube.com with an empty body, so the
#     assertion can never match and a perfectly healthy exit fails;
#   * worse, m.youtube.com does NOT bot-gate — on an exit where the desktop
#     site returns LOGIN_REQUIRED, the mobile site still returns status OK.
# With the random UA rotation used elsewhere, this check would therefore both
# fail healthy exits and MISS gated ones, roughly 2 times in 5 each. Rotation
# is fine for the other probes, whose verdict does not depend on which variant
# of a site answers; here it must not be used. Expected status is exactly 200
# for the same reason: with a desktop UA there is no redirect to follow.
mandatory_results+=( "$(probe youtube    "https://www.youtube.com/watch?v=jNQXAC9IVRw" '200' \
                              '"playabilityStatus":{"status":"OK"' \
                              "${UAS[0]}")" )

# ADVISORY — Reddit blocks large fractions of Proton's streaming pool by policy,
# not abuse-rep, so its verdict is informational only.
advisory_results+=( "$(probe reddit     "https://www.reddit.com/.json"            200)" )

# --- Cloudflare canaries -------------------------------------------------------
# The shipped basket (or canaries.json), judged purely on Cloudflare's own
# verdict via cf_probe_canary. Tier comes from PROTEUS_CF_TIER; a canary the
# ledger shows as site-wide (quarantined) is demoted to advisory for this run
# so it cannot wedge rotation; a canary that is no longer on Cloudflare is
# SKIPped and counts for nothing. STANDING is clean/active over the canaries
# that are part of the standard right now.
canary_lines=()
canary_active=0; canary_clean=0
while IFS= read -r c_url; do
    [[ -n "$c_url" ]] || continue
    c_host=$(cf_host "$c_url")
    cls=$(cf_probe_canary "$NS" "$c_url")
    canary_lines+=( "$c_host $cls" )
    case "$cls" in
        clean)          r="PASS cf:$c_host" ;;
        challenge)      r="BLOCK cf:$c_host cf-challenge" ;;
        block-*)        r="BLOCK cf:$c_host cf-${cls#block-}" ;;
        not-cloudflare) r="SKIP cf:$c_host not-cloudflare" ;;
        # A lost socket is not a verdict. SKIP, so it counts in neither pass,
        # block nor error — the same rule slot-warmup.sh's live watch applies
        # (transport bumps the streak for visibility but never rotates and
        # never dirties CF_CLEAN). Rotation-time and live verdicts have to agree
        # on what a canary means, or a candidate gets rejected here for
        # something the live watch would shrug off. Reachability is still
        # gated: the built-in mandatory `cloudflare` probe covers an exit that
        # cannot reach Cloudflare at all. It stays inside canary_active, so
        # STANDING drops and a candidate that lost a canary mid-probe ranks
        # below one that answered every canary.
        *)              r="SKIP cf:$c_host transport-fail" ;;
    esac
    if [[ "$cls" != "not-cloudflare" ]] && ! cf_quarantined "$c_host"; then
        canary_active=$((canary_active + 1))
        [[ "$cls" == "clean" ]] && canary_clean=$((canary_clean + 1))
        if [[ "$CF_TIER" == "mandatory" ]]; then
            mandatory_results+=( "$r" )
        else
            advisory_results+=( "$r" )
        fi
    else
        advisory_results+=( "$r" )
    fi
done < <(cf_canaries)

# Custom operator checks (rotation-only, in this staging netns). checklib's
# custom_checks reads checks.json and yields nothing for a missing or malformed
# file — a bad custom list can never stop a rotation. A custom check passes on
# any 2xx/3xx that isn't a block page; the optional "body" field turns it into
# a content assertion (streaming sites answer 200 from exits they won't serve).
while IFS=$'\t' read -r c_tier c_url c_body; do
    [ -n "$c_url" ] || continue
    c_host=$(cf_host "$c_url")
    r=$(probe "custom:${c_host:0:40}" "$c_url" '[23][0-9][0-9]' "${c_body:-}")
    if [ "$c_tier" = "mandatory" ]; then
        mandatory_results+=( "$r" )
    else
        advisory_results+=( "$r" )
    fi
done < <(custom_checks all)

count() {
    # $1 = prefix (PASS|BLOCK|ERROR), remaining args = results array
    local prefix="$1"; shift
    local n=0
    for r in "$@"; do
        [[ "$r" == ${prefix}* ]] && n=$((n+1))
    done
    echo "$n"
}

echo "--- mandatory ---"
for r in "${mandatory_results[@]}"; do echo "$r"; done
m_pass=$(count PASS "${mandatory_results[@]}")
m_block=$(count BLOCK "${mandatory_results[@]}")
m_error=$(count ERROR "${mandatory_results[@]}")

echo "--- advisory ---"
for r in "${advisory_results[@]}"; do echo "$r"; done
a_block=$(count BLOCK "${advisory_results[@]}")

# BASELINE: the verdict the non-canary mandatory set would give on its own.
# rotate-slot.sh's step-down promotes only candidates whose baseline passes.
baseline_results=()
for r in "${mandatory_results[@]}"; do
    [[ "$r" == *" cf:"* ]] || baseline_results+=( "$r" )
done
b_pass=$(count PASS "${baseline_results[@]}")
b_block=$(count BLOCK "${baseline_results[@]}")
b_error=$(count ERROR "${baseline_results[@]}")
baseline=PASS
if (( b_block > 0 || b_error >= MAX_MANDATORY_ERRORS || b_pass < MIN_MANDATORY_PASS )); then
    baseline=FAIL
fi

# Machine-readable trailer for rotate-slot.sh (ledger + step-down). One CANARY
# line per canary, one CHECK line per non-canary result, then STANDING and
# BASELINE. Keep these formats stable; tests and the ledger depend on them.
for l in "${canary_lines[@]}"; do echo "CANARY $l"; done
for r in "${mandatory_results[@]}" "${advisory_results[@]}"; do
    [[ "$r" == *" cf:"* ]] && continue
    echo "CHECK $(result_class "$r")"
done
echo "STANDING $canary_clean/$canary_active"
echo "BASELINE $baseline"

echo "SUMMARY mandatory: pass=$m_pass block=$m_block error=$m_error | advisory: block=$a_block"

# Verdict (mandatory-only)
if (( m_block > 0 )); then
    echo "VERDICT FAIL (mandatory block signals present)"
    exit 1
fi
if (( m_error >= MAX_MANDATORY_ERRORS )); then
    echo "VERDICT FAIL (too many mandatory errors: $m_error >= $MAX_MANDATORY_ERRORS)"
    exit 1
fi
if (( m_pass < MIN_MANDATORY_PASS )); then
    echo "VERDICT FAIL (insufficient mandatory passes: $m_pass < $MIN_MANDATORY_PASS)"
    exit 1
fi

if (( a_block > 0 )); then
    echo "VERDICT PASS (with advisory blocks — e.g. Reddit; exit still usable for general browsing)"
else
    echo "VERDICT PASS"
fi
exit 0
