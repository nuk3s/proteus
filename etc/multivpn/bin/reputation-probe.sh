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
# Defaults are tuned for the 5-probe mandatory tier we run (github, google204,
# ddg, cloudflare, youtube). We require 4-of-5 to PASS and tolerate at most
# one ERROR — a "gold standard" exit must reach the popular consumer
# services that user traffic actually hits, not just Google's captive-portal
# probe. Override via env if you're tweaking thresholds at the CLI.
MIN_MANDATORY_PASS="${MIN_MANDATORY_PASS:-4}"
MAX_MANDATORY_ERRORS="${MAX_MANDATORY_ERRORS:-1}"
PER_PROBE_TIMEOUT="${PER_PROBE_TIMEOUT:-40}"

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

# Rotating realistic desktop/mobile UAs — each probe picks one at random.
UAS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/198.51.100.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/198.51.100.0 Mobile Safari/537.36"
)
rand_ua() { printf '%s' "${UAS[RANDOM % ${#UAS[@]}]}"; }

# Args: <label> <url> <expected-http-pattern> [body-must-contain]
# expected-http-pattern is a bash extended regex against the literal HTTP code,
# anchored to the full string. Use "200" for an exact match or "200|301|302"
# to accept multiple codes. (Useful when a site geo-redirects, etc.)
# Prints one of: "PASS <label>", "BLOCK <label> <reason>", "ERROR <label> <reason>"
probe() {
    local label="$1" url="$2" expected="$3" want_body="${4:-}"
    local ua body_file code body
    ua=$(rand_ua)
    body_file=$(mktemp)
    # Retry on transient transport errors — tunnels lose stray packets and DNS
    # warmup can miss even after our priming loop. 3 attempts × 8s each + delays
    # must stay under PER_PROBE_TIMEOUT.
    code=$(ip netns exec "$NS" timeout "$PER_PROBE_TIMEOUT" curl -sS \
        -A "$ua" \
        -H "Accept: text/html,application/json,*/*" \
        -o "$body_file" \
        -w "%{http_code}" \
        --retry 3 --retry-all-errors --retry-delay 1 \
        --max-time 8 \
        --connect-timeout 5 \
        "$url" 2>/dev/null || echo "000")
    body=$(head -c 4096 "$body_file" 2>/dev/null || true)
    rm -f "$body_file"

    if [[ "$code" == "000" ]]; then
        echo "ERROR $label transport-fail"
        return
    fi

    case "$code" in
        403|429)
            echo "BLOCK $label http=$code"
            return
            ;;
    esac

    # Captcha challenges (Cloudflare et al.) — body markers indicating the
    # site asked us to prove humanity. We BLOCK on these intentionally:
    # a captcha-clean exit is the gold standard, and rotation has 5 attempts
    # to find one. Don't relax this.
    if grep -qiE 'cf-chl-bypass|cdn-cgi/challenge-platform|attention required|unusual traffic from your computer|sorry, we just need to make sure' <<<"$body"; then
        echo "BLOCK $label body-challenge"
        return
    fi

    if ! [[ "$code" =~ ^($expected)$ ]]; then
        echo "ERROR $label http=$code (expected $expected)"
        return
    fi
    if [[ -n "$want_body" ]] && ! grep -qF "$want_body" <<<"$body"; then
        echo "ERROR $label body-missing '$want_body'"
        return
    fi

    echo "PASS $label"
}

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
# YouTube geo-redirects (302) are normal — accept 3xx alongside 200.
mandatory_results+=( "$(probe youtube    "https://www.youtube.com/"                    '200|301|302|307|308')" )

# ADVISORY — Reddit blocks large fractions of Proton's streaming pool by policy,
# not abuse-rep, so its verdict is informational only.
advisory_results+=( "$(probe reddit     "https://www.reddit.com/.json"            200)" )

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
