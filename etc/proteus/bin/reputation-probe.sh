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
# ddg, cloudflare, youtube). A "gold standard" exit must reach the popular
# consumer services that user traffic actually hits, not just Google's
# captive-portal probe. Override via env if you're tweaking thresholds at the CLI.
#
# MAX_MANDATORY_ERRORS is an exclusive bound: the test below is
# `m_error >= MAX_MANDATORY_ERRORS`, so the default of 1 tolerates ZERO errors.
# The value that tolerates one error is 2. Counter-intuitive, but changing the
# comparison now would silently loosen every deployment that has tuned this.
MIN_MANDATORY_PASS="${PROTEUS_REP_MIN_MANDATORY_PASS:-${MIN_MANDATORY_PASS:-4}}"
MAX_MANDATORY_ERRORS="${PROTEUS_REP_MAX_MANDATORY_ERRORS:-${MAX_MANDATORY_ERRORS:-1}}"
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

# Args: <label> <url> <expected-http-pattern> [body-must-contain] [force-ua]
# expected-http-pattern is a bash extended regex against the literal HTTP code,
# anchored to the full string. Use "200" for an exact match or "200|301|302"
# to accept multiple codes. (Useful when a site geo-redirects, etc.)
# force-ua pins the User-Agent instead of picking one at random — only for
# probes whose ASSERTION depends on which site variant answers (see youtube).
# Prints one of: "PASS <label>", "BLOCK <label> <reason>", "ERROR <label> <reason>"
probe() {
    local label="$1" url="$2" expected="$3" want_body="${4:-}" force_ua="${5:-}"
    local ua body_file code body
    ua="${force_ua:-$(rand_ua)}"
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
        -- "$url" 2>/dev/null || echo "000")
    body=$(head -c 4096 "$body_file" 2>/dev/null || true)
    # Body assertions are matched against the WHOLE response, not the 4096-byte
    # prefix above. The signals worth asserting on live deep inside big pages —
    # YouTube's playabilityStatus sits ~100KB into a ~900KB watch page — so a
    # prefix match would silently never fire and every check would "pass".
    # -F: literal substring, never a regex. -e: the next arg is the pattern, so
    # an operator-supplied string starting with "-" can't become a grep option.
    local body_hit=0
    if [[ -n "$want_body" ]] && grep -qF -e "$want_body" "$body_file" 2>/dev/null; then
        body_hit=1
    fi
    # Bot-gating (YouTube's "Sign in to confirm you're not a bot") is a genuine
    # reputation block, but it appears deep in the page, so it needs the same
    # full-body scan. Kept separate from the challenge markers below rather than
    # widening those to the full body: strings like "attention required" are
    # generic enough that scanning 900KB of arbitrary page content for them
    # would start producing false BLOCKs. The apostrophe is a UTF-8 right single
    # quote in YouTube's markup, hence .{0,3} rather than a literal.
    local bot_gated=0
    if grep -qiE "sign in to confirm you.{0,3}re not a bot" "$body_file" 2>/dev/null; then
        bot_gated=1
    fi
    rm -f "$body_file"

    if [[ "$code" == "000" ]]; then
        echo "ERROR $label transport-fail"
        return
    fi

    if (( bot_gated )); then
        echo "BLOCK $label bot-gate"
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
    if [[ -n "$want_body" ]] && (( ! body_hit )); then
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

# Custom operator checks (rotation-only, in this staging netns). A missing or
# malformed file is ignored — a bad custom list can never stop a rotation.
# Uses process substitution (< <(...)), NOT a pipe: under `set -euo pipefail` a
# `python3 ... | while` would run the loop in a subshell and silently discard
# every += append. A custom check passes on any 2xx/3xx that isn't a block page.
# An optional "body" field turns a check into a real content assertion instead
# of a bare status check. That matters for streaming: Netflix, YouTube and Apple
# all answer HTTP 200 from an exit they will not actually serve video to, so a
# status-only check cannot express "this exit works for streaming".
# The field is passed to `grep -F -e` as a literal substring (see probe()), and
# ui_logic.validate_checks rejects tabs/newlines so it cannot break this TSV.
CHECKS_FILE="${PROTEUS_CHECKS_FILE:-/etc/proteus/checks.json}"
if [ -r "$CHECKS_FILE" ]; then
    while IFS=$'\t' read -r c_tier c_url c_body; do
        [ -n "$c_url" ] || continue
        c_host=$(printf '%s' "$c_url" | sed -E 's#^https?://##; s#/.*$##')
        r=$(probe "custom:${c_host:0:40}" "$c_url" '[23][0-9][0-9]' "${c_body:-}")
        if [ "$c_tier" = "mandatory" ]; then
            mandatory_results+=( "$r" )
        else
            advisory_results+=( "$r" )
        fi
    done < <(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
BAD = ("\t", "\n", "\r")
for c in d.get("checks", [])[:15]:   # hard cap even for a hand-edited file
    u = str(c.get("url", "")); t = str(c.get("tier", "")); b = str(c.get("body", ""))
    if (u.lower().startswith(("http://", "https://"))
            and t in ("mandatory", "advisory")
            and not any(x in u for x in BAD) and not any(x in b for x in BAD)):
        print(t + "\t" + u + "\t" + b)' "$CHECKS_FILE" 2>/dev/null)
fi

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
