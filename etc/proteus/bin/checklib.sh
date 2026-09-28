#!/usr/bin/env bash
# checklib.sh — shared probe machinery for the candidate gate (reputation-probe.sh)
# and the live watch (slot-warmup.sh), the Cloudflare verdict classifier, the
# canary list, and thin wrappers over ledger.py. Sourced, never executed.
# Design: architecture.md, "Cloudflare canaries, live checks and the exit ledger"
#
# Contract: callers set NS (the netns to probe from) before calling probe or
# cf_probe_canary. Everything else is parameterised through the variables below,
# all overridable from the environment so tests can point them at temp files.

CHECKLIB_DIR="${CHECKLIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
LEDGER_PY="${PROTEUS_LEDGER_PY:-$CHECKLIB_DIR/ledger.py}"
LEDGER_FILE="${PROTEUS_LEDGER_FILE:-/etc/proteus/state/exit-ledger.jsonl}"
CANARIES_FILE="${PROTEUS_CANARIES_FILE:-/etc/proteus/canaries.json}"
CHECKS_FILE="${PROTEUS_CHECKS_FILE:-/etc/proteus/checks.json}"
# mandatory|advisory. The _OVERRIDE form exists for rotate-slot.sh's step-down
# re-probe: it must win even when proteus-local.env (sourced earlier by the
# caller) pins PROTEUS_CF_TIER=mandatory.
# shellcheck disable=SC2034
CF_TIER="${PROTEUS_CF_TIER_OVERRIDE:-${PROTEUS_CF_TIER:-mandatory}}"
CF_QUARANTINE_MIN_EXITS="${PROTEUS_CF_QUARANTINE_MIN_EXITS:-8}"
CF_PROBE_TIMEOUT_S="${PROTEUS_CF_PROBE_TIMEOUT_S:-15}"
PER_PROBE_TIMEOUT="${PER_PROBE_TIMEOUT:-40}"
# PINNED, and byte-identical to PLAYABILITY_UA in slot-warmup.sh (test-asserted).
# A Cloudflare verdict is only comparable across slots and over time if the
# probe's shape never moves; a rotating UA would make the standard drift.
CF_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

# Rotating realistic desktop/mobile UAs for the generic probes (github, ddg...)
# whose verdict does not depend on which site variant answers.
UAS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/198.51.100.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/198.51.100.0 Mobile Safari/537.36"
)
rand_ua() { printf '%s' "${UAS[RANDOM % ${#UAS[@]}]}"; }

# --- Cloudflare verdict ------------------------------------------------------
# cf_classify <http-code> <header-file> <body-file>
# Prints one of: transport | challenge | block-1NNN | block-1xxx | not-cloudflare | clean
# Evaluated top to bottom; see the spec's "Verdict semantics" table.
cf_classify() {
    local code=$1 hdr=$2 body=$3 mit code1
    [[ -z "$code" || "$code" == "000" ]] && { echo transport; return; }
    # Last occurrence: after a curl transport retry the header file holds one
    # block per attempt and the final response is what Cloudflare decided.
    mit=$(grep -i '^cf-mitigated:' "$hdr" 2>/dev/null | tail -n1 | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr 'A-Z' 'a-z' || true)
    [[ "$mit" == "challenge" ]] && { echo challenge; return; }
    grep -qi '^cf-ray:' "$hdr" 2>/dev/null || { echo not-cloudflare; return; }
    # These body scans only apply to non-2xx responses: a 2xx origin page that
    # merely mentions "error code: 1020" in its text (a blog post, say) is not
    # a Cloudflare block, and a cf-ray header on a 2xx is clean by definition.
    if [[ "$code" != 2* ]]; then
        code1=$(grep -oiE 'error code: 1[0-9]{3}' "$body" 2>/dev/null | head -n1 | grep -oE '1[0-9]{3}' || true)
        [[ -n "$code1" ]] && { echo "block-$code1"; return; }
        case "$code" in
            403|429|503)
                if grep -qiE 'attention required|access denied' "$body" 2>/dev/null; then
                    echo block-1xxx; return
                fi ;;
        esac
    fi
    echo clean
}

# cf_host <url> -> the bare hostname, restricted to [A-Za-z0-9.-].
# A hostname cannot contain '=', ',', '#' or whitespace, and those are exactly
# the separators ledger.py's --canaries/--checks parsing uses, so a malformed or
# hostile URL must not be able to inject a field there. Empty after stripping
# (e.g. "https://") prints invalid-host so the caller still has a token to log.
cf_host() {
    local h
    h=$(printf '%s' "$1" | sed -E 's|^https?://||; s|[/:?#].*$||' | tr -dc 'A-Za-z0-9.-')
    printf '%s' "${h:-invalid-host}"
}

# One URL per line: canaries.json when valid, else the shipped basket (ledger.py
# owns both the parser and the default list so bash, mint and the UI agree).
cf_canaries() { python3 "$LEDGER_PY" canaries --file "$CANARIES_FILE" 2>/dev/null; }

# cf_quarantined <host> -> 0 when the ledger says the canary is site-wide.
# ledger.py answers 0 (quarantined) or 1 (not); any other status means the tool
# itself failed (no python3, ledger.py crashed or unreadable). That is NOT a
# "not quarantined" answer: treat it as quarantined so the canary is demoted to
# advisory and a broken ledger can never wedge rotation — but say so on stderr,
# because a silent demotion looks exactly like a healthy run.
cf_quarantined() {
    local rc=0
    python3 "$LEDGER_PY" quarantined --path "$LEDGER_FILE" --host "$1" \
        --min-exits "$CF_QUARANTINE_MIN_EXITS" 2>/dev/null || rc=$?
    case "$rc" in
        0) return 0 ;;
        1) return 1 ;;
    esac
    echo "checklib: quarantine lookup failed for $1 (rc=$rc); demoting to advisory" >&2
    return 0
}

cf_attainable() { # <active-hosts-csv> <live-slot-count> -> exit 0 when attainable
    python3 "$LEDGER_PY" attainable --path "$LEDGER_FILE" --hosts "$1" --slots "$2" 2>/dev/null
}

# cf_probe_canary <ns> <url> -> prints the verdict class. Pinned UA and headers;
# curl retries transport errors only (a 403 is a verdict, not an error).
# Budget: 2 attempts x CF_PROBE_TIMEOUT_S (15s) + retry delay, so ~35s worst
# case per canary and about 140s for the four-canary basket. That has to stay
# inside the rotation's per-candidate time, so widen the retry count only
# together with the outer timeout below.
cf_probe_canary() {
    local ns=$1 url=$2 hdr body code cls
    hdr=$(mktemp); body=$(mktemp)
    # Outer timeout must cover the full retry budget (2 attempts x --max-time
    # CF_PROBE_TIMEOUT_S, plus the retry delay), or a canary that legitimately
    # needs its retry gets killed mid-retry and misreported as transport.
    code=$(ip netns exec "$ns" timeout "$((2 * CF_PROBE_TIMEOUT_S + 5))" curl -s \
        -A "$CF_UA" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.9" \
        -D "$hdr" -o "$body" -w '%{http_code}' \
        --retry 1 --retry-all-errors --retry-delay 1 \
        --max-time "$CF_PROBE_TIMEOUT_S" --connect-timeout 5 \
        -- "$url" 2>/dev/null) || true
    # curl still prints %{http_code} on some transport failures, so a bare
    # `|| echo 000` fallback can concatenate onto real output (e.g. "000000").
    # Validate the shape instead of trusting a non-empty capture.
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
    cls=$(cf_classify "$code" "$hdr" "$body")
    rm -f "$hdr" "$body"
    printf '%s\n' "$cls"
}

# --- generic probe (moved from reputation-probe.sh) ----------------------------
# Args: <label> <url> <expected-http-pattern> [body-must-contain] [force-ua]
# expected-http-pattern is a bash extended regex against the literal HTTP code,
# anchored to the full string. Use "200" for an exact match or "200|301|302"
# to accept multiple codes. force-ua pins the User-Agent instead of picking one
# at random — only for probes whose ASSERTION depends on which site variant
# answers (see youtube in reputation-probe.sh).
# Prints one of: "PASS <label>", "BLOCK <label> <reason>", "ERROR <label> <reason>"
# Cloudflare reasons come first: cf-challenge, cf-1NNN. Uses $NS.
probe() {
    local label="$1" url="$2" expected="$3" want_body="${4:-}" force_ua="${5:-}"
    local ua body_file hdr_file code body cf
    ua="${force_ua:-$(rand_ua)}"
    body_file=$(mktemp); hdr_file=$(mktemp)
    # Retry on transient transport errors — tunnels lose stray packets and DNS
    # warmup can miss even after the priming loop. 3 attempts x 8s each + delays
    # must stay under PER_PROBE_TIMEOUT.
    code=$(ip netns exec "${NS:?probe needs NS}" timeout "$PER_PROBE_TIMEOUT" curl -sS \
        -A "$ua" \
        -H "Accept: text/html,application/json,*/*" \
        -D "$hdr_file" \
        -o "$body_file" \
        -w "%{http_code}" \
        --retry 3 --retry-all-errors --retry-delay 1 \
        --max-time 8 \
        --connect-timeout 5 \
        -- "$url" 2>/dev/null) || true
    [[ "$code" =~ ^[0-9]{3}$ ]] || code="000"
    body=$(head -c 4096 "$body_file" 2>/dev/null || true)
    # Body assertions are matched against the WHOLE response, not the 4096-byte
    # prefix above: YouTube's playabilityStatus sits ~100KB into a ~900KB page.
    # -F: literal substring, never a regex. -e: an operator string starting
    # with "-" can't become a grep option.
    local body_hit=0
    if [[ -n "$want_body" ]] && grep -qF -e "$want_body" "$body_file" 2>/dev/null; then
        body_hit=1
    fi
    # YouTube's "Sign in to confirm you're not a bot" is a genuine reputation
    # block deep in the page, so it needs the full-body scan. The apostrophe is
    # a UTF-8 right single quote in YouTube's markup, hence .{0,3}.
    local bot_gated=0
    if grep -qiE "sign in to confirm you.{0,3}re not a bot" "$body_file" 2>/dev/null; then
        bot_gated=1
    fi
    cf=$(cf_classify "$code" "$hdr_file" "$body_file")
    rm -f "$body_file" "$hdr_file"

    if [[ "$code" == "000" ]]; then
        echo "ERROR $label transport-fail"
        return
    fi
    if (( bot_gated )); then
        echo "BLOCK $label bot-gate"
        return
    fi
    # Cloudflare's own verdict beats the status-code heuristics below: it says
    # WHY (clickable challenge vs 1xxx hard block), which the ledger records.
    case "$cf" in
        challenge) echo "BLOCK $label cf-challenge"; return ;;
        block-*)   echo "BLOCK $label cf-${cf#block-}"; return ;;
    esac
    case "$code" in
        403|429)
            echo "BLOCK $label http=$code"
            return
            ;;
    esac
    # Captcha challenges (non-Cloudflare, or Cloudflare without the header) —
    # body markers saying the site asked us to prove humanity. BLOCK on purpose.
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

# result_class "<PASS|BLOCK|ERROR|SKIP> <label> [reason]" -> "<label> <class>"
result_class() {
    local kind label reason
    read -r kind label reason <<<"$1"
    case "$kind:$reason" in
        PASS:*)             echo "$label clean" ;;
        BLOCK:cf-challenge) echo "$label challenge" ;;
        BLOCK:cf-1*)        echo "$label block-${reason#cf-}" ;;
        BLOCK:*)            echo "$label block" ;;
        SKIP:*)             echo "$label skip" ;;
        *)                  echo "$label error" ;;
    esac
}

# custom_checks [mandatory|advisory|all] -> TSV lines: tier<TAB>url<TAB>body
# A missing or malformed checks.json yields nothing — a bad custom list can
# never stop a rotation. Tabs/newlines in fields are rejected by ui_logic and
# re-checked here because this is TSV.
custom_checks() {
    local want="${1:-all}"
    [ -r "$CHECKS_FILE" ] || return 0
    python3 - "$CHECKS_FILE" "$want" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
want = sys.argv[2]
BAD = (" ", "\t", "\n", "\r")
for c in d.get("checks", [])[:15]:
    u = str(c.get("url", "")); t = str(c.get("tier", "")); b = str(c.get("body", ""))
    if (u.lower().startswith(("http://", "https://"))
            and t in ("mandatory", "advisory")
            and not any(x in u for x in BAD) and not any(x in b for x in BAD)
            and (want == "all" or t == want)):
        print(t + "\t" + u + "\t" + b)
PY
}

# ledger_record <ledger.py append args...>  — best effort, never fails the caller.
ledger_record() {
    python3 "$LEDGER_PY" append --path "$LEDGER_FILE" "$@" 2>/dev/null || true
}

live_slot_count() {
    # find exits 1 when the state directory is absent, which would abort a
    # pipefail caller; swallow that so a missing dir simply reads as 0 slots.
    local dir="${PROTEUS_STATE_DIR:-/etc/proteus/state}"
    { find "$dir" -maxdepth 1 -name 'proton-*.state' 2>/dev/null || true; } | wc -l | tr -d ' '
}
