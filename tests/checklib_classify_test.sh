#!/usr/bin/env bash
# tests/checklib_classify_test.sh — the Cloudflare verdict classifier and the
# canary list helpers in checklib.sh. Pure functions over fixture files.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
export PROTEUS_CANARIES_FILE="$TMP/canaries.json"
. "$ROOT/etc/proteus/bin/checklib.sh"

mk() { printf '%b' "$2" > "$TMP/$1"; printf '%s' "$TMP/$1"; }
H_CHAL=$(mk h_chal 'HTTP/2 403\r\ncf-mitigated: challenge\r\ncf-ray: 8a1b-IAD\r\nserver: cloudflare\r\n\r\n')
H_CF=$(mk h_cf 'HTTP/2 403\r\ncf-ray: 8a1b-IAD\r\nserver: cloudflare\r\n\r\n')
H_CF_UP=$(mk h_cfup 'HTTP/2 403\r\nCF-Mitigated: CHALLENGE\r\nCF-RAY: 8a1b-IAD\r\n\r\n')
H_NONE=$(mk h_none 'HTTP/2 403\r\nserver: nginx\r\n\r\n')
H_RETRY=$(mk h_retry 'HTTP/2 503\r\ncf-ray: 1\r\n\r\nHTTP/2 403\r\ncf-mitigated: challenge\r\ncf-ray: 2\r\n\r\n')
H_CHAL_NOSPACE=$(mk h_chal_nospace 'HTTP/2 403\r\ncf-mitigated:challenge\r\ncf-ray: 8a1b-IAD\r\n\r\n')
B_EMPTY=$(mk b_empty '')
B_1020=$(mk b_1020 '<html><head><title>Access denied</title></head><body>... error code: 1020 ...</body></html>')
B_1015=$(mk b_1015 '<title>Access denied | x.invalid used Cloudflare to restrict access</title> Error code: 1015')
B_ATT=$(mk b_att '<title>Attention Required! | Cloudflare</title><p>Please complete the security check</p>')
B_PAGE=$(mk b_page '<html><title>Hello</title></html>')

echo "cf_classify decision table"
assert_eq "$(cf_classify 000 "$H_NONE" "$B_EMPTY")" transport "000 -> transport"
assert_eq "$(cf_classify "" "$H_NONE" "$B_EMPTY")" transport "empty code -> transport"
assert_eq "$(cf_classify 403 "$H_CHAL" "$B_EMPTY")" challenge "cf-mitigated: challenge -> challenge"
assert_eq "$(cf_classify 403 "$H_CF_UP" "$B_EMPTY")" challenge "header match is case-insensitive"
assert_eq "$(cf_classify 403 "$H_RETRY" "$B_EMPTY")" challenge "last header block wins after a curl retry"
assert_eq "$(cf_classify 403 "$H_CHAL_NOSPACE" "$B_EMPTY")" challenge "cf-mitigated:challenge (no space) -> challenge"
assert_eq "$(cf_classify 200 "$H_CF" "$B_1020")" clean "1020 text in a 200 body is not a block (scan only fires on non-2xx)"
assert_eq "$(cf_classify 403 "$H_CF" "$B_1020")" block-1020 "error code 1020 -> block-1020"
assert_eq "$(cf_classify 429 "$H_CF" "$B_1015")" block-1015 "1015 on a 429 -> block-1015"
assert_eq "$(cf_classify 403 "$H_CF" "$B_ATT")" block-1xxx "Attention Required page without a code -> block-1xxx"
assert_eq "$(cf_classify 403 "$H_NONE" "$B_1020")" not-cloudflare "no cf-ray -> not-cloudflare, whatever the body says"
assert_eq "$(cf_classify 200 "$H_CF" "$B_PAGE")" clean "200 with cf-ray -> clean"
assert_eq "$(cf_classify 401 "$H_CF" "$B_EMPTY")" clean "401 with cf-ray and no mitigation -> clean"
assert_eq "$(cf_classify 403 "$H_CF" "$B_PAGE")" clean "403 from origin behind Cloudflare, no markers -> clean"

echo "cf_host"
assert_eq "$(cf_host 'https://www.example.invalid/path?x=1')" www.example.invalid "strips scheme, path, query"
assert_eq "$(cf_host 'https://example.invalid:8443/')" example.invalid "strips port"
assert_eq "$(cf_host 'https://a=b,c.invalid/#x')" abc.invalid "drops ledger field separators and the fragment"
assert_eq "$(cf_host 'https://')" invalid-host "nothing left to parse -> invalid-host"

echo "canary list: shipped basket when the file is absent"
assert_eq "$(cf_canaries | wc -l | tr -d ' ')" "3" "three default canaries"
assert_eq "$(cf_canaries | head -n1)" "https://discord.com/" "first default is discord"

echo "canary list: the file wins when valid"
printf '{"canaries":[{"url":"https://one.invalid/"},{"url":"https://two.invalid/"}]}' > "$PROTEUS_CANARIES_FILE"
assert_eq "$(cf_canaries | tr '\n' ' ')" "https://one.invalid/ https://two.invalid/ " "file list used"
printf 'nope' > "$PROTEUS_CANARIES_FILE"
assert_eq "$(cf_canaries | wc -l | tr -d ' ')" "3" "malformed file -> defaults"

echo "the probe user agent is pinned and identical to the playability UA"
ua_lib=$(sed -n 's/^CF_UA="\(.*\)"$/\1/p' "$ROOT/etc/proteus/bin/checklib.sh")
ua_warm=$(sed -n 's/^PLAYABILITY_UA="\(.*\)"$/\1/p' "$ROOT/etc/proteus/bin/slot-warmup.sh")
[[ -n "$ua_lib" && "$ua_lib" == "$ua_warm" ]] && r=ok || r=fail
assert_eq "$r" ok "CF_UA == PLAYABILITY_UA"
[[ "$ua_lib" == *"Windows NT"* ]] && r=ok || r=fail
assert_eq "$r" ok "pinned UA is a desktop string"

echo "transport failures, header/body precedence, and live_slot_count (curl+ip stubs)"
mkdir -p "$TMP/bin"
# ip: `netns exec <ns> <cmd...>` runs <cmd...> locally so curl is our stub.
cat > "$TMP/bin/ip" <<'IPEOF'
#!/usr/bin/env bash
[ "$1" = "netns" ] && [ "$2" = "exec" ] && { shift 3; exec "$@"; }
exit 0
IPEOF
# curl: honors -D <hdrfile> and -o <bodyfile>, prints ${STUB_CODE} on stdout
# (what -w '%{http_code}' would produce), writes ${STUB_HDR}/${STUB_BODY} into
# those files, and exits ${STUB_EXIT:-0}. A real curl on a transport failure
# can still print a (possibly bogus) http_code before it exits non-zero — this
# stub reproduces exactly that shape.
cat > "$TMP/bin/curl" <<'CURLEOF'
#!/usr/bin/env bash
hdr=""; body=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) hdr="$2"; shift 2 ;;
        -o) body="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n "$hdr" ]] && printf '%b' "${STUB_HDR:-}" > "$hdr"
[[ -n "$body" ]] && printf '%b' "${STUB_BODY:-}" > "$body"
printf '%s' "${STUB_CODE:-000}"
exit "${STUB_EXIT:-0}"
CURLEOF
chmod +x "$TMP/bin/ip" "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH"

export STUB_CODE=000 STUB_EXIT=7 STUB_HDR='' STUB_BODY=''
assert_eq "$(cf_probe_canary ns https://x.invalid/)" transport \
    "a curl transport failure (exit 7) -> transport, not not-cloudflare (was '000000')"
NS=ns
assert_eq "$(probe lbl https://x.invalid/ 200)" "ERROR lbl transport-fail" \
    "same transport failure via probe() -> ERROR transport-fail, not http=000000"
unset STUB_CODE STUB_EXIT STUB_HDR STUB_BODY

export STUB_CODE=403 STUB_EXIT=0 STUB_HDR='HTTP/2 403\r\ncf-mitigated: challenge\r\ncf-ray: 8a1b-IAD\r\n\r\n' STUB_BODY=''
assert_eq "$(probe lbl https://x.invalid/ 200)" "BLOCK lbl cf-challenge" \
    "cf-challenge wins over the generic http=403 rule"
unset STUB_CODE STUB_EXIT STUB_HDR STUB_BODY

EMPTYDIR="$TMP/emptystate"; mkdir -p "$EMPTYDIR"
assert_eq "$(PROTEUS_STATE_DIR="$EMPTYDIR" live_slot_count)" "0" \
    "live_slot_count on an empty dir prints 0 without tripping pipefail (was: ls exit 2)"

echo "result_class maps probe lines to ledger classes"
assert_eq "$(result_class 'PASS custom:a.invalid')" "custom:a.invalid clean" "PASS -> clean"
assert_eq "$(result_class 'BLOCK custom:a.invalid cf-challenge')" "custom:a.invalid challenge" "cf-challenge -> challenge"
assert_eq "$(result_class 'BLOCK custom:a.invalid cf-1020')" "custom:a.invalid block-1020" "cf-1020 -> block-1020"
assert_eq "$(result_class 'BLOCK custom:a.invalid http=403')" "custom:a.invalid block" "generic block -> block"
assert_eq "$(result_class 'ERROR custom:a.invalid transport-fail')" "custom:a.invalid error" "ERROR -> error"
assert_eq "$(result_class 'SKIP cf:a.invalid not-cloudflare')" "cf:a.invalid skip" "SKIP -> skip"

summary
