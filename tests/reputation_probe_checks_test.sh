#!/usr/bin/env bash
# Custom-check merge in reputation-probe.sh, with mocked ip+curl (no real netns).
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
NS="ns-proton-1-s"
mkdir -p "$TMP/bin"

# mock ip: `netns list` reports our NS; `netns exec <ns> <cmd...>` runs <cmd...>
cat > "$TMP/bin/ip" <<IPEOF
#!/usr/bin/env bash
if [ "\$1" = "netns" ] && [ "\$2" = "list" ]; then echo "$NS (id: 0)"; exit 0; fi
if [ "\$1" = "netns" ] && [ "\$2" = "exec" ]; then shift 3; exec "\$@"; fi
exit 0
IPEOF

# mock curl: http_code by URL (204 for generate_204 else 200) and a body.
# The body matters now: the built-in youtube probe asserts the watch page
# contains a playable status, so the mock has to emulate a healthy YouTube or
# every run would fail on that one check. BODY_URL/BODY_TEXT let a test inject
# an arbitrary body for one URL; PAD keeps the payload well past the 4096-byte
# prefix so the test also proves assertions are matched against the FULL body.
cat > "$TMP/bin/curl" <<'CURLEOF'
#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -w|-A|-H|--retry|--retry-delay|--max-time|--connect-timeout) shift 2;;
    -sS|-s|--retry-all-errors) shift;;
    http://*|https://*) url="$1"; shift;;
    *) shift;;
  esac
done
PAD=$(head -c 8000 /dev/zero | tr '\0' 'x')
if [ -n "$out" ]; then
  : > "$out"
  case "$url" in
    *"watch?v="*) printf '%s{"playabilityStatus":{"status":"OK","playableInEmbed":true}}' "$PAD" > "$out";;
  esac
  if [ -n "${BODY_URL:-}" ] && [ "$url" = "${BODY_URL}" ]; then
    printf '%s%s' "$PAD" "${BODY_TEXT:-}" > "$out"
  fi
fi
if [ -n "${BLOCK_URL:-}" ] && [ "$url" = "${BLOCK_URL}" ]; then printf 403; exit 0; fi
case "$url" in *generate_204*) printf 204;; *) printf 200;; esac
CURLEOF
chmod +x "$TMP/bin/ip" "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH" PER_PROBE_TIMEOUT=8

# with a custom mandatory + advisory check
cat > "$TMP/checks.json" <<'JEOF'
{"checks":[{"url":"https://custom-mand.example/","tier":"mandatory"},
           {"url":"https://custom-adv.example/","tier":"advisory"}]}
JEOF
export PROTEUS_CHECKS_FILE="$TMP/checks.json"
OUT=$(bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
assert_eq "$(echo "$OUT" | grep -c 'PASS custom:custom-mand.example')" "1" "custom mandatory merged+passed"
assert_eq "$(echo "$OUT" | grep -c 'PASS custom:custom-adv.example')" "1" "custom advisory merged+passed"

# missing file -> no custom lines, still succeeds on builtins
rm -f "$TMP/checks.json"
OUT2=$(bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
assert_eq "$(echo "$OUT2" | grep -c 'custom:')" "0" "no custom lines when file absent"
assert_eq "$(echo "$OUT2" | grep -c 'VERDICT PASS')" "1" "builtins pass without custom file"

# verdict semantics: a custom MANDATORY site that BLOCKs (403) fails the exit
export BLOCK_URL="https://blocked.example/"
printf '{"checks":[{"url":"%s","tier":"mandatory"}]}\n' "$BLOCK_URL" > "$TMP/checks.json"
export PROTEUS_CHECKS_FILE="$TMP/checks.json"
rc=0; bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" >/dev/null 2>&1 || rc=$?
assert_eq "$rc" "1" "custom mandatory block -> VERDICT FAIL (exit 1)"
# the SAME site as advisory must NOT gate
printf '{"checks":[{"url":"%s","tier":"advisory"}]}\n' "$BLOCK_URL" > "$TMP/checks.json"
rc=0; bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" >/dev/null 2>&1 || rc=$?
assert_eq "$rc" "0" "custom advisory block -> still PASS (exit 0)"
unset BLOCK_URL

# --- body assertions on custom checks ----------------------------------------
export BODY_URL="https://body.example/"
printf '{"checks":[{"url":"%s","tier":"advisory","body":"NEEDLE-PRESENT"}]}\n' "$BODY_URL" > "$TMP/checks.json"

OUT3=$(BODY_TEXT="prefix NEEDLE-PRESENT suffix" bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
assert_eq "$(echo "$OUT3" | grep -c 'PASS custom:body.example')" "1" "body assertion satisfied -> PASS"

OUT4=$(BODY_TEXT="nothing relevant here" bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
assert_eq "$(echo "$OUT4" | grep -c 'ERROR custom:body.example body-missing')" "1" "body assertion unsatisfied -> ERROR"

# The needle sits ~8KB in, well past the 4096-byte prefix used for the challenge
# grep. If assertions were matched against that prefix this would fail.
assert_eq "$(echo "$OUT3" | grep -c 'ERROR custom:body.example')" "0" "assertion matches beyond the 4096-byte prefix"

# a mandatory check whose body assertion fails must sink the exit
printf '{"checks":[{"url":"%s","tier":"mandatory","body":"NEEDLE-PRESENT"}]}\n' "$BODY_URL" > "$TMP/checks.json"
rc=0; BODY_TEXT="nothing relevant here" bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" >/dev/null 2>&1 || rc=$?
assert_eq "$rc" "1" "mandatory body-assertion failure -> VERDICT FAIL"

# a body assertion starting with '-' is a literal pattern, not a grep option
printf '{"checks":[{"url":"%s","tier":"advisory","body":"-dash-literal"}]}\n' "$BODY_URL" > "$TMP/checks.json"
OUT5=$(BODY_TEXT="see -dash-literal here" bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
assert_eq "$(echo "$OUT5" | grep -c 'PASS custom:body.example')" "1" "leading-dash assertion treated as a pattern"

# bot-gating anywhere in the body is a BLOCK, not a soft error
printf '{"checks":[{"url":"%s","tier":"advisory"}]}\n' "$BODY_URL" > "$TMP/checks.json"
OUT6=$(BODY_TEXT="Sign in to confirm you’re not a bot" bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
assert_eq "$(echo "$OUT6" | grep -c 'BLOCK custom:body.example bot-gate')" "1" "bot-gate phrase -> BLOCK (curly apostrophe)"
OUT7=$(BODY_TEXT="sign in to confirm you're not a bot" bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
assert_eq "$(echo "$OUT7" | grep -c 'BLOCK custom:body.example bot-gate')" "1" "bot-gate phrase -> BLOCK (ascii apostrophe)"
unset BODY_URL

# The youtube probe must pin a desktop UA. Rotating UAs break it BOTH ways:
# a mobile UA 302s to m.youtube.com (empty body -> healthy exit fails), and
# m.youtube.com does not bot-gate (-> a gated exit is silently missed).
assert_eq "$(grep -c '\${UAS\[0\]}' "$ROOT/etc/proteus/bin/reputation-probe.sh")" "1" "youtube probe pins a UA"
# 12 runs must give an identical verdict; a rotating UA would vary.
# The probe exits 1 on FAIL by design, so capture with `|| true` — under
# `set -e` + `pipefail` an inline substitution would abort this script instead.
seen=""
for _ in $(seq 12); do
  o=$(BODY_URL="https://www.youtube.com/watch?v=jNQXAC9IVRw" BODY_TEXT="LOGIN_REQUIRED" \
      bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || true
  seen="$seen$(printf '%s' "$o" | grep -c 'ERROR youtube body-missing' || true)"
done
assert_eq "$seen" "111111111111" "youtube verdict is deterministic across runs (no UA flap)"

# the built-in youtube probe must assert playability, not just reachability
assert_eq "$(grep -c 'watch?v=' "$ROOT/etc/proteus/bin/reputation-probe.sh")" "1" "youtube probe uses a watch page"
rc=0; BODY_URL="https://www.youtube.com/watch?v=jNQXAC9IVRw" BODY_TEXT="LOGIN_REQUIRED" \
  bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" >/dev/null 2>&1 || rc=$?
assert_eq "$rc" "1" "unplayable youtube -> VERDICT FAIL (the whole point)"

summary
