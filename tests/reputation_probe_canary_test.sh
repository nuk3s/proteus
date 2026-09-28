#!/usr/bin/env bash
# tests/reputation_probe_canary_test.sh — the built-in Cloudflare canaries in the
# candidate gate: tier routing, SKIP, 1xxx, quarantine demotion, trailer lines.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
NS="ns-proton-1-s"
FIX="$TMP/fix"; mkdir -p "$TMP/bin" "$FIX"
export FIX

cat > "$TMP/bin/ip" <<IPEOF
#!/usr/bin/env bash
if [ "\$1" = "netns" ] && [ "\$2" = "list" ]; then echo "$NS (id: 0)"; exit 0; fi
if [ "\$1" = "netns" ] && [ "\$2" = "exec" ]; then shift 3; exec "\$@"; fi
exit 0
IPEOF
# curl: per-host fixtures under $FIX: <host>.code, <host>.hdr, <host>.body.
# No fixture -> 200, no headers (so not-cloudflare), empty body; the youtube
# watch page always carries a playable status so the built-in gate passes.
cat > "$TMP/bin/curl" <<'CURLEOF'
#!/usr/bin/env bash
out=""; hdr=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -D) hdr="$2"; shift 2;;
    -w|-A|-H|--retry|--retry-delay|--max-time|--connect-timeout) shift 2;;
    --) shift;;
    http://*|https://*) url="$1"; shift;;
    *) shift;;
  esac
done
host=$(printf '%s' "$url" | sed -E 's#^https?://##; s#[/:?].*$##')
code=200; PAD=$(head -c 8000 /dev/zero | tr '\0' 'x')
[ -r "$FIX/$host.code" ] && code=$(cat "$FIX/$host.code")
if [ -n "$hdr" ]; then : > "$hdr"; [ -r "$FIX/$host.hdr" ] && cat "$FIX/$host.hdr" > "$hdr"; fi
if [ -n "$out" ]; then
  : > "$out"
  case "$url" in *"watch?v="*) printf '%s{"playabilityStatus":{"status":"OK"}}' "$PAD" > "$out";; esac
  if [ -r "$FIX/$host.body" ]; then printf '%s' "$PAD" > "$out"; cat "$FIX/$host.body" >> "$out"; fi
fi
case "$url" in *generate_204*) code=204;; esac
printf '%s' "$code"
CURLEOF
chmod +x "$TMP/bin/ip" "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH" PER_PROBE_TIMEOUT=8
export PROTEUS_LEDGER_FILE="$TMP/ledger.jsonl"
export PROTEUS_CANARIES_FILE="$TMP/canaries.json"
export PROTEUS_CHECKS_FILE="$TMP/checks.json"
rm -f "$PROTEUS_CANARIES_FILE" "$PROTEUS_CHECKS_FILE"

fix() { # fix <host> <code> <cf|chal|nocf> [body]
  echo "$2" > "$FIX/$1.code"
  case "$3" in
    cf)   printf 'HTTP/2 %s\r\ncf-ray: 8a1-IAD\r\nserver: cloudflare\r\n\r\n' "$2" > "$FIX/$1.hdr";;
    chal) printf 'HTTP/2 %s\r\ncf-mitigated: challenge\r\ncf-ray: 8a1-IAD\r\nserver: cloudflare\r\n\r\n' "$2" > "$FIX/$1.hdr";;
    nocf) printf 'HTTP/2 %s\r\nserver: nginx\r\n\r\n' "$2" > "$FIX/$1.hdr";;
  esac
  if [ -n "${4:-}" ]; then printf '%s' "$4" > "$FIX/$1.body"; else rm -f "$FIX/$1.body"; fi
}
run() { # run [env=val ...] -> OUT, RC
  RC=0; OUT=$(env "$@" bash "$ROOT/etc/proteus/bin/reputation-probe.sh" "$NS" 2>&1) || RC=$?
}
has() { printf '%s\n' "$OUT" | grep -qF -- "$1" && echo y || echo n; }

echo "default basket, one canary challenged, mandatory tier -> FAIL"
fix discord.com 200 cf; fix www.digitalocean.com 200 cf
fix www.patreon.com 403 chal
run PROTEUS_CF_TIER=mandatory
assert_eq "$RC" "1" "exit 1"
assert_eq "$(has 'BLOCK cf:www.patreon.com cf-challenge')" y "challenge named"
assert_eq "$(has 'PASS cf:discord.com')" y "clean canary passes"
assert_eq "$(has 'CANARY www.patreon.com challenge')" y "CANARY trailer"
assert_eq "$(has 'CANARY discord.com clean')" y "CANARY trailer for a clean one"
assert_eq "$(has 'STANDING 2/3')" y "standing 2 of 3"
assert_eq "$(has 'BASELINE PASS')" y "baseline (non-canary mandatory) still passes"
assert_eq "$(has 'CHECK youtube clean')" y "CHECK trailer for a built-in"
assert_eq "$(has 'CHECK cf:')" n "canaries are not repeated as CHECK lines"

echo "same fixtures, advisory tier -> PASS with advisory blocks"
run PROTEUS_CF_TIER=advisory
assert_eq "$RC" "0" "exit 0 in shadow mode"
assert_eq "$(has 'VERDICT PASS (with advisory blocks')" y "advisory block reported"
assert_eq "$(has 'STANDING 2/3')" y "standing still computed in shadow mode"

echo "the override beats the tier (used by step-down)"
run PROTEUS_CF_TIER=mandatory PROTEUS_CF_TIER_OVERRIDE=advisory
assert_eq "$RC" "0" "override -> advisory"

echo "operator canary file replaces the basket; not-cloudflare is SKIP"
printf '{"canaries":[{"url":"https://canary.invalid/"}]}' > "$PROTEUS_CANARIES_FILE"
fix canary.invalid 200 nocf
run PROTEUS_CF_TIER=mandatory
assert_eq "$RC" "0" "SKIP never fails an exit"
assert_eq "$(has 'SKIP cf:canary.invalid not-cloudflare')" y "SKIP line"
assert_eq "$(has 'SUMMARY mandatory: pass=5 block=0 error=0')" y "SKIP counted nowhere (5 built-in passes)"
assert_eq "$(has 'STANDING 0/0')" y "not-cloudflare is not part of the standard"
assert_eq "$(has 'cf:discord.com')" n "default basket not probed when a file exists"

echo "a 1xxx page is its own class"
fix canary.invalid 403 cf '<title>Access denied</title> error code: 1020'
run PROTEUS_CF_TIER=mandatory
assert_eq "$RC" "1" "1020 fails the exit"
assert_eq "$(has 'BLOCK cf:canary.invalid cf-1020')" y "cf-1020 named"
assert_eq "$(has 'CANARY canary.invalid block-1020')" y "ledger class block-1020"

echo "a canary the ledger shows as site-wide is demoted to advisory"
for i in 1 2 3 4 5 6 7 8; do
  python3 "$ROOT/etc/proteus/bin/ledger.py" append --path "$PROTEUS_LEDGER_FILE" \
    --exit-ip "10.9.9.$i" --entry-ip "10.8.8.$i" --slot proton-1 --source gate --verdict fail \
    --canaries "canary.invalid=challenge" --standing 0 --of 1
done
fix canary.invalid 403 chal
run PROTEUS_CF_TIER=mandatory
assert_eq "$RC" "0" "quarantined canary cannot fail an exit"
assert_eq "$(has 'BLOCK cf:canary.invalid cf-challenge')" y "still probed and reported"
assert_eq "$(has 'CANARY canary.invalid challenge')" y "trailer still reports it (the only way it recovers)"
assert_eq "$(has 'STANDING 0/0')" y "quarantined canary leaves the standard"
rm -f "$PROTEUS_LEDGER_FILE"

echo "a transport failure on a canary is a SKIP, like the live watch treats it"
fix canary.invalid 000 nocf
run PROTEUS_CF_TIER=mandatory
assert_eq "$(has 'SKIP cf:canary.invalid transport-fail')" y "transport -> SKIP"
assert_eq "$RC" "0" "a lost socket is not a verdict about the exit"
assert_eq "$(has 'SUMMARY mandatory: pass=5 block=0 error=0')" y "counted nowhere"
assert_eq "$(has 'CANARY canary.invalid transport')" y "trailer still records what happened"
assert_eq "$(has 'STANDING 0/1')" y "still part of the standard, so standing drops"

echo "custom checks now report Cloudflare reasons and feed BASELINE"
rm -f "$PROTEUS_CANARIES_FILE"; fix www.patreon.com 200 cf
fix blocked.invalid 403 chal
printf '{"checks":[{"url":"https://blocked.invalid/","tier":"mandatory"}]}' > "$PROTEUS_CHECKS_FILE"
run PROTEUS_CF_TIER=mandatory
assert_eq "$RC" "1" "custom mandatory challenge fails"
assert_eq "$(has 'BLOCK custom:blocked.invalid cf-challenge')" y "custom check names the challenge"
assert_eq "$(has 'CHECK custom:blocked.invalid challenge')" y "CHECK trailer for the custom check"
assert_eq "$(has 'BASELINE FAIL')" y "baseline fails when a non-canary mandatory check blocks"
assert_eq "$(has 'STANDING 3/3')" y "canaries all clean"

echo "MIN_MANDATORY_PASS counts canaries alongside the built-ins"
rm -f "$PROTEUS_CHECKS_FILE" "$PROTEUS_CANARIES_FILE"
fix discord.com 200 cf; fix www.digitalocean.com 200 cf; fix www.patreon.com 200 cf
run PROTEUS_CF_TIER=mandatory PROTEUS_REP_MIN_MANDATORY_PASS=8
assert_eq "$RC" "0" "5 built-ins + 3 clean canaries reach a threshold of 8"
assert_eq "$(has 'SUMMARY mandatory: pass=8 block=0 error=0')" y "eight mandatory passes"
run PROTEUS_CF_TIER=mandatory PROTEUS_REP_MIN_MANDATORY_PASS=9
assert_eq "$RC" "1" "one more than the tier can produce -> FAIL"
assert_eq "$(has 'insufficient mandatory passes: 8 < 9')" y "verdict names the shortfall"

echo "a broken ledger tool demotes instead of wedging rotation"
fix www.patreon.com 403 chal
run PROTEUS_CF_TIER=mandatory PROTEUS_LEDGER_PY=/nonexistent/ledger.py
assert_eq "$RC" "0" "no ledger tool -> no canary list, and the gate still passes"
assert_eq "$(has 'STANDING 0/0')" y "no canaries, so an empty standard"
# A ledger.py that still lists canaries but fails every quarantine lookup: the
# canaries are probed, and each one is demoted with a message on stderr.
cat > "$TMP/halfbroken.py" <<PYEOF
import subprocess, sys
if sys.argv[1:2] == ["canaries"]:
    sys.exit(subprocess.call([sys.executable, "$ROOT/etc/proteus/bin/ledger.py"] + sys.argv[1:]))
sys.exit(3)
PYEOF
run PROTEUS_CF_TIER=mandatory PROTEUS_LEDGER_PY="$TMP/halfbroken.py"
assert_eq "$RC" "0" "a failed quarantine lookup cannot fail an exit"
assert_eq "$(has 'quarantine lookup failed for www.patreon.com (rc=3); demoting to advisory')" y \
    "the demotion is announced, not silent"
assert_eq "$(has 'BLOCK cf:www.patreon.com cf-challenge')" y "still probed and reported"
assert_eq "$(has 'STANDING 0/0')" y "every canary demoted -> empty standard"

summary
