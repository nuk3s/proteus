#!/usr/bin/env bash
# tests/ui_apply_test.sh
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/dropin" "$TMP/trigger"
cat > "$TMP/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "$@" >> "${SYSTEMCTL_LOG}"
if [[ "$1" == "restart" && -f "${SYSTEMCTL_FAIL_FLAG:-/nonexistent-flag}" ]]; then
  exit 1
fi
EOF
chmod +x "$TMP/bin/systemctl"
# wireguard-tools stand-in: genkey mints a fresh random key every call, pubkey
# is a hash rather than the real curve operation. That is all pairing needs —
# distinct keys per pairing, and one stable public key per private key — and it
# keeps the suite runnable on a box without wireguard-tools installed.
cat > "$TMP/bin/wg" <<'EOF'
#!/usr/bin/env bash
# Write a call number into WG_FAIL_FROM_FLAG to make every call from that one
# onward fail, so a pairing that dies part-way through can be walked.
if [ -s "${WG_FAIL_FROM_FLAG:-/nonexistent-flag}" ]; then
  n=$(cat "$WG_FAIL_FROM_FLAG")
  c=$(( $(cat "$WG_CALL_COUNT" 2>/dev/null || echo 0) + 1 ))
  echo "$c" > "$WG_CALL_COUNT"
  if [ "$c" -ge "$n" ]; then echo "wg: simulated failure on call $c" >&2; exit 1; fi
fi
case "${1:-}" in
  genkey) python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())';;
  pubkey) python3 -c 'import base64,hashlib,sys
print(base64.b64encode(hashlib.sha256(sys.stdin.buffer.read()).digest()).decode())';;
  *) echo "wg: unexpected args: $*" >&2; exit 1;;
esac
EOF
# The broker asks the kernel for its own management address to fill the
# Endpoint. Pin it, so the pairing assertions do not depend on the addresses of
# whatever machine runs the suite.
#
# IP_FAIL_FLAG reproduces production: the broker's unit sets
# RestrictAddressFamilies=AF_UNIX, AF_NETLINK is denied, and `ip` cannot open a
# netlink socket — it exits 1 with exactly this message. Pairing must still work.
cat > "$TMP/bin/ip" <<'EOF'
#!/usr/bin/env bash
if [ -f "${IP_FAIL_FLAG:-/nonexistent-flag}" ]; then
  echo "Cannot open netlink socket: Address family not supported by protocol" >&2
  exit 1
fi
cat <<'ADDR'
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 172.20.0.119/24 brd 172.20.0.255 scope global eth0\       valid_lft forever preferred_lft forever
ADDR
EOF
chmod +x "$TMP/bin/wg" "$TMP/bin/ip"
# A fixture standing in for /proc/net/fib_trie, so the suite never depends on
# the addresses of whatever machine runs it. Same shape as the real file: the
# box's own address is `host LOCAL`, the subnet broadcast beside it is
# `link BROADCAST`, and Main: (routes) comes before Local: (our addresses).
write_fib_trie() { cat > "$TMP/fib_trie" <<'EOF'
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 172.20.0.0/24 2 0 2
        |-- 172.20.0.0
           /24 link UNICAST
        |-- 172.20.0.1
           /32 link UNICAST
Local:
  +-- 0.0.0.0/0 3 0 5
     +-- 172.20.0.0/24 2 0 2
        |-- 172.20.0.119
           /32 host LOCAL
        |-- 172.20.0.255
           /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.1
           /32 host LOCAL
EOF
}
write_fib_trie
export IP_FAIL_FLAG="$TMP/fail-ip"
cat > "$TMP/proteus.env" <<'EOF'
PROTEUS_MGMT_CIDR=172.20.0.0/24
PROTEUS_CLIENT_VLAN_CIDR=172.16.1.0/24
PROTEUS_UDM_TUNNEL_CIDR=10.99.99.0/30
PROTEUS_UDM_TUNNEL_PORT=51821
PROTEUS_UDM_TUNNEL_MTU=1420
PROTEUS_UDM_DNS=172.20.0.53
EOF
mkdir -p "$TMP/udmkeys"
export SYSTEMCTL_LOG="$TMP/systemctl.log"; touch "$SYSTEMCTL_LOG"
export SYSTEMCTL_FAIL_FLAG="$TMP/fail-restart"
export WG_FAIL_FROM_FLAG="$TMP/fail-wg"; export WG_CALL_COUNT="$TMP/wg-calls"
export PATH="$TMP/bin:$PATH"

SOCK="$TMP/apply.sock"
python3 "$ROOT/etc/proteus/bin/proteus-ui-apply" \
  --test-socket "$SOCK" --env-file "$TMP/local.env" \
  --dropin-dir "$TMP/dropin" --flag-file "$TMP/paused" \
  --trigger-dir "$TMP/trigger" --checks-file "$TMP/checks.json" \
  --canaries-file "$TMP/canaries.json" \
  --trusted-file "$TMP/trusted.json" --proteus-env "$TMP/proteus.env" \
  --fib-trie "$TMP/fib_trie" \
  --udm-key-dir "$TMP/udmkeys" 2> "$TMP/broker.err" &
# Broker logs land in $TMP/broker.err — read it when a case here fails, and note
# that the key-material grep below covers it because it lives under $TMP.
BROKER=$!; sleep 0.3
trap 'kill $BROKER 2>/dev/null; rm -rf "$TMP"' EXIT

req() { printf '%s\n' "$1" | python3 -c '
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read()); print(s.makefile().readline().strip())
' "$SOCK"; }

ok_field() { python3 -c 'import json,sys;print(json.load(sys.stdin)["ok"])'; }

# valid set writes overlay atomically
OUT=$(req '{"cmd":"set","key":"PROTEUS_STREAMING_MIN_MBPS","value":"30"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "set ok"
grep -q '^PROTEUS_STREAMING_MIN_MBPS=30$' "$TMP/local.env" || { echo "FAIL overlay"; exit 1; }

# re-set the same key: overlay is deduped, not appended
req '{"cmd":"set","key":"PROTEUS_STREAMING_MIN_MBPS","value":"40"}' >/dev/null
COUNT=$(grep -c '^PROTEUS_STREAMING_MIN_MBPS=' "$TMP/local.env")
assert_eq "$COUNT" "1" "overlay dedup: one line for the key"
grep -q '^PROTEUS_STREAMING_MIN_MBPS=40$' "$TMP/local.env" || { echo "FAIL dedup value"; exit 1; }

# overlay write is atomic and mode 644, no leftover tmp file
[ -f "$TMP/local.env.tmp" ] && { echo "FAIL: local.env.tmp leftover"; exit 1; }
assert_eq "$(stat -c %a "$TMP/local.env")" "644" "overlay file mode"

# reject: range, unknown key, unknown cmd, bad slot name
for bad in '{"cmd":"set","key":"PROTEUS_STREAMING_MIN_MBPS","value":"9999"}' \
           '{"cmd":"set","key":"EVIL","value":"1"}' \
           '{"cmd":"fork-bomb"}' \
           '{"cmd":"rotate","slot":"proton-1; reboot"}'; do
  OUT=$(req "$bad")
  assert_eq "$(echo "$OUT" | ok_field)" "False" "reject: $bad"
done

# dispatcher knob kicks restart
req '{"cmd":"set","key":"PROTEUS_SPREAD_BAND","value":"60"}' >/dev/null
grep -q 'restart proteus-dispatcher.service' "$SYSTEMCTL_LOG" || { echo "FAIL kick"; exit 1; }

# kick restart failure: overlay already saved, broker reports it honestly (not silently or masked)
touch "$SYSTEMCTL_FAIL_FLAG"
OUT=$(req '{"cmd":"set","key":"PROTEUS_SPREAD_BAND","value":"77"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "kick restart failure reported"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["error"])')" \
  "saved but proteus-dispatcher.service restart failed" "kick restart failure: honest error text"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["saved"])')" \
  "True" "kick restart failure: saved flag set"
grep -q '^PROTEUS_SPREAD_BAND=77$' "$TMP/local.env" || { echo "FAIL: value not saved despite restart failure"; exit 1; }
rm -f "$SYSTEMCTL_FAIL_FLAG"

# restart-dispatcher command
req '{"cmd":"restart-dispatcher"}' >/dev/null
grep -q 'restart proteus-dispatcher.service' "$SYSTEMCTL_LOG" || { echo "FAIL restart-dispatcher"; exit 1; }

# rotate writes trigger file then starts unit
req '{"cmd":"rotate","slot":"proton-2"}' >/dev/null
assert_eq "$(cat "$TMP/trigger/proton-2")" "manual" "trigger file"
grep -q 'start --no-block proteus-rotate-slot@proton-2.service' "$SYSTEMCTL_LOG" || { echo "FAIL rotate"; exit 1; }

# dns slots are out of v1 scope for manual rotation — no proteus-rotate-slot@ unit exists for them
OUT=$(req '{"cmd":"rotate","slot":"dns-6"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "dns rotate rejected"

# pause/resume flag file
req '{"cmd":"pause"}' >/dev/null;  [ -f "$TMP/paused" ] || { echo "FAIL pause"; exit 1; }
req '{"cmd":"resume"}' >/dev/null; [ ! -f "$TMP/paused" ] || { echo "FAIL resume"; exit 1; }

# cadence drop-in
req '{"cmd":"set-cadence","on_calendar":"daily","randomized_delay":"6h"}' >/dev/null
grep -q 'RandomizedDelaySec=6h' "$TMP/dropin/override.conf" || { echo "FAIL dropin"; exit 1; }
grep -q 'daemon-reload' "$SYSTEMCTL_LOG" || { echo "FAIL reload"; exit 1; }

# cadence flag-injection: a leading-dash value must not be parsed as a systemd-analyze option
OUT=$(req '{"cmd":"set-cadence","on_calendar":"-h","randomized_delay":"6h"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "cadence -h not treated as a flag"
OUT=$(req '{"cmd":"set-cadence","on_calendar":"daily","randomized_delay":"-h"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "cadence delay -h rejected"

# non-dict JSON: valid JSON but not an object — must not crash, must report ok:false
for j in '[]' '123'; do
  OUT=$(req "$j")
  assert_eq "$(echo "$OUT" | ok_field)" "False" "non-dict JSON rejected: $j"
done

# malformed/binary input must not crash the broker (regression for the readline-outside-try bug)
printf '\xff\xfe\x00garbage\n' | python3 -c '
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read())
try:
    s.makefile().readline()
except Exception:
    pass
' "$SOCK"
sleep 0.2
kill -0 "$BROKER" 2>/dev/null || { echo "FAIL: broker died on binary input"; exit 1; }
OUT=$(req '{"cmd":"pause"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "broker still serving after binary input"
req '{"cmd":"resume"}' >/dev/null

# set-checks: valid list writes checks.json (640), atomic, correct content
OUT=$(req '{"cmd":"set-checks","checks":[{"url":"https://www.example.com/","tier":"advisory"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "set-checks valid ok"
[ -f "$TMP/checks.json" ] || { echo "FAIL: checks.json not written"; exit 1; }
grep -q 'www.example.com' "$TMP/checks.json" || { echo "FAIL: checks.json content"; exit 1; }
[ ! -f "$TMP/checks.json.tmp" ] || { echo "FAIL: leftover checks tmp"; exit 1; }
assert_eq "$(stat -c '%a' "$TMP/checks.json")" "640" "checks.json mode 640"
# set-checks rejects a bad scheme and a non-list
for bad in '{"cmd":"set-checks","checks":[{"url":"ftp://x/","tier":"advisory"}]}' \
           '{"cmd":"set-checks","checks":"nope"}'; do
  OUT=$(req "$bad")
  assert_eq "$(echo "$OUT" | ok_field)" "False" "set-checks reject: $bad"
done

# set-canaries: valid list writes canaries.json; http:// is rejected
OUT=$(req '{"cmd":"set-canaries","canaries":[{"url":"https://a.invalid/"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "set-canaries valid ok"
assert_eq "$(grep -c 'https://a.invalid/' "$TMP/canaries.json")" "1" "canaries.json written"
assert_eq "$(stat -c '%a' "$TMP/canaries.json")" "640" "canaries.json mode 640"
OUT=$(req '{"cmd":"set-canaries","canaries":[{"url":"http://a.invalid/"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "set-canaries rejects http"
# the basket is capped at MAX_CANARIES=8: exactly 8 is accepted, 9 is rejected
mkcanaries() { python3 -c 'import json,sys
n=int(sys.argv[1])
print(json.dumps({"cmd":"set-canaries",
                  "canaries":[{"url":"https://c%d.invalid/" % i} for i in range(n)]}))' "$1"; }
OUT=$(req "$(mkcanaries 8)")
assert_eq "$(echo "$OUT" | ok_field)" "True" "set-canaries accepts 8"
assert_eq "$(grep -c 'https://c7.invalid/' "$TMP/canaries.json")" "1" "8-canary list written"
OUT=$(req "$(mkcanaries 9)")
assert_eq "$(echo "$OUT" | ok_field)" "False" "set-canaries rejects 9"

# --- set-trusted -------------------------------------------------------------
OUT=$(req '{"cmd":"set-trusted","trusted":[{"cidr":"192.168.7.0/24"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "set-trusted valid ok"
assert_eq "$(grep -c '192.168.7.0/24' "$TMP/trusted.json")" "1" "trusted.json written"
assert_eq "$(stat -c '%a' "$TMP/trusted.json")" "640" "trusted.json is group-readable, not world"
# Same mode and ownership as the other broker-written lists, whoever runs this.
assert_eq "$(stat -c '%a %U:%G' "$TMP/trusted.json")" "$(stat -c '%a %U:%G' "$TMP/canaries.json")" \
  "trusted.json matches canaries.json mode and ownership"
[ ! -f "$TMP/trusted.json.tmp" ] || { echo "FAIL: leftover trusted tmp"; exit 1; }
grep -q 'restart proteus-trusted-egress.service' "$SYSTEMCTL_LOG" || { echo "FAIL: no reconcile kick"; exit 1; }

OUT=$(req '{"cmd":"set-trusted","trusted":[{"cidr":"172.20.0.0/24"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "the management subnet is refused"
assert_eq "$(grep -c '172.20.0.0/24' "$TMP/trusted.json")" "0" "and nothing was written"

OUT=$(req '{"cmd":"set-trusted","trusted":[{"cidr":"172.20.0.150/32"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "one infra host is allowed"

# 203.0.113.0/24 is an RFC 5737 documentation range (not RFC 1918), so it's
# both a real "public range" for validate() to refuse and safe for the
# public mirror.
OUT=$(req '{"cmd":"set-trusted","trusted":[{"cidr":"203.0.113.0/24"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "a public range is refused"

OUT=$(req '{"cmd":"set-trusted","trusted":[]}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "an empty list is valid and means off"

# A reconcile that will not restart is reported, not swallowed: the list is on
# disk but the data path still reflects the old one.
touch "$SYSTEMCTL_FAIL_FLAG"
OUT=$(req '{"cmd":"set-trusted","trusted":[{"cidr":"192.168.9.0/24"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "a failed reconcile kick is reported"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["error"])')" \
  "saved but proteus-trusted-egress restart failed" "failed kick: honest error text"
assert_eq "$(grep -c '192.168.9.0/24' "$TMP/trusted.json")" "1" "failed kick: the list is still saved"
rm -f "$SYSTEMCTL_FAIL_FLAG"

# --- the overlay wins over the base config, as it does for every script -------
# The UI writes knob changes to proteus-local.env, and the reconcile script and
# the dispatcher both source proteus.env and then that overlay. A broker reading
# only the base file would validate trusted ranges against a management subnet
# nothing else uses any more — accepting a list the data path's identical guard
# then refuses, while the UI goes on reporting the feature as on.
cat >> "$TMP/local.env" <<'EOF'
PROTEUS_MGMT_CIDR=192.168.7.0/24
PROTEUS_UDM_TUNNEL_MTU=1380
EOF
OUT=$(req '{"cmd":"set-trusted","trusted":[{"cidr":"192.168.7.0/24"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "False" \
  "the guard uses the overlay's management subnet, so that range is refused"
OUT=$(req '{"cmd":"set-trusted","trusted":[{"cidr":"172.20.0.0/24"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "True" \
  "and the base file's subnet, now overridden, is just another private range"
# Pairing reads the same way: with no address inside the overlay's subnet there
# is no endpoint to hand the UDM.
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "pairing follows the overlay too"
echo "$OUT" | grep -q '192.168.7.0/24' && r=ok || r=fail
assert_eq "$r" ok "and the error quotes the overlay's value, not the base file's"

sed -i '/^PROTEUS_MGMT_CIDR=/d' "$TMP/local.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "pairing works again once the overlay is back in range"
echo "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config",""))' \
  | grep -qF 'MTU = 1380' && r=ok || r=fail
assert_eq "$r" ok "the rendered config carries the overlay's MTU, not the base file's"
sed -i '/^PROTEUS_UDM_TUNNEL_MTU=/d' "$TMP/local.env"

# --- udm-peer ----------------------------------------------------------------
: > "$SYSTEMCTL_LOG"   # from here on, every restart in the log is pairing's
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "pairing succeeds"
CFG=$(echo "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config",""))')
for want in '[Interface]' '[Peer]' 'Address = 10.99.99.2/30' 'DNS = 172.20.0.53' \
            'MTU = 1420' 'AllowedIPs = 0.0.0.0/0'; do
  printf '%s' "$CFG" | grep -qF -- "$want" && r=ok || r=fail
  assert_eq "$r" ok "config contains $want"
done
printf '%s' "$CFG" | grep -qE '^Endpoint = [0-9.]+:51821$' && r=ok || r=fail
assert_eq "$r" ok "config points at this box on the tunnel port"

assert_eq "$(ls "$TMP/udmkeys" | grep -c 'peer.pub')" "1" "the UDM public key is recorded"
assert_eq "$(ls "$TMP/udmkeys" | grep -c 'server.key')" "1" "our own key is kept"
assert_eq "$(stat -c '%a' "$TMP/udmkeys/server.key")" "600" "our private key is owner-only"
# Recording a peer changes nothing until the interface is reconciled: without
# this the pasted config would not connect and the key it replaced would stay
# live, so re-pairing would not actually revoke.
assert_eq "$(grep -c 'restart proteus-trusted-egress.service' "$SYSTEMCTL_LOG")" "1" \
    "pairing reconciles the interface"
# The UDM private key is the one secret this feature must never persist — not in
# the key directory, not in a stray temp file, not in the broker's log.
UDM_PRIV=$(printf '%s' "$CFG" | sed -n 's/^PrivateKey = //p')
assert_eq "$(grep -rlF "$UDM_PRIV" "$TMP" 2>/dev/null | wc -l)" "0" \
    "the UDM private key is never written to disk"

PEER1=$(cat "$TMP/udmkeys/peer.pub"); SRV1=$(cat "$TMP/udmkeys/server.key")
OUT2=$(req '{"cmd":"udm-peer"}')
CFG2=$(echo "$OUT2" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config",""))')
UDM_PRIV2=$(printf '%s' "$CFG2" | sed -n 's/^PrivateKey = //p')
[ "$UDM_PRIV" != "$UDM_PRIV2" ] && r=ok || r=fail
assert_eq "$r" ok "re-pairing issues a new UDM key"
[ "$PEER1" != "$(cat "$TMP/udmkeys/peer.pub")" ] && r=ok || r=fail
assert_eq "$r" ok "and replaces the recorded peer, invalidating the old one"
assert_eq "$(cat "$TMP/udmkeys/server.key")" "$SRV1" "our own identity is stable across pairings"

# --- the production condition: `ip` cannot run at all -------------------------
# The broker's unit sets RestrictAddressFamilies=AF_UNIX, which denies AF_NETLINK,
# so `ip` cannot open its socket and exits 1 — this is the bug that broke pairing
# on the live gateway. The address has to come from /proc/net/fib_trie, a plain
# file read the sandbox allows, and it must be the `host LOCAL` entry rather than
# the `link BROADCAST` one sitting one line below it in the same subnet.
touch "$IP_FAIL_FLAG"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "pairing succeeds when ip cannot open a netlink socket"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["endpoint"])')" \
  "172.20.0.119:51821" "the endpoint is our own address, not the subnet broadcast"

# Neither source yields an address: the operator must be told which setting to
# fix. The fallback dying is not the cause and must not be reported as one —
# `Command '['ip', ...]' returned non-zero exit status 1` is precisely the
# useless message this bug produced in production.
mv "$TMP/fib_trie" "$TMP/fib_trie.away"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "with neither source, pairing fails"
echo "$OUT" | grep -q 'PROTEUS_MGMT_CIDR' && r=ok || r=fail
assert_eq "$r" ok "and the error names PROTEUS_MGMT_CIDR"
echo "$OUT" | grep -q '172.20.0.0/24' && r=ok || r=fail
assert_eq "$r" ok "and quotes the value in force"
echo "$OUT" | grep -q 'non-zero exit status' && r=fail || r=ok
assert_eq "$r" ok "and does not mask it with the fallback's own failure"

# With procfs unreadable but `ip` working, the fallback still answers.
rm -f "$IP_FAIL_FLAG"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "an unreadable fib_trie falls back to ip"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["endpoint"])')" \
  "172.20.0.119:51821" "and the fallback yields the same endpoint"
mv "$TMP/fib_trie.away" "$TMP/fib_trie"

# A reconcile that will not restart must not cost the operator the pairing: the
# config is still returned, and the reply says it is recorded but not yet live.
touch "$SYSTEMCTL_FAIL_FLAG"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "a pairing whose reconcile fails is reported"
echo "$OUT" | grep -q 'not live' && r=ok || r=fail
assert_eq "$r" ok "and the error says the key is recorded but not live"
CFG3=$(echo "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config",""))')
printf '%s' "$CFG3" | grep -qF '[Interface]' && r=ok || r=fail
assert_eq "$r" ok "and the configuration still comes back"
rm -f "$SYSTEMCTL_FAIL_FLAG"

# A pairing that dies part-way through key generation leaves nothing behind:
# the recorded peer is untouched and no half-written temp file survives.
PEER3=$(cat "$TMP/udmkeys/peer.pub")
: > "$WG_CALL_COUNT"; echo 2 > "$WG_FAIL_FROM_FLAG"
OUT=$(req '{"cmd":"udm-peer"}')
rm -f "$WG_FAIL_FROM_FLAG"
assert_eq "$(echo "$OUT" | ok_field)" "False" "a pairing that dies mid-mint is reported"
assert_eq "$(cat "$TMP/udmkeys/peer.pub")" "$PEER3" "the recorded peer is byte-identical"
assert_eq "$(find "$TMP/udmkeys" -name '*.tmp' | wc -l)" "0" "no half-written temp file is left"

# A pairing that cannot be rendered must leave the working one alone: revoking
# the recorded peer in exchange for a config the operator never received would
# take the tunnel down over a configuration mistake.
PEER2=$(cat "$TMP/udmkeys/peer.pub")
cp "$TMP/proteus.env" "$TMP/proteus.env.good"
# Keep the DNS knob set: this case is about the management CIDR, and pairing
# checks the knobs in order, so dropping it would have the error name that one.
printf 'PROTEUS_MGMT_CIDR=not-a-cidr\nPROTEUS_UDM_DNS=172.20.0.53\n' > "$TMP/proteus.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "pairing fails when the management CIDR is unusable"
echo "$OUT" | grep -q 'PROTEUS_MGMT_CIDR' && r=ok || r=fail
assert_eq "$r" ok "and the error names the setting to fix"
assert_eq "$(cat "$TMP/udmkeys/peer.pub")" "$PEER2" "the existing peer survives a failed pairing"

# Same for a setting the renderer cannot use: name it, do not leak int()'s wording.
cp "$TMP/proteus.env.good" "$TMP/proteus.env"
printf 'PROTEUS_UDM_TUNNEL_MTU=wide\n' >> "$TMP/proteus.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "a non-numeric MTU fails the pairing"
echo "$OUT" | grep -q 'PROTEUS_UDM_TUNNEL_MTU' && r=ok || r=fail
assert_eq "$r" ok "and the error names the setting to fix"
mv "$TMP/proteus.env.good" "$TMP/proteus.env"

# --- PROTEUS_UDM_DNS: the DNS line UniFi will not accept a config without -----
# UniFi refuses a VPN Client whose [Interface] has no DNS ("Invalid DNS in
# [Interface]. Use: DNS = IP Address"), and it refuses it AFTER the operator has
# pasted in a private key this gateway never stored and cannot reissue. So an
# unset knob has to stop the pairing here, naming the knob and where to set it.
PEER_DNS=$(cat "$TMP/udmkeys/peer.pub")
cp "$TMP/proteus.env" "$TMP/proteus.env.good"
sed -i '/^PROTEUS_UDM_DNS=/d' "$TMP/proteus.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "an unset PROTEUS_UDM_DNS fails the pairing"
for want in 'PROTEUS_UDM_DNS' 'LAN resolver' 'UDM tunnel (trusted-VLAN egress)' \
            'DNS server for trusted hosts'; do
  echo "$OUT" | grep -qF -- "$want" && r=ok || r=fail
  assert_eq "$r" ok "the error says: $want"
done
assert_eq "$(cat "$TMP/udmkeys/peer.pub")" "$PEER_DNS" "and the working peer survives"

# An empty value is the same failure as no line at all — an operator who cleared
# the field must not get a config with a bare "DNS = " that UniFi then rejects.
printf 'PROTEUS_UDM_DNS=\n' >> "$TMP/proteus.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "an empty PROTEUS_UDM_DNS fails the pairing"

# A hostname is exactly what UniFi's validator rejects; catch it before it ships.
sed -i '/^PROTEUS_UDM_DNS=/d' "$TMP/proteus.env"
printf 'PROTEUS_UDM_DNS=resolver.internal\n' >> "$TMP/proteus.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "a hostname fails the pairing"
echo "$OUT" | grep -qF -- 'PROTEUS_UDM_DNS' && r=ok || r=fail
assert_eq "$r" ok "and the error names the knob"
echo "$OUT" | grep -qF -- 'resolver.internal' && r=ok || r=fail
assert_eq "$r" ok "and quotes the value it would not take"

# A LAN resolver address pairs, and the rendered config carries exactly one DNS
# line, inside [Interface].
mv "$TMP/proteus.env.good" "$TMP/proteus.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "a LAN resolver IP pairs"
CFGD=$(echo "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config",""))')
printf '%s\n' "$CFGD" | grep -qF -- 'DNS = 172.20.0.53' && r=ok || r=fail
assert_eq "$r" ok "the config carries the DNS line"
assert_eq "$(printf '%s\n' "$CFGD" | grep -c '^DNS = ')" "1" "exactly one DNS line"
assert_eq "$(printf '%s\n' "$CFGD" | sed -n '/^\[Peer\]/,$p' | grep -c '^DNS')" "0" \
  "and it is in [Interface], not [Peer]"

# Two resolvers: WireGuard takes a comma-separated list, and the overlay wins
# over the base file here as it does for every other knob.
printf 'PROTEUS_UDM_DNS=172.20.0.53,172.20.0.54\n' >> "$TMP/local.env"
OUT=$(req '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "a comma-separated pair pairs"
CFGD=$(echo "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config",""))')
printf '%s\n' "$CFGD" | grep -qF -- 'DNS = 172.20.0.53, 172.20.0.54' && r=ok || r=fail
assert_eq "$r" ok "and the list is rendered normalised"
sed -i '/^PROTEUS_UDM_DNS=/d' "$TMP/local.env"

# The same value through the knob path the UI uses, so the panel can never save
# one that the pairing then refuses.
OUT=$(req '{"cmd":"set","key":"PROTEUS_UDM_DNS","value":"172.20.0.53,172.20.0.54"}')
assert_eq "$(echo "$OUT" | ok_field)" "True" "the UI can save a DNS list"
grep -q '^PROTEUS_UDM_DNS=172.20.0.53,172.20.0.54$' "$TMP/local.env" || {
  echo "FAIL: DNS knob not written to the overlay"; exit 1; }
OUT=$(req '{"cmd":"set","key":"PROTEUS_UDM_DNS","value":"resolver.internal"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "the UI refuses a hostname"
# A space would be inert in the config but not in the overlay, which every
# script on the box SOURCES: "KEY=a b" runs `b`.
OUT=$(req '{"cmd":"set","key":"PROTEUS_UDM_DNS","value":"172.20.0.53, 172.20.0.54"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "and a value with a space in it"
sed -i '/^PROTEUS_UDM_DNS=/d' "$TMP/local.env"

# --- a systemctl that is not on PATH at all -----------------------------------
# That exec raises FileNotFoundError, an OSError rather than a CalledProcessError,
# so a kick guard that names only the subprocess errors lets it escape to the
# generic handler. For pairing that is the expensive shape of the bug: peer.pub
# has already been replaced, and the config the operator can no longer regenerate
# identically is discarded with it. Both kicks must report a failed kick instead.
mkdir -p "$TMP/nosysctl" "$TMP/udmkeys2"
for prog in bash cat python3; do ln -sf "$(command -v "$prog")" "$TMP/nosysctl/$prog"; done
ln -sf "$TMP/bin/wg" "$TMP/nosysctl/wg"; ln -sf "$TMP/bin/ip" "$TMP/nosysctl/ip"
# Belt and braces: this case must never be able to reach a real systemctl.
[ -z "$(PATH="$TMP/nosysctl" command -v systemctl || true)" ] || {
  echo "FAIL: systemctl is still reachable on the stripped PATH"; exit 1; }

SOCK2="$TMP/apply2.sock"
PATH="$TMP/nosysctl" python3 "$ROOT/etc/proteus/bin/proteus-ui-apply" \
  --test-socket "$SOCK2" --env-file "$TMP/local2.env" \
  --dropin-dir "$TMP/dropin" --flag-file "$TMP/paused2" \
  --trigger-dir "$TMP/trigger" --checks-file "$TMP/checks2.json" \
  --canaries-file "$TMP/canaries2.json" \
  --trusted-file "$TMP/trusted2.json" --proteus-env "$TMP/proteus.env" \
  --fib-trie "$TMP/fib_trie" \
  --udm-key-dir "$TMP/udmkeys2" 2> "$TMP/broker2.err" &
BROKER2=$!; sleep 0.3
trap 'kill $BROKER $BROKER2 2>/dev/null; rm -rf "$TMP"' EXIT

req2() { printf '%s\n' "$1" | python3 -c '
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read()); print(s.makefile().readline().strip())
' "$SOCK2"; }

OUT=$(req2 '{"cmd":"set-trusted","trusted":[{"cidr":"192.168.8.0/24"}]}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "set-trusted: a missing systemctl is a failed kick"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["error"])')" \
  "saved but proteus-trusted-egress restart failed" \
  "missing systemctl: honest error text, not an exception name"
assert_eq "$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["saved"])')" \
  "True" "missing systemctl: saved flag set"
assert_eq "$(grep -c '192.168.8.0/24' "$TMP/trusted2.json")" "1" \
  "missing systemctl: the list is still saved"

OUT=$(req2 '{"cmd":"udm-peer"}')
assert_eq "$(echo "$OUT" | ok_field)" "False" "pairing: a missing systemctl is reported"
echo "$OUT" | grep -q 'not live' && r=ok || r=fail
assert_eq "$r" ok "pairing: the error still says the key is recorded but not live"
CFG4=$(echo "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config",""))')
printf '%s' "$CFG4" | grep -qF '[Interface]' && r=ok || r=fail
assert_eq "$r" ok "pairing: the config the operator cannot regenerate still comes back"
assert_eq "$(ls "$TMP/udmkeys2" | grep -c 'peer.pub')" "1" "pairing: the peer was recorded even so"

summary
