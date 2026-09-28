#!/usr/bin/env bash
# tests/sysctl_hardening_test.sh
#
# etc/sysctl.d/90-proxy-hardening.conf holds the kernel settings the routing
# depends on (the installer copies and loads it; systemd-sysctl loads it at
# boot). Three of them are load-bearing:
#   - ip_forward=1: the box is a router.
#   - rp_filter 0 or 2, never 1. A tunnel's reply to a client is validated by
#     a lookup made as if it had arrived on the client interface, which ends in
#     routeguard.sh's ingress sink, not on the slot veth it came in on. Strict
#     mode drops every tunnel reply. The kernel uses the higher of conf.all and
#     the interface's own value, so all=2 keeps every interface loose.
#   - net.ipv6.conf.all.forwarding=0: the routing guards are IPv4-only, so with
#     no ruleset loaded this is what keeps client IPv6 from being routed.
# Plus tcp_fwmark_accept=0: a client's TCP DNS query reaches unbound marked
# (the flow is dispatched before the redirect), and with 1 unbound's socket
# would take the mark and answer into the slot tunnel.
# Also pinned: no net.netfilter.* key (boot can skip one), IPv6 redirects off on
# NICs that exist before the load, comments that name every sysctl.d file the
# installer rewrites, and the end-to-end sim loading this file.
# The content pins run everywhere; the behaviour half loads the real file into
# a private network namespace, with sysctl -p (the installer) and with
# systemd-sysctl (boot), and needs unprivileged user namespaces.
# The installer side is install/tests/apply_sysctl_test.sh.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
F="$ROOT/etc/sysctl.d/90-proxy-hardening.conf"
RG="$ROOT/etc/proteus/bin/routeguard.sh"
APPLY="$ROOT/install/lib/apply.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# key=value per key, in first-seen order, with the value the file leaves it at
# (sysctl applies assignments in order, so the last one wins). sysctl.d syntax:
# comments start with # or ;, keys may use / for ., spaces around = are
# allowed, and systemd reads a leading - as "ignore failure".
kv() {
    [[ -r "$1" ]] || return 0
    awk '
        { sub(/^[ \t]+/, "") }
        /^([#;]|$)/ { next }
        { i = index($0, "="); if (!i) next
          k = substr($0, 1, i - 1); v = substr($0, i + 1)
          sub(/^-/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v)
          gsub("/", ".", k)
          if (!(k in val)) order[++n] = k
          val[k] = v }
        END { for (j = 1; j <= n; j++) print order[j] "=" val[order[j]] }' "$1"
}
val() { kv "$F" | awk -F= -v k="$1" '$1 == k { print substr($0, length(k) + 2) }'; }
userns_ok() { command -v unshare >/dev/null 2>&1 && unshare -rn true 2>/dev/null; }

# ---------------------------------------------------------------------------
echo "the file: the values the routing depends on"
assert_eq "$([[ -f "$F" ]] && echo present || echo missing)" present "etc/sysctl.d/90-proxy-hardening.conf is tracked"
assert_eq "$(val net.ipv4.ip_forward)" "1" "ip_forward=1"
assert_eq "$(val net.ipv4.conf.all.rp_filter)" "2" \
    "conf.all.rp_filter=2 (the highest value, so no interface's own 1 can make it strict)"
assert_eq "$(val net.ipv4.conf.default.rp_filter)" "2" "conf.default.rp_filter=2"
bad_rpf=$(kv "$F" | awk -F= '$1 ~ /^net\.ipv4\.conf\.[^.]+\.rp_filter$/ && $2 != "0" && $2 != "2"')
assert_eq "$bad_rpf" "" "no rp_filter key anywhere in the file is anything but 0 or 2"
assert_eq "$(val net.ipv6.conf.all.forwarding)" "0" "net.ipv6.conf.all.forwarding=0"
bad_v6=$(kv "$F" | awk -F= '$1 ~ /^net\.ipv6\.conf\.[^.]+\.forwarding$/ && $2 != "0"')
assert_eq "$bad_v6" "" "no key turns IPv6 forwarding on for any interface"
assert_eq "$(val net.ipv4.tcp_fwmark_accept)" "0" "tcp_fwmark_accept=0 (accepted sockets stay unmarked)"
assert_eq "$(kv "$F" | awk -F= '$1 ~ /^net\.netfilter\./')" "" \
    "no net.netfilter.* key (boot can skip one before nf_conntrack loads, while the installer's load sets it)"
assert_eq "$(val 'net.ipv6.conf.*.accept_redirects')" "0" \
    "IPv6 redirects off by glob, for the NICs that exist before the file loads"

echo "where a comment names the sysctl.d files the installer rewrites, it names all of them"
# Put a local setting in one of them and the next install drops it.
written=(99-proteus.conf)
for f in "$ROOT"/etc/sysctl.d/*.conf; do written+=("$(basename "$f")"); done
n_claims=0; missing=""
while IFS= read -r path; do
    # Comment text joined into one line; a claim runs to the end of its
    # sentence (a dot not followed by a letter or digit).
    while IFS= read -r claim; do
        n_claims=$((n_claims + 1))
        for w in "${written[@]}"; do
            [[ "$claim" == *"$w"* ]] || missing+="${path#"$ROOT"/}: '$claim' leaves out $w; "
        done
    done < <(sed 's/^[[:space:]]*#*[[:space:]]*//' "$path" | tr '\n' ' ' \
             | grep -oE 'installer rewrites [^ ]+\.conf([^.]|\.[A-Za-z0-9])*' || true)
done < <(grep -rlE 'installer rewrites [^ ]+\.conf' "$ROOT/etc" "$ROOT/install" "$ROOT"/*.md 2>/dev/null || true)
assert_eq "$missing" "" "every such sentence names ${written[*]}"
assert_eq "$([[ $n_claims -ge 2 ]] && echo yes || echo "no ($n_claims)")" yes \
    "(the ruleset and its installer template still say it, so the check has something to read)"

echo "the end-to-end sim (tests/rebuild_leak_sim.sh) runs with this file"
LS="$ROOT/tests/rebuild_leak_sim.sh"
assert_eq "$(grep -cF 'etc/sysctl.d/90-proxy-hardening.conf' "$LS" || true)" "2" \
    "it copies the file from the tree under test (this checkout's for a tree without one)"
assert_eq "$(grep -cE '^sysctl -q -p "\$SIM/sysctl-90\.conf"' "$LS" || true)" "1" "... and loads it in the gateway's namespace"
assert_eq "$(grep -E '^[[:space:]]*sysctl ' "$LS" | grep -c 'rp_filter' || true)" "0" \
    "... and sets no rp_filter of its own, so the file's value is the one exercised"

echo "the file agrees with the 99-proteus.conf the installer writes"
# 99 loads after 90 and wins at boot, so a key both set with different values
# would make this file say something the box does not do.
s99=$(sed -n "s|.*/etc/sysctl\.d/99-proteus\.conf <<< \$'\([^']*\)'.*|\1|p" "$APPLY")
assert_eq "$([[ -n "$s99" ]] && echo found || echo missing)" found "apply_network's 99-proteus.conf content is where this test looks"
printf '%b\n' "$s99" > "$WORK/99.conf"
clash=$(join -t= <(kv "$F" | sort -t= -k1,1) <(kv "$WORK/99.conf" | sort -t= -k1,1) | awk -F= '$2 != $3')
assert_eq "$clash" "" "no key set to different values in 90-proxy-hardening.conf and 99-proteus.conf"
assert_eq "$(kv "$WORK/99.conf" | awk -F= '$1 == "net.ipv4.fwmark_reflect" { print $2 }')" "0" \
    "(99-proteus.conf still pins fwmark_reflect=0, so the check above has something to compare)"

# ---------------------------------------------------------------------------
echo "behaviour: the real file loaded into a private network namespace"
if command -v ip >/dev/null 2>&1 && command -v sysctl >/dev/null 2>&1 && userns_ok; then
  cat > "$WORK/accept_mark.py" <<'EOS'
# Mark of an accepted TCP socket, for a SYN that carried mark 0x5 (as a
# dispatched client's query to unbound does).
import socket
SO_MARK = 36
ls = socket.socket()
ls.bind(("127.0.0.1", 0)); ls.listen(1)
c = socket.socket()
c.setsockopt(socket.SOL_SOCKET, SO_MARK, 0x5)
c.connect(ls.getsockname())
a, _ = ls.accept()
print(hex(a.getsockopt(socket.SOL_SOCKET, SO_MARK)))
EOS
  cat > "$WORK/netns.sh" <<'EOS'
set -u
F=$1; RG=$2; PY=$3
. "$RG"
ip link set lo up
ip link add up0 type dummy; ip addr add 192.0.2.1/24 dev up0; ip link set up0 up
ip route add default via 192.0.2.254 dev up0
ip link add v0 type dummy; ip addr add 198.51.100.1/30 dev v0; ip link set v0 up
ip link add cl0 type dummy; ip addr add 172.16.1.5/24 dev cl0; ip link set cl0 up
# The interfaces exist before the file loads, as a box's NICs usually do at
# boot, and something has turned IPv6 forwarding on.
sysctl -q -w net.ipv6.conf.all.forwarding=1
echo "load_errors=$(sysctl -q -p "$F" 2>&1 >/dev/null | tr '\n' ' ')"
echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"
echo "v6fwd_cl0=$(cat /proc/sys/net/ipv6/conf/cl0/forwarding)"
echo "v6redir_cl0=$(cat /proc/sys/net/ipv6/conf/cl0/accept_redirects)"
ip link add late0 type dummy
echo "v6redir_late0=$(cat /proc/sys/net/ipv6/conf/late0/accept_redirects)"
PROTEUS_CLIENT_IFACE=cl0 rg_sink_ensure >/dev/null 2>&1
# A slot's reply to a client: in on the slot veth, from a public address.
reply() { ip route get 172.16.1.50 from 203.0.113.9 iif v0 2>&1 | head -1; }
echo "reply=$(reply)"
sysctl -q -w net.ipv4.conf.v0.rp_filter=1
echo "reply_v0_strict=$(reply)"
sysctl -q -w net.ipv4.conf.all.rp_filter=0
echo "reply_strict=$(reply)"
sysctl -q -w net.ipv4.conf.v0.rp_filter=0
echo "reply_off=$(reply)"
echo "accept_mark=$(python3 "$PY" 2>&1)"
sysctl -q -w net.ipv4.tcp_fwmark_accept=1
echo "accept_mark_on=$(python3 "$PY" 2>&1)"
EOS
  OUT=$(unshare -rn bash "$WORK/netns.sh" "$F" "$RG" "$WORK/accept_mark.py" 2>&1 || true)
  get() { sed -n "s/^$1=//p" <<<"$OUT" | head -1; }
  assert_eq "$(get load_errors)" "" "sysctl -p applies every key of the file"
  assert_eq "$(get ip_forward)" "1" "loaded: forwarding on"
  assert_eq "$(get v6fwd_cl0)" "0" "loaded: IPv6 forwarding off on an interface that existed before the load"
  assert_eq "$(get v6redir_cl0)/$(get v6redir_late0)" "0/0" \
    "loaded: IPv6 redirects off on an interface that existed before the load, and on one added after"
  assert_eq "$(get reply | grep -cF 'dev cl0' || true)" "1" \
    "with the file's rp_filter and routeguard's sink, a tunnel reply to a client passes"
  assert_eq "$(get reply_v0_strict | grep -cF 'dev cl0' || true)" "1" \
    "... and still passes with the slot veth's own rp_filter at 1 (conf.all=2 wins)"
  assert_eq "$(get reply_strict | grep -cF 'dev cl0' || true)" "0" \
    "strict mode (effective 1) drops the same reply: why the file must never say 1"
  assert_eq "$(get reply_off | grep -cF 'dev cl0' || true)" "1" "rp_filter 0 passes it too"
  assert_eq "$(get accept_mark)" "0x0" "loaded: a marked SYN gives an unmarked accepted socket"
  assert_eq "$(get accept_mark_on)" "0x5" "(with tcp_fwmark_accept=1 the socket takes the client's mark)"

  # Boot loads the file with systemd-sysctl, not sysctl -p: its own glob rules.
  SDS=""
  for p in /usr/lib/systemd/systemd-sysctl /lib/systemd/systemd-sysctl; do [[ -x "$p" ]] && { SDS=$p; break; }; done
  if [[ -n "$SDS" ]]; then
    BOOT=$(unshare -rn bash -c '
      ip link add cl0 type dummy
      sysctl -q -w net.ipv6.conf.all.forwarding=1
      echo "errors=$("$1" "$2" 2>&1 | tr "\n" " ")"
      echo "rpf=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)/$(cat /proc/sys/net/ipv4/conf/default/rp_filter)"
      echo "v6=$(cat /proc/sys/net/ipv6/conf/cl0/forwarding)/$(cat /proc/sys/net/ipv6/conf/cl0/accept_redirects)"' \
      _ "$SDS" "$F" 2>&1 || true)
    bget() { sed -n "s/^$1=//p" <<<"$BOOT" | head -1; }
    assert_eq "$(bget errors)" "" "systemd-sysctl (boot) applies every key of the file"
    assert_eq "$(bget rpf)" "2/2" "boot: rp_filter all/default 2"
    assert_eq "$(bget v6)" "0/0" "boot: IPv6 forwarding and redirects off on a NIC that existed before it ran"
  else
    echo "  - SKIPPED boot loader: no systemd-sysctl"
  fi
else
  echo "  - SKIPPED behaviour: needs ip, sysctl and unprivileged user+net namespaces (unshare -rn)"
fi

summary
