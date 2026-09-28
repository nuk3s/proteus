#!/usr/bin/env bash
# tests/nftables_trusted_test.sh
#
# The dispatch gate decides which traffic may reach the rotating exits, so its
# shape is worth pinning literally. Two properties matter most and are easy to
# lose in a later edit: an EMPTY @trusted_src must reproduce the pre-feature
# behaviour exactly, and the wg-udm match must use `iifname` rather than `iif`
# — `iif` resolves to an interface index when the ruleset LOADS, so it would
# make the whole firewall fail to load on any box that has not paired a UDM,
# and nftables.conf begins with `flush ruleset`.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$ROOT/etc/nftables.conf"

echo "the trusted set exists and is not seeded"
assert_eq "$(grep -c 'set trusted_src' "$CONF")" "1" "@trusted_src declared once"
assert_eq "$(awk '/set trusted_src/,/^    }/' "$CONF" | grep -c 'elements')" "0" \
    "set is empty at load: an unpaired box boots with the feature off"

echo "the gate accepts exactly two origins"
assert_eq "$(grep -c 'iifname != { "ens19", "wg-udm" } return' "$CONF")" "1" "two-origin guard"
assert_eq "$(grep -c 'iifname "ens19"  *ip saddr != \$CLIENT_VLAN return' "$CONF")" "1" "client gate"
assert_eq "$(grep -c 'iifname "wg-udm" *ip saddr != @trusted_src return' "$CONF")" "1" "trusted gate"

echo "wg-udm is matched by NAME, never by index"
if grep -nE '\biif +"?wg-udm' "$CONF" | grep -v iifname; then r=fail; else r=ok; fi
assert_eq "$r" ok "no bare 'iif wg-udm' anywhere (would break loading before pairing)"

# ---------------------------------------------------------------------------
# Tunnel traffic must dispatch on DESTINATION, never on source.
#
# The UDM masquerades, so every trusted host reaches proteus as the single
# tunnel address. With an unscoped @source_pin lookup — which runs before the
# @vpn_dispatch lookup — the first trusted packet pinned that one address to
# one slot and the entire trusted VLAN shared one exit from then on. Scoping
# the source lookup to the client interface is what lets tunnel traffic fall
# through to the destination lookup. Assert the shape literally: the failure is
# silent (traffic still flows, just all through one exit) and would otherwise
# only be visible by reading a live map.
# ---------------------------------------------------------------------------
echo "the source lookup is scoped to the client VLAN, so wg-udm dispatches per destination"
TMPL="$ROOT/install/templates/nftables.conf.tmpl"

assert_eq "$(grep -cF 'iifname "ens19" meta mark set ip saddr map @source_pin' "$CONF")" "1" \
    "source lookup is scoped to the client interface"
assert_eq "$(grep -cE '^[[:space:]]*meta mark set ip saddr map @source_pin' "$CONF")" "0" \
    "and there is no unscoped source lookup left to shadow it"
assert_eq "$(grep -cE '^[[:space:]]*meta mark set ip daddr map @vpn_dispatch' "$CONF")" "1" \
    "the destination lookup stays unscoped, so tunnel traffic reaches it"
assert_eq "$(grep -cF 'iifname "${CLIENT_IFACE}" meta mark set ip saddr map @source_pin' "$TMPL")" "1" \
    "template: same scoping, in placeholder form"
assert_eq "$(grep -cE '^[[:space:]]*meta mark set ip saddr map @source_pin' "$TMPL")" "0" \
    "template: no unscoped source lookup either"
assert_eq "$(grep -cE '^[[:space:]]*meta mark set ip daddr map @vpn_dispatch' "$TMPL")" "1" \
    "template: destination lookup unscoped too"

# The conntrack restore must stay first and unconditional: it is what keeps an
# established flow on the exit it started on when a map entry expires
# mid-stream, and that matters MORE for tunnel traffic now that a destination
# entry is all such a flow has.
CT_LINE=$(grep -nE '^[[:space:]]*meta mark set ct mark$' "$CONF" | head -1 | cut -d: -f1)
SRC_LINE=$(grep -nF 'meta mark set ip saddr map @source_pin' "$CONF" | head -1 | cut -d: -f1)
DST_LINE=$(grep -nE '^[[:space:]]*meta mark set ip daddr map @vpn_dispatch' "$CONF" | head -1 | cut -d: -f1)
assert_eq "$([ -n "$CT_LINE" ] && [ "$CT_LINE" -lt "$SRC_LINE" ] && echo yes || echo no)" yes \
    "the conntrack restore still runs before the source lookup, unscoped"
assert_eq "$([ "$SRC_LINE" -lt "$DST_LINE" ] && echo yes || echo no)" yes \
    "and the source lookup still precedes the destination lookup for the client VLAN"

# The reason has to travel with the rule. Someone deleting the iifname to
# "simplify" the chain reintroduces the bug in one keystroke, and nothing else
# in the ruleset says why the scope is there.
assert_eq "$(grep -c 'masquerade' "$CONF")" "1" "the ruleset says WHY: the UDM masquerades"
assert_eq "$(grep -c 'masquerade' "$TMPL")" "1" "template: that reasoning is carried over"

# Both copies of the chain must agree rule for rule. The installer renders the
# firewall from the template and NEVER copies etc/nftables.conf, so a fix
# landed in one file only ships a fresh gateway with the old behaviour.
norm_chain() {   # <file> — the mangle chain, comments and spacing removed
  awk '/chain prerouting_mangle/,/^    }/' "$1" \
    | grep -vE '^[[:space:]]*(#|$)' \
    | sed -e 's/\${CLIENT_IFACE}/ens19/g' -e 's/[[:space:]]\+/ /g' \
          -e 's/^ //' -e 's/ $//'
}
CHAIN_DIFF=$(diff <(norm_chain "$CONF") <(norm_chain "$TMPL") || true)
assert_eq "$CHAIN_DIFF" "" "etc/nftables.conf and the installer template carry the same mangle chain"

echo "the forward chain accepts marked trusted traffic and names the LAN mistake"
assert_eq "$(grep -c 'comment "trusted-marked-to-vpn"' "$CONF")" "1" "trusted egress accept"
assert_eq "$(grep -c 'comment "trusted-to-lan"' "$CONF")" "1" "RFC1918-from-tunnel drop"
assert_eq "$(grep -c 'nft-trusted-lan ' "$CONF")" "1" "that drop is logged distinctly"

echo "the tunnel handshake is allowed in, from the management LAN only"
assert_eq "$(grep -c 'comment "udm-tunnel"' "$CONF")" "1" "input accept for the tunnel"
assert_eq "$(grep -c 'define UDM_TUNNEL_PORT' "$CONF")" "1" "port is a define"

echo "the ruleset still parses"
# `nft -c` needs a netlink cache to resolve table/set references, which normally
# needs privileges this suite should not assume. `unshare -rn` builds that cache
# inside a private, unprivileged user+network namespace, so the check runs for
# real without root. Separately, `meta skuid "name"` rules resolve the name via
# NSS at PARSE time, and this dev box does not carry the ruleset's system
# accounts (Debian's `_apt`, `unbound`, ...) — so every named skuid is rewritten
# to a numeric placeholder first. That substitution count is itself asserted
# nonzero: if it ever drops to zero because the pattern changed, this check has
# silently stopped covering skuid rules, and a real typo in a future one could
# sail through unparsed. The only loud SKIP left is an environment where even
# `unshare -rn` cannot build a netlink cache (no user namespaces) — that must
# degrade honestly rather than either pass falsely or fail red.
nft_parses() {   # <file> <label>
  local src=$1 label=$2 tmp err skuids
  tmp=$(mktemp); err=$(mktemp)
  sed -e 's/^flush ruleset$//' -e '/^include /d' "$src" > "$tmp"
  skuids=$(grep -o 'meta skuid "[^"]*"' "$tmp" | wc -l || true)
  sed -i -E 's/meta skuid "[^"]+"/meta skuid 0/g' "$tmp"
  assert_eq "$([ "${skuids:-0}" -gt 0 ] && echo yes || echo no)" yes \
      "$label: meta skuid names replaced with a numeric placeholder before parsing ($skuids substitutions)"

  if unshare -rn nft -c -f "$tmp" 2>"$err"; then
    assert_eq ok ok "$label: unshare -rn nft -c accepts the ruleset with wg-udm absent"
  elif grep -qi 'cache initialization' "$err"; then
    echo "  - SKIPPED nft -c ($label): this environment cannot build a netlink cache even inside unshare -rn ($(tr '\n' ' ' <"$err" | cut -c1-100))"
  else
    assert_eq "fail: $(tr '\n' ' ' <"$err" | cut -c1-200)" ok "$label: unshare -rn nft -c accepts the ruleset with wg-udm absent"
  fi
  rm -f "$tmp" "$err"
}

if command -v nft >/dev/null 2>&1 && command -v unshare >/dev/null 2>&1; then
  nft_parses "$CONF" "etc/nftables.conf"
else
  echo "  - SKIPPED nft -c: nft or unshare not available in this environment"
fi

echo "all three copies of the tunnel port agree"
# The port is fixed rather than rendered: the live ruleset, the installer
# template and the reconcile script each carry the number, and nothing derives
# one from another. A fresh install that shipped a template disagreeing with the
# script would listen on a port its own firewall drops — a UDM that will not
# connect, with no rule to point at. Cheap to assert, so assert it.
SCRIPT="$ROOT/etc/proteus/bin/proteus-trusted-egress.sh"
TMPL="$ROOT/install/templates/nftables.conf.tmpl"
if [[ -f "$SCRIPT" ]]; then
  NFT_PORT=$(sed -n 's/^define UDM_TUNNEL_PORT *= *//p' "$CONF" | tr -d ' ')
  TMPL_PORT=$(sed -n 's/^define UDM_TUNNEL_PORT *= *//p' "$TMPL" | tr -d ' ')
  SH_PORT=$(sed -n 's/.*PROTEUS_UDM_TUNNEL_PORT:-\([0-9]*\)}.*/\1/p' "$SCRIPT" | head -1)
  assert_eq "$SH_PORT" "$NFT_PORT" "reconcile script default matches the firewall define"
  assert_eq "$TMPL_PORT" "$NFT_PORT" "the installer template's define matches it too"
  assert_eq "$(grep -c 'FIXED, not a per-site setting' "$CONF")" "1" \
      "and the ruleset says the port is fixed, so nobody expects the env var to move it"
  assert_eq "$(grep -c 'FIXED, in lockstep' "$SCRIPT")" "1" "as does the script default"
  assert_eq "$(grep -c 'FIXED, not a per-site setting' "$TMPL")" "1" "and the installer template"
else
  echo "  - SKIPPED: $SCRIPT does not exist yet (created by Task 3)"
fi

# ---------------------------------------------------------------------------
# The installer renders install/templates/nftables.conf.tmpl into
# /etc/nftables.conf on a FRESH box; it never copies etc/nftables.conf. A rule
# added to one file and not the other therefore ships a gateway whose scripts,
# unit and UI all speak of trusted egress while the firewall has no
# @trusted_src at all — the reconcile script fails with "set not present" and
# every tunnelled packet dies in the forward policy drop, with nothing naming
# the cause. Assert the feature is in the template too, in placeholder form.
# ---------------------------------------------------------------------------
echo "the installer template carries the same feature"
TMPL="$ROOT/install/templates/nftables.conf.tmpl"
RENDER="$ROOT/install/lib/render.sh"

assert_eq "$(grep -c 'define UDM_TUNNEL_PORT' "$TMPL")" "1" "template: port is a define"
assert_eq "$(grep -c 'set trusted_src' "$TMPL")" "1" "template: @trusted_src declared once"
assert_eq "$(awk '/set trusted_src/,/^    }/' "$TMPL" | grep -c 'auto-merge')" "1" \
    "template: auto-merge, so overlapping operator ranges cannot empty the gate"
assert_eq "$(awk '/set trusted_src/,/^    }/' "$TMPL" | grep -c 'elements')" "0" \
    "template: set is empty at load, and the comment says why it has no boot seed"
assert_eq "$(grep -c 'Deliberately not seeded here' "$TMPL")" "1" "template: that reasoning is carried over"

# Placeholder form is the whole point: envsubst only substitutes the names in
# INSTALLER_VARS, and a literal ens18/ens19 would hard-code THIS gateway's NICs
# into every install.
assert_eq "$(grep -cF 'iifname != { "${CLIENT_IFACE}", "wg-udm" } return' "$TMPL")" "1" "template: two-origin guard"
assert_eq "$(grep -cF 'iifname "${CLIENT_IFACE}" ip saddr != $CLIENT_VLAN return' "$TMPL")" "1" "template: client gate"
assert_eq "$(grep -cF 'iifname "wg-udm" ip saddr != @trusted_src return' "$TMPL")" "1" "template: trusted gate"
assert_eq "$(grep -c 'comment "trusted-marked-to-vpn"' "$TMPL")" "1" "template: trusted egress accept"
assert_eq "$(grep -c 'comment "trusted-to-lan"' "$TMPL")" "1" "template: RFC1918-from-tunnel drop"
assert_eq "$(grep -c 'nft-trusted-lan ' "$TMPL")" "1" "template: that drop is logged distinctly"
assert_eq "$(grep -c 'comment "udm-tunnel"' "$TMPL")" "1" "template: input accept for the tunnel"
assert_eq "$(grep -cF '${MGMT_IFACE}" ip saddr $LAN_MGMT udp dport $UDM_TUNNEL_PORT' "$TMPL")" "1" \
    "template: the tunnel accept is on \${MGMT_IFACE}, not a literal NIC name"
assert_eq "$(grep -vE '^\s*#' "$TMPL" | grep -c 'ens1[89]')" "0" \
    "template: no site-specific NIC name in any rule (comments aside)"

# A placeholder that is NOT in INSTALLER_VARS is worse than none: envsubst
# copies the literal `${NAME}` through, and that string ships into a firewall.
VARLIST=" $(sed -n "s/^INSTALLER_VARS='\(.*\)'$/\1/p" "$RENDER") "
assert_eq "$([ -n "${VARLIST// }" ] && echo yes || echo no)" yes "INSTALLER_VARS found in render.sh"
UNLISTED=""
for v in $(grep -o '\${[A-Za-z_][A-Za-z0-9_]*}' "$TMPL" | tr -d '${}' | sort -u); do
    [[ "$VARLIST" == *" \$$v "* ]] || UNLISTED="$UNLISTED $v"
done
assert_eq "${UNLISTED# }" "" "every \${VAR} the template uses is substituted by render.sh"

echo "the rendered template parses, with interface names the installer chose"
if command -v envsubst >/dev/null 2>&1 && command -v nft >/dev/null 2>&1 \
   && command -v unshare >/dev/null 2>&1; then
  # Same mechanism as render.sh: envsubst restricted to INSTALLER_VARS, so
  # nftables' own $LAN_MGMT/$RFC1918/$UDM_TUNNEL_PORT defines survive. The
  # interfaces are deliberately NOT ens18/ens19 — that is what proves the
  # ported rules are parameterised rather than copied literally.
  export MGMT_IFACE=eth0 CLIENT_IFACE=eth1 MGMT_CIDR=10.0.0.0/24 \
         CLIENT_VLAN_CIDR=172.16.1.0/24 CLIENT_GW_IP=172.16.1.5 \
         DNS_UPSTREAMS="9.9.9.9 149.112.112.112" UNBOUND_UPSTREAM=10.2.0.1 \
         STREAMING_MIN_MBPS=25 PROTON_COUNTRY=US \
         DNS_INSTANCE=dns DNS_INDEX=99 DNS_TABLE=199 DNS_TRANSIT_MAIN=172.31.99.1 \
         DNS_FWMARK_HEX=0x63 \
         UNBOUND_FORWARD_ADDRS="    forward-addr: 10.2.0.1" \
         UNBOUND_TLS_UPSTREAM=no UNBOUND_MODULE_CONFIG='module-config: "iterator"' \
         UNBOUND_TLS_CERT_BUNDLE="    # (no tls-cert-bundle)" \
         UI_PORT=8443 UI_MGMT_EXTRA=127.0.0.1/32 \
         UI_CLIENT_RULE="        # client-VLAN access to the UI is disabled"
  RENDERED=$(mktemp)
  envsubst "${VARLIST% }" < "$TMPL" > "$RENDERED"

  assert_eq "$(grep -c '\${' "$RENDERED")" "0" "rendered: no unsubstituted \${...} left in the ruleset"
  assert_eq "$(grep -cF 'iifname != { "eth1", "wg-udm" } return' "$RENDERED")" "1" \
      "rendered: the dispatch gate names the configured client NIC"
  assert_eq "$(grep -c 'iifname "eth0".*comment "udm-tunnel"' "$RENDERED")" "1" \
      "rendered: the tunnel accept names the configured mgmt NIC"
  nft_parses "$RENDERED" "rendered template"
  rm -f "$RENDERED"
else
  echo "  - SKIPPED render check: envsubst, nft or unshare not available in this environment"
fi

summary
