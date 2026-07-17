#!/usr/bin/env bash
# Preflight/postflight checks. Each: 0 pass, 1 hard-fail, 2 warn. Prints result.
# Depends on common.sh (config loaded).

_pass() { printf '  PASS  %s\n' "$*"; return 0; }
_fail() { printf '  FAIL  %s\n' "$*" >&2; return 1; }
_warn() { printf '  WARN  %s\n' "$*" >&2; return 2; }

check_os() {
    # The doctor runs BEFORE deps, so require only what a base Debian/Ubuntu
    # always has (apt + systemd). nftables/python3/tcpdump/conntrack are
    # dependencies THIS installer installs — checking for them here would
    # false-fail a minimal image. The rendered ruleset is validated with
    # `nft -c` in apply_files once nftables is actually installed.
    { command -v apt-get && command -v systemctl; } >/dev/null 2>&1 \
        && _pass "apt + systemd present (nftables + other deps are installed by this installer)" \
        || _fail "not an apt+systemd system (spec-1 supports the Debian/Ubuntu family only)"
}

check_ifaces() {
    local i
    for i in "$MGMT_IFACE" "$CLIENT_IFACE"; do
        ip link show "$i" >/dev/null 2>&1 || { _fail "interface '$i' not found — fix MGMT_IFACE/CLIENT_IFACE in multivpn.conf"; return 1; }
    done
    case "$MGMT_IFACE$CLIENT_IFACE" in *eth[0-9]*) _warn "eth* names may not be stable across reboots; prefer predictable names";; esac
    _pass "interfaces $MGMT_IFACE, $CLIENT_IFACE present"
}

check_two_nics() {
    [[ "$MGMT_IFACE" != "$CLIENT_IFACE" && -n "$CLIENT_IFACE" ]] \
        && _pass "two distinct NICs (gateway mode)" \
        || _fail "gateway mode needs two distinct NICs; single-NIC = SOCKS mode (spec 2, not yet available)"
}

check_forwarding() {
    # Read the proc knob directly. doctor runs BEFORE deps, so `sysctl` (procps)
    # may not be installed yet; /proc/sys/net/ipv4/ip_forward is always present
    # on any IPv4-capable Linux. The installer sets+persists it in apply_network.
    [[ -r /proc/sys/net/ipv4/ip_forward ]] \
        && _pass "IP forwarding controllable (installer will enable+persist)" \
        || _fail "cannot read /proc/sys/net/ipv4/ip_forward — is this a Linux host with IPv4?"
}

check_no_conflict() {
    if ip netns list 2>/dev/null | grep -qE 'ns-(proton|dns)'; then
        _warn "pre-existing multivpn netns/ip-rules present — vpnns-up.sh will reconcile them on bring-up (fine for a re-run; investigate if this is a fresh box)"; return 2
    fi
    if ip rule 2>/dev/null | grep -qE '172\.31\.'; then
        _warn "pre-existing multivpn netns/ip-rules present — vpnns-up.sh will reconcile them on bring-up (fine for a re-run; investigate if this is a fresh box)"; return 2
    fi
    _pass "no conflicting netns / ip rules"
}

check_ssh_source() {
    local src
    src=$(ss -tnp 2>/dev/null | awk '/:22 /{split($4,a,":"); split($5,b,":"); print b[1]; exit}')
    [[ -z "$src" ]] && { _warn "no active SSH session detected — can't verify lockout safety"; return 2; }
    if ip_in_cidr "$src" "$MGMT_CIDR"; then
        _pass "live SSH source $src is inside MGMT_CIDR (kept by input ruleset)"
    else
        _fail "live SSH source $src is NOT covered by the rendered input rules — applying nft would lock you out. Widen MGMT_CIDR or add an ssh-mgmt exception."
    fi
}

check_client_traffic() {   # network; not unit-tested
    # tcpdump isn't in the base system and is installed with the deps (after the
    # pre-apply doctor runs); if it's missing, say so rather than guess.
    command -v tcpdump >/dev/null 2>&1 \
        || { _warn "tcpdump not installed yet — skipping client-VLAN traffic check (re-run post-apply)"; return 2; }
    # Count only real packet lines. `... | wc -l` over-counts because tcpdump can
    # emit a non-packet line (and an empty capture can still yield one line),
    # which produced a false PASS on an idle interface; grep for packet lines.
    local pkts
    pkts=$(timeout 6 tcpdump -ni "$CLIENT_IFACE" -c1 -q "net ${CLIENT_VLAN_CIDR} and not arp" 2>/dev/null | grep -cE ' IP6? ')
    (( pkts > 0 )) && _pass "saw client-VLAN traffic on $CLIENT_IFACE" \
        || _warn "no client-VLAN traffic on $CLIENT_IFACE in 6s. Confirm this VM is the VLAN's default gateway (point the VLAN gateway at $CLIENT_GW_IP; the upstream/UniFi holds the /24 for DHCP). A brand-new VLAN is legitimately quiet."
}

check_upstream() {         # network; not unit-tested
    getent ahostsv4 vpn-api.proton.me >/dev/null 2>&1 \
        && _pass "Proton API resolves from mgmt" \
        || _warn "cannot resolve vpn-api.proton.me — check upstream DNS/reachability before bootstrap"
}

check_return_path() {      # post-apply; network — the asymmetric mgmt->VLAN SSH scar
    local first
    first=$(nft list chain inet filter forward 2>/dev/null \
        | grep -nE 'client-to-private|ct state invalid' | head -1)
    if grep -q client-to-private <<<"$first"; then
        _pass "forward chain: client-to-private precedes ct-state-invalid drop (return path OK)"
    else
        _warn "forward chain ordering: client-to-private must precede the ct-state-invalid drop for mgmt->VLAN SSH return traffic — check the nftables template"
    fi
}

# Runs the pre-apply gate; hard fails (rc 1) abort the install.
doctor_pre() {
    local rc=0
    for c in check_os check_ifaces check_two_nics check_forwarding check_no_conflict check_ssh_source; do
        "$c" || { [[ $? -eq 1 ]] && rc=1; }
    done
    check_client_traffic || true
    check_upstream || true
    return $rc
}

# Post-apply verification (all network; prints, never blocks).
doctor_post() {
    check_client_traffic || true
    check_return_path || true
    check_upstream || true
    command -v /etc/multivpn/bin/slot-rank >/dev/null && /etc/multivpn/bin/slot-rank || true
}
