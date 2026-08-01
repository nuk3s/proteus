#!/usr/bin/env bash
# Render every install/templates/*.tmpl into a staging dir via envsubst.
# Depends on common.sh (config already loaded+validated, derive available).

TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../templates" && pwd)"

# Export config + derived values so envsubst can see them.
DNS_INSTANCE=dns   # fresh-install DNS instance name (index 99 via override)

_export_vars() {
    local line
    export MGMT_IFACE CLIENT_IFACE MGMT_CIDR CLIENT_VLAN_CIDR CLIENT_GW_IP \
           SLOT_COUNT DNS_UPSTREAMS PROTON_COUNTRY STREAMING_MIN_MBPS NFT_REVERT_SECONDS \
           DNS_INSTANCE
    while IFS= read -r line; do export "${line?}"; done < <(derive)
    export DNS_FWMARK_HEX="0x$(printf '%x' "$DNS_INDEX")"
    # Pre-expand list-valued fields into template-ready blocks. Known Quad9
    # service IPs get DNS-over-TLS form (ip@853#authname): Quad9 rate-limits
    # UDP/53 per source IP under sustained volume (a VPN exit trips it within
    # the hour and goes dark), while tcp/853 is unaffected. If every upstream
    # maps to an authname the zone forwards over TLS; any unknown upstream
    # falls the whole zone back to plain UDP (mixed zones aren't valid).
    local ns an block="" tls=yes
    for ns in $DNS_UPSTREAMS; do
        case "$ns" in
            9.9.9.9|149.112.112.112)   an=dns.quad9.net ;;
            9.9.9.10|149.112.112.10)   an=dns10.quad9.net ;;
            9.9.9.11|149.112.112.11)   an=dns11.quad9.net ;;
            *)                         an="" ;;
        esac
        [[ -z "$an" ]] && tls=no
        block+="    forward-addr: ${ns}${an:+@853#${an}}"$'\n'
    done
    if [[ $tls == no ]]; then
        # Rebuild plain if any upstream lacked an authname.
        block=""
        for ns in $DNS_UPSTREAMS; do block+="    forward-addr: ${ns}"$'\n'; done
    fi
    export UNBOUND_FORWARD_ADDRS="$block"
    export UNBOUND_TLS_UPSTREAM="$tls"
}

# envsubst substitutes EVERY $VAR it finds unless given an explicit list. The
# nftables template keeps nftables' own native define-vars ($LAN_MGMT,
# $CLIENT_VLAN, $RFC1918); an unrestricted envsubst would blank those to empty
# strings and produce an invalid ruleset. Restrict it to OUR variables only.
INSTALLER_VARS='$MGMT_IFACE $CLIENT_IFACE $MGMT_CIDR $CLIENT_VLAN_CIDR $CLIENT_GW_IP $DNS_UPSTREAMS $STREAMING_MIN_MBPS $PROTON_COUNTRY $DNS_INSTANCE $DNS_INDEX $DNS_TABLE $DNS_TRANSIT_MAIN $DNS_FWMARK_HEX $UNBOUND_FORWARD_ADDRS $UNBOUND_TLS_UPSTREAM'

render_all() {
    local out=${1:?staging dir required}
    mkdir -p "$out"
    _export_vars
    local f base
    for f in "$TEMPLATE_DIR"/*.tmpl; do
        base=$(basename "$f" .tmpl)
        envsubst "$INSTALLER_VARS" < "$f" > "$out/$base"
    done
}

# Print a unified diff of staged files vs their live destinations.
stage_diff() {
    local out=${1:?staging dir}
    declare -A DEST=(
        [proteus.env]=/etc/proteus/proteus.env
        [nftables.conf]=/etc/nftables.conf
        [unbound-proteus-dns.conf]=/etc/unbound/unbound.conf.d/proteus-dns.conf
    )
    local base
    for base in "${!DEST[@]}"; do
        [[ -f "$out/$base" ]] || continue
        diff -u "${DEST[$base]}" "$out/$base" 2>/dev/null || true
    done
    local su
    for su in "$out"/proteus-*.service "$out"/proteus-*.timer; do
        [[ -e "$su" ]] || continue
        diff -u "/etc/systemd/system/$(basename "$su")" "$su" 2>/dev/null || true
    done
}
