#!/usr/bin/env bash
# Render every install/templates/*.tmpl into a staging dir via envsubst.
# Depends on common.sh (config already loaded+validated, derive available).

TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../templates" && pwd)"

# Export config + derived values so envsubst can see them.
DNS_INSTANCE=dns   # fresh-install DNS instance name (index 99 via override)

_export_vars() {
    local line
    export MGMT_IFACE CLIENT_IFACE MGMT_CIDR CLIENT_VLAN_CIDR CLIENT_GW_IP \
           SLOT_COUNT DNS_UPSTREAMS UNBOUND_UPSTREAM PROTON_COUNTRY STREAMING_MIN_MBPS \
           NFT_REVERT_SECONDS DNS_INSTANCE UI_PORT UI_MGMT_EXTRA
    while IFS= read -r line; do export "${line?}"; done < <(derive)
    export DNS_FWMARK_HEX="0x$(printf '%x' "$DNS_INDEX")"
    # Build unbound's forward-zone from UNBOUND_UPSTREAM alone. DNS_UPSTREAMS is
    # NOT consulted here: it feeds the per-netns resolv.conf for the reputation
    # probes, and the two are deliberately decoupled (see common.sh).
    #
    # Why the DoT mapping exists, and when it applies: Quad9 rate-limits UDP/53
    # per source IP under sustained volume — a VPN exit carrying our query volume
    # trips it within the hour and goes completely dark on UDP while tcp/853 keeps
    # answering (measured 2026-08-01: 100% UDP loss, TCP fine, same exit), which
    # reads as a dead tunnel and drives constant DNS-tunnel rotation. So a public
    # Quad9 upstream must be forwarded over TLS. None of that applies to the
    # default in-tunnel resolver: the query never leaves WireGuard, Proton does
    # not rate-limit its own gateway address, and WG already encrypts the hop, so
    # DoT would only add handshake latency. Keep the mapping anyway — it is what
    # makes pointing UNBOUND_UPSTREAM back at a public resolver safe.
    #
    # An upstream with no known authname forwards over plain UDP:
    # forward-tls-upstream is per-zone, not per-address, so the zone has to agree.
    local an tls=yes
    case "$UNBOUND_UPSTREAM" in
        10.2.0.1)                  an=""; tls=no ;;   # Proton in-tunnel NetShield
        9.9.9.9|149.112.112.112)   an=dns.quad9.net ;;
        9.9.9.10|149.112.112.10)   an=dns10.quad9.net ;;
        9.9.9.11|149.112.112.11)   an=dns11.quad9.net ;;
        *)                         an=""; tls=no ;;
    esac
    export UNBOUND_FORWARD_ADDRS="    forward-addr: ${UNBOUND_UPSTREAM}${an:+@853#${an}}"
    export UNBOUND_TLS_UPSTREAM="$tls"
    # A COMPLETE config line, emitted ONLY on the DoT path. The `#authname` form
    # above makes unbound verify the upstream certificate, and with no CA store
    # configured that verification fails for every query — unbound-checkconf
    # returns 0, the daemon starts clean, and then 100% of client lookups
    # SERVFAIL ("ssl handshake cert error: unable to get local issuer
    # certificate"). Emitting it unconditionally is not safe either: if
    # /etc/ssl/certs/ca-certificates.crt is absent, unbound refuses to start at
    # all ("error in SSL_CTX verify locations"), which would turn a working
    # plain-UDP install into a dead one. So: bundle on the TLS path, comment on
    # the plain path.
    if [[ $tls == yes ]]; then
        export UNBOUND_TLS_CERT_BUNDLE="    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt"
    else
        export UNBOUND_TLS_CERT_BUNDLE="    # (no tls-cert-bundle: plain-UDP upstream authenticates nothing)"
    fi
    # A COMPLETE config line, dropped into the server: block verbatim. An upstream
    # in 10.2.0.0/16 is a Proton in-tunnel resolver: NetShield answers a blocked
    # name with a bare unsigned NXDOMAIN and NXDOMAINs the DS query for it too, so
    # a validating resolver cannot prove insecure delegation and hands clients
    # SERVFAIL for every blocked ad domain instead of a clean NXDOMAIN (verified:
    # `delv @10.2.0.1 doubleclick.net` -> "broken trust chain"). Dropping the
    # validator is what makes NetShield usable downstream, and it costs only the
    # last hop — 10.2.0.1 validates upstream itself and that hop is inside the
    # WireGuard tunnel. Any other upstream keeps the validator.
    if ip_in_cidr "$UNBOUND_UPSTREAM" 10.2.0.0/16; then
        export UNBOUND_MODULE_CONFIG='module-config: "iterator"'
    else
        export UNBOUND_MODULE_CONFIG='module-config: "validator iterator"'
    fi
}

# envsubst substitutes EVERY $VAR it finds unless given an explicit list. The
# nftables template keeps nftables' own native define-vars ($LAN_MGMT,
# $CLIENT_VLAN, $RFC1918); an unrestricted envsubst would blank those to empty
# strings and produce an invalid ruleset. Restrict it to OUR variables only.
#
# The flip side: a variable MISSING from this list is not an error — envsubst
# copies the literal `${NAME}` into the output, and unbound then refuses to start
# on the unknown option. Every var a template references must be listed here.
INSTALLER_VARS='$MGMT_IFACE $CLIENT_IFACE $MGMT_CIDR $CLIENT_VLAN_CIDR $CLIENT_GW_IP $DNS_UPSTREAMS $UNBOUND_UPSTREAM $STREAMING_MIN_MBPS $PROTON_COUNTRY $DNS_INSTANCE $DNS_INDEX $DNS_TABLE $DNS_TRANSIT_MAIN $DNS_FWMARK_HEX $UNBOUND_FORWARD_ADDRS $UNBOUND_TLS_UPSTREAM $UNBOUND_MODULE_CONFIG $UNBOUND_TLS_CERT_BUNDLE $UI_PORT $UI_MGMT_EXTRA'

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
    for su in "$out"/proteus-*.service "$out"/proteus-*.timer "$out"/proteus-*.socket; do
        [[ -e "$su" ]] || continue
        diff -u "/etc/systemd/system/$(basename "$su")" "$su" 2>/dev/null || true
    done
}
