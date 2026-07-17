#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/common.sh"
source "$HERE/lib/render.sh"
source "$HERE/lib/doctor.sh"
source "$HERE/lib/apply.sh"
CONF="$HERE/multivpn.conf"
STAGE="$HERE/.staging"

usage() { echo "usage: sudo $0 [--check | --render | --confirm]"; exit 1; }

main() {
    local mode=install
    case "${1:-}" in
        --check) mode=check;; --render) mode=render;; --confirm) mode=confirm;;
        "") ;; *) usage;;
    esac
    [[ -r "$CONF" ]] || die "copy install/multivpn.conf.example to $CONF and edit it first"
    load_config "$CONF"; validate_config

    if [[ $mode == check ]]; then
        log "== doctor (read-only) =="; doctor_pre || die "preflight failed (see FAIL lines)"; return
    fi
    if [[ $mode == confirm ]]; then
        confirm                       # cancel the revert (you reached here, so SSH survived)
        log "== phase: bootstrap =="; proton_bootstrap
        log "== phase: mint =="; initial_mint
        log "== phase: enable =="; enable_services
        log "== phase: verify =="; doctor_post
        log "install complete."
        return
    fi

    log "== phase: doctor =="; doctor_pre || die "preflight failed; fix FAILs and re-run"
    log "== phase: deps =="; install_deps
    log "== phase: render =="; render_all "$STAGE"; log "-- diff vs live --"; stage_diff "$STAGE"
    [[ $mode == render ]] && { log "dry-run: rendered + diffed, nothing applied"; return 0; }
    log "== phase: apply =="; apply_files "$STAGE"; apply_network
    log "Network applied behind a ${NFT_REVERT_SECONDS}s auto-revert."
    log "NOW: open a NEW SSH session to confirm you're not locked out, and that"
    log "clients still reach the LAN. Then finish the install with:"
    log "    sudo $0 --confirm"
    log "(cancels the revert; runs Proton login + initial mint + services)."
    log "If you cannot reconnect, do nothing — it auto-reverts in ${NFT_REVERT_SECONDS}s."
}

install_deps() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # systemd-timesyncd matters twice: it keeps the clock correct (TLS cert
    # validation on the Proton control plane fails on a skewed clock) AND it
    # creates the `systemd-timesync` system user that the kill-switch's NTP rule
    # scopes egress to (meta skuid "systemd-timesync") — without the user, the
    # rendered ruleset fails `nft -c` and the install aborts. unbound/_apt users
    # are likewise created by the unbound package / apt itself.
    # python3-netfilterqueue + python3-scapy back the NFQUEUE dispatcher
    # (dispatcher.py: `from netfilterqueue import NetfilterQueue` and
    # `from scapy.layers.inet import IP`); without them the dispatcher crash-loops
    # and no client traffic is routed. Both are in Debian 13 main.
    apt-get install -y -qq nftables unbound wireguard-tools gettext-base curl dnsutils \
        python3 python3-netfilterqueue python3-scapy conntrack tcpdump iproute2 procps \
        systemd-timesyncd || die "dependency install failed"
    # Proton VPN python lib. Debian 13 (trixie) ships python3-proton-vpn-api-core
    # 0.39.0-1 in main — the exact build production runs — pulling python3-proton-core.
    # (The PyPI name "proton-vpn-api-core" is an unrelated empty placeholder with no
    # releases, so `pip install` can never work; use the distro package.) On distros
    # that don't carry it, fall back to Proton's official APT repo.
    if ! python3 -c 'import proton.vpn.core' 2>/dev/null; then
        apt-get install -y -qq python3-proton-vpn-api-core 2>/dev/null || add_proton_repo
    fi
    python3 -c 'import proton.vpn.core' 2>/dev/null \
        || warn "proton.vpn.core still not importable — install the proton-vpn python packages before --confirm (bootstrap/mint need them)"
}

# Fallback for non-Debian-13 targets: add Proton's official, GPG-signed APT repo
# via their release .deb (version-pinned + checksum-verified), then apt-install.
add_proton_repo() {
    warn "python3-proton-vpn-api-core not in this distro's apt; adding Proton's official repo"
    local deb=/tmp/protonvpn-stable-release_1.0.8_all.deb
    local want=0b14e71586b22e498eb20926c48c7b434b751149b1f2af9902ef1cfe6b03e180
    curl -fsSL -o "$deb" \
        "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.8_all.deb" \
        || { warn "could not download Proton release deb"; return 1; }
    echo "$want  $deb" | sha256sum --check --status \
        || { warn "Proton release deb checksum mismatch — refusing to install"; rm -f "$deb"; return 1; }
    dpkg -i "$deb" >/dev/null 2>&1 || true      # 'apt-get install ./x.deb' rejects local debs on trixie
    apt-get update -qq
    apt-get install -y -qq python3-proton-vpn-api-core || warn "Proton-repo install of python3-proton-vpn-api-core failed"
}

proton_bootstrap() {
    # Don't pre-check the session here. proton-mint/proton-bootstrap force
    # proton-sso onto the JsonFiles keyring (a headless box has no DBus/
    # SecretService), and the session is persisted under THAT backend. A raw
    # ProtonVPNAPI().is_user_logged_in() without the same override always reports
    # False on a headless box even when the session is valid — so it's a useless
    # gate. proton-bootstrap already applies the override and no-ops if a valid
    # session exists; otherwise it runs the one-time interactive login.
    log "Proton login (skips automatically if a valid session already exists):"
    /etc/multivpn/bin/proton-bootstrap
}

# A fresh box has no minted WG configs, so the slot/dns units (ConditionPathExists)
# would come up empty and the rotation timers wouldn't fire for up to ~12h. Mint an
# initial config for each slot + dns now via the normal rotation pipeline (which
# also brings each up and writes the stable .conf symlink the units read).
initial_mint() {
    local n
    log "minting initial config for $SLOT_COUNT slot(s) + dns (each runs mint+probe+gate, ~1-2 min)"
    for (( n=1; n<=SLOT_COUNT; n++ )); do
        log "  proton-$n ..."
        /etc/multivpn/bin/rotate-slot.sh "proton-$n" \
            || warn "initial mint for proton-$n failed — its daily timer will retry"
    done
    log "  dns ..."
    /etc/multivpn/bin/rotate-dns.sh -f || warn "initial dns mint failed — dns-latency timer will retry"
}

enable_services() {
    systemctl daemon-reload
    local n
    for (( n=1; n<=SLOT_COUNT; n++ )); do systemctl enable --now "multivpn-proton@proton-$n" || true; done
    systemctl enable --now multivpn-dns-tunnel.service unbound multivpn-dispatcher.service
    systemctl enable --now multivpn-slot-warmup.timer multivpn-dns-latency.timer \
        multivpn-proton-api-whitelist.timer
    for (( n=1; n<=SLOT_COUNT; n++ )); do systemctl enable "multivpn-rotate-slot@proton-$n.timer" || true; done
}

main "$@"
