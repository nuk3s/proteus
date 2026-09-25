#!/usr/bin/env bash
# Install staged files and apply networking behind an auto-reverting guard.
# Depends on common.sh + render.sh (STAGE dir already rendered).

REVERT_UNIT=proteus-nft-revert
# Repo root: apply.sh lives at <repo>/install/lib/apply.sh. The runtime scripts
# the systemd units + rotation call all live under <repo>/etc/proteus/bin and
# must be copied to /etc/proteus/bin (the path every unit/doctor/apply expects).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

apply_files() {
    local stage=${1:?stage dir}
    # An EMPTY ruleset passes `nft -c` (nothing to check) and would replace the
    # kill-switch with nothing at all, so size-check before validating.
    [[ -s "$stage/nftables.conf" ]] \
        || { die "rendered nftables.conf is empty (render failed?); not installing"; return 1; }
    # validate the rendered ruleset BEFORE it lands on disk (a bad render must
    # not sit at /etc/nftables.conf where a reboot would load it).
    # Safe to run this early, before /etc/proteus/nft is created below: the
    # ruleset's trailing client-pivot include is a bracket glob, and nft treats a
    # glob matching zero files as a no-op. A missing seed therefore cannot fail
    # validation (nor a real load) — @client_pivot just stays empty.
    nft -c -f "$stage/nftables.conf" || { die "rendered nftables failed nft -c; not installing"; return 1; }
    install -d -m 0755 /etc/proteus /etc/proteus/bin /etc/proteus/state /var/log/proteus /etc/unbound/unbound.conf.d
    install -o root -g root -m 0644 "$stage/proteus.env" /etc/proteus/proteus.env
    install -o root -g root -m 0644 "$stage/unbound-proteus-dns.conf" /etc/unbound/unbound.conf.d/proteus-dns.conf
    install -o root -g root -m 0644 "$stage/nftables.conf" /etc/nftables.conf
    local u
    for u in "$stage"/proteus-*.service "$stage"/proteus-*.timer "$stage"/proteus-*.socket; do
        [[ -e "$u" ]] || continue
        install -o root -g root -m 0644 "$u" "/etc/systemd/system/$(basename "$u")"
    done
    # Runtime scripts/modules the units + rotation pipeline execute. Everything
    # in the repo bin/ (shell, python, extensionless) is installed executable;
    # the [[ -f ]] guard skips __pycache__ and any stray subdirs.
    local f
    for f in "$REPO_ROOT"/etc/proteus/bin/*; do
        [[ -f "$f" ]] || continue
        install -o root -g root -m 0755 "$f" "/etc/proteus/bin/$(basename "$f")"
    done
    log "staged files + systemd units + $(find "$REPO_ROOT"/etc/proteus/bin -maxdepth 1 -type f | wc -l) bin scripts installed"

    # --- client-isolation boot seed ---
    # /etc/nftables.conf ends with an include of /etc/proteus/nft/client-pivot-seed[.]nft,
    # so anything in this directory is root-authored FIREWALL content that the
    # kernel loads at boot. It stays root:root 0755 deliberately: the web UI runs
    # as the unprivileged proteus-ui user, and the provisioning block right below
    # this one *does* chgrp several paths to proteus-ui. Do NOT "fix" the
    # inconsistency by chgrp'ing this directory too — a proteus-ui-writable seed
    # dir would let a non-root service inject arbitrary nftables rules.
    install -d -o root -g root -m 0755 /etc/proteus/nft
    # Generate the seed now, before apply_network's `nft -f`, so the very first
    # ruleset load already has the configured fail direction
    # (PROTEUS_CLIENT_ISOLATION_FAILSAFE: open -> the seed grants the client VLAN
    # the LAN pivot; closed -> the seed is comment-only and clients are isolated).
    # Run the script directly rather than via systemctl: on a fresh install the
    # unit file has only just been copied and daemon-reload doesn't happen until
    # enable_services (at --confirm time), so the unit may not be loaded yet.
    # Non-fatal: a box without a usable env file yet simply gets no seed, and the
    # ruleset still loads correctly — the bracket glob matches nothing and
    # @client_pivot starts empty, i.e. isolated.
    /etc/proteus/bin/proteus-client-isolation.sh \
        || warn "client-pivot seed not generated; @client_pivot will start empty (clients isolated) until proteus-client-isolation.service runs"

    # --- web UI ---
    # Unprivileged system user the daemon runs as (proteus-ui-apply.service
    # stays root — it's the privileged side of the broker boundary).
    id -u proteus-ui >/dev/null 2>&1 || useradd --system --no-create-home \
        --shell /usr/sbin/nologin proteus-ui
    install -d -m 755 /etc/proteus/ui
    install -o root -g root -m 0644 "$REPO_ROOT/etc/proteus/ui/index.html" /etc/proteus/ui/index.html
    install -d -m 700 -o proteus-ui -g proteus-ui /etc/proteus/ui/secrets /etc/proteus/ui/secrets/tls
    install -o root -g root -m 0644 "$REPO_ROOT/etc/tmpfiles.d/proteus.conf" /etc/tmpfiles.d/proteus.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/proteus.conf
    # state dir group-readable + SETGID so new .state/.meta inherit proteus-ui
    # (rotate-slot.sh/rotate-dns.sh run without CAP_CHOWN, so they can't chown
    # explicitly — setgid makes the group inheritance automatic).
    chgrp proteus-ui /etc/proteus/state && chmod 2750 /etc/proteus/state
    find /etc/proteus/state -maxdepth 1 -type f \( -name '*.state' -o -name '*.meta' \) \
        -exec chgrp proteus-ui {} + -exec chmod 640 {} + 2>/dev/null || true
    # slot-health files predate the setgid dir (slot-warmup.sh mkdir's it 0755
    # itself); catch up group ownership so the UI can read them too.
    chgrp -R proteus-ui /run/proteus-slot-health 2>/dev/null || true
    # Self-signed cert, minted once (kept across re-installs/re-applies).
    if [ ! -f /etc/proteus/ui/secrets/tls/cert.pem ]; then
        local ui_mgmt_ip
        ui_mgmt_ip=$(ip -4 -o addr show "$MGMT_IFACE" | awk '{split($4,a,"/");print a[1]}')
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
            -subj "/CN=proteus" -addext "subjectAltName=IP:${ui_mgmt_ip},IP:${CLIENT_GW_IP}" \
            -keyout /etc/proteus/ui/secrets/tls/key.pem -out /etc/proteus/ui/secrets/tls/cert.pem
        chown proteus-ui:proteus-ui /etc/proteus/ui/secrets/tls/*.pem
        chmod 600 /etc/proteus/ui/secrets/tls/key.pem
    fi
    log "web UI provisioned: user proteus-ui, /etc/proteus/ui, tls cert, tmpfiles(setgid)"
}

apply_network() {
    # 1. snapshot known-good
    nft list ruleset > /etc/nftables.conf.pre-install 2>/dev/null || true
    # 2. arm self-cancelling revert (restores the pre-install ruleset)
    systemctl reset-failed "${REVERT_UNIT}.service" "${REVERT_UNIT}.timer" 2>/dev/null || true
    systemd-run --unit="$REVERT_UNIT" --on-active="${NFT_REVERT_SECONDS}" \
        /usr/sbin/nft -f /etc/nftables.conf.pre-install
    log "armed revert in ${NFT_REVERT_SECONDS}s (unit $REVERT_UNIT)"
    # 3. apply
    nft -f /etc/nftables.conf
    sysctl -qw net.ipv4.ip_forward=1
    install -o root -g root -m 0644 /dev/stdin /etc/sysctl.d/99-proteus.conf <<< "net.ipv4.ip_forward=1"
    # 4. repopulate sets that 'flush ruleset' emptied (the scar)
    /etc/proteus/bin/repopulate-wg-peers.sh 2>/dev/null || true
    systemctl start proteus-proton-api-whitelist.service 2>/dev/null || true
    # A full ruleset load repopulates client_pivot from the boot SEED file, which
    # encodes the failsafe direction, not the mode in force right now. The two
    # legitimately differ (failsafe=open + mode=isolated is the default shape), so
    # re-assert the configured MODE on top of the freshly seeded set — otherwise
    # applying while isolated would silently reopen the client->LAN pivot.
    systemctl restart proteus-client-isolation.service 2>/dev/null || true
    # 5. instruct
    log "APPLIED. Verify you still have SSH and (once bootstrapped) client egress,"
    log "then run:  sudo ./install/install.sh --confirm"
    log "If anything is wrong, it auto-reverts in ${NFT_REVERT_SECONDS}s."
}

confirm() {
    systemctl stop "${REVERT_UNIT}.timer" 2>/dev/null || true
    systemctl reset-failed "${REVERT_UNIT}.service" "${REVERT_UNIT}.timer" 2>/dev/null || true
    log "revert timer cancelled; ruleset kept"
}
