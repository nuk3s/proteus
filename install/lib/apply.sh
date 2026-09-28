#!/usr/bin/env bash
# Install staged files and apply networking behind an auto-reverting guard.
# Depends on common.sh + render.sh (STAGE dir already rendered).

REVERT_UNIT=proteus-nft-revert
# The installed ruleset and the two copies the revert unit restores from: the
# running ruleset as apply_network found it, and the file apply_files
# replaced. Plain variables so install/tests can point them at a scratch
# directory; nothing else sets them.
NFT_CONF=/etc/nftables.conf
NFT_SNAPSHOT=/etc/nftables.conf.pre-install
NFT_PRIOR_FILE=/etc/nftables.conf.pre-install-file
# Dropped by the revert unit as its first act, so confirm() can tell "the
# revert already fired" (its transient timer is gone either way) from "armed".
NFT_REVERTED_MARK=/run/proteus-nft-reverted
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
    # Keep the file this replaces, for the revert unit to put back (see
    # apply_network). With no file to keep, drop any copy an earlier install
    # left, so a revert never restores a file older than the one it replaced.
    if [[ -e "$NFT_CONF" ]]; then
        cp -a "$NFT_CONF" "$NFT_PRIOR_FILE" \
            || { die "could not keep a copy of $NFT_CONF at $NFT_PRIOR_FILE; not installing"; return 1; }
    else
        rm -f "$NFT_PRIOR_FILE"
    fi
    install -o root -g root -m 0644 "$stage/nftables.conf" "$NFT_CONF"
    local u
    for u in "$stage"/proteus-*.service "$stage"/proteus-*.timer "$stage"/proteus-*.socket; do
        [[ -e "$u" ]] || continue
        install -o root -g root -m 0644 "$u" "/etc/systemd/system/$(basename "$u")"
    done
    install_repo_files
    log "staged files + systemd units + drop-ins + $(find "$REPO_ROOT"/etc/proteus/bin -maxdepth 1 -type f | wc -l) bin scripts installed"

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

# Files that go on the box exactly as they are in the repo: nothing to render.
# A function of its own so a test can run it with `install` stubbed; apply_files
# has absolute-path side effects a test must not trigger.
install_repo_files() {
    # Runtime scripts/modules the units + rotation pipeline execute. Everything
    # in the repo bin/ (shell, python, extensionless) is installed executable;
    # the [[ -f ]] guard skips __pycache__ and any stray subdirs.
    local f d
    for f in "$REPO_ROOT"/etc/proteus/bin/*; do
        [[ -f "$f" ]] || continue
        install -o root -g root -m 0755 "$f" "/etc/proteus/bin/$(basename "$f")"
    done
    # Drop-ins for units proteus does not own, today nftables.service.d/
    # proteus.conf: it turns `systemctl restart nftables` into an atomic reload
    # plus a set refill instead of a flush (see the file). No template: there is
    # nothing to substitute, and a copy under install/templates would be one more
    # thing to drift. systemd picks it up the next time it loads
    # nftables.service: at the daemon-reload in enable_services (--confirm) at
    # the latest, or earlier on a fresh install, where apply_network's
    # `systemctl start` of a unit that Wants=nftables.service loads and starts
    # it. Live that early is fine: the helper only queues jobs (--no-block), so
    # apply_network's own blocking systemctl calls cannot deadlock on it.
    for f in "$REPO_ROOT"/etc/systemd/system/*.d/*.conf; do
        [[ -f "$f" ]] || continue
        d="/etc/systemd/system/$(basename "$(dirname "$f")")"
        install -d -o root -g root -m 0755 "$d"
        install -o root -g root -m 0644 "$f" "$d/$(basename "$f")"
    done
}

# The sets a full ruleset load empties, refilled from their sources of truth.
# Shared by apply_network and by the revert unit, so a revert that fires
# unattended leaves the box in the same state a successful apply would.
# restart, not start, for the whitelist: a start merges into a run already in
# progress, which may have filled @proton_api before the load emptied it.
REPOPULATE_CMD='/etc/proteus/bin/repopulate-wg-peers.sh; systemctl restart proteus-proton-api-whitelist.service; systemctl restart proteus-client-isolation.service; /etc/proteus/bin/proteus-trusted-egress.sh'

apply_network() {
    # 1. snapshot known-good. `nft list ruleset` has no `flush ruleset` line,
    # and without one `nft -f` of the snapshot is ADDITIVE: it appends the old
    # rules after the new ones and leaves every new chain in place, so the
    # revert below would change nothing that matters. Hence the prefix.
    # A listing that FAILS is no snapshot. A revert armed on it would load
    # `flush ruleset` plus whatever part of the listing got written, and take
    # a box with a working ruleset down to nothing, so stop before arming
    # anything. An EMPTY listing is different: a fresh box has no ruleset, and
    # a snapshot of just `flush ruleset` reverts it to exactly that. Written
    # aside and moved into place, so a failed listing never replaces the
    # previous snapshot.
    local snap_tmp="$NFT_SNAPSHOT.tmp"
    if ! { echo 'flush ruleset'; nft list ruleset; } > "$snap_tmp"; then
        rm -f "$snap_tmp"
        # Nothing is applied, so the file apply_files replaced goes back too:
        # otherwise the next boot would load the new ruleset with no revert.
        [[ -e "$NFT_PRIOR_FILE" ]] && cp -a "$NFT_PRIOR_FILE" "$NFT_CONF"
        die "could not snapshot the running ruleset (nft list ruleset, into $snap_tmp); no revert armed, nothing applied, running ruleset untouched"
        return 1
    fi
    mv -f "$snap_tmp" "$NFT_SNAPSHOT"
    # 2. arm self-cancelling revert: put back the file apply_files replaced,
    # restore the pre-install ruleset, then repopulate exactly as step 4 does.
    # The file matters as much as the running ruleset: without it, a reboot
    # after a revert loads the very ruleset the revert backed out. Whatever was
    # there comes back, and on Debian that is usually the nftables package's
    # stock accept-all table, which is why confirm() refuses once the revert
    # has fired. With no previous file at all the new one stays. Deleting it
    # would boot the box with no ruleset while 99-proteus.conf (step 3) still
    # turns forwarding on: a plain router.
    local restore_file=""
    if [[ -e "$NFT_PRIOR_FILE" ]]; then
        restore_file="cp -a $NFT_PRIOR_FILE $NFT_CONF; "
    fi
    systemctl reset-failed "${REVERT_UNIT}.service" "${REVERT_UNIT}.timer" 2>/dev/null || true
    rm -f "$NFT_REVERTED_MARK"
    systemd-run --unit="$REVERT_UNIT" --on-active="${NFT_REVERT_SECONDS}" \
        /bin/sh -c "touch $NFT_REVERTED_MARK; ${restore_file}/usr/sbin/nft -f $NFT_SNAPSHOT && { $REPOPULATE_CMD; }"
    log "armed revert in ${NFT_REVERT_SECONDS}s (unit $REVERT_UNIT)"
    # 3. apply. Checked here rather than left to `set -e`: the wizard
    # (install/proteus) runs without it and goes by this function's status.
    nft -f "$NFT_CONF" \
        || { die "nft -f $NFT_CONF failed; the old ruleset is still loaded and the revert armed above fires in ${NFT_REVERT_SECONDS}s"; return 1; }
    sysctl -qw net.ipv4.ip_forward=1
    # fwmark_reflect stays at the kernel default (0), pinned here because the
    # box's own replies to clients depend on it: with it on, the ICMP errors
    # and TCP RSTs the box sends to a client inherit the flow's mark, and
    # policy routing sends them into the slot tunnel instead of straight back
    # out the client interface. The guards do not stop them (a slot veth is an
    # allowed way out), so nothing counts it either.
    sysctl -qw net.ipv4.fwmark_reflect=0
    install -o root -g root -m 0644 /dev/stdin /etc/sysctl.d/99-proteus.conf <<< $'net.ipv4.ip_forward=1\nnet.ipv4.fwmark_reflect=0'
    # 4. repopulate sets that 'flush ruleset' emptied (the scar). Keep in step
    # with REPOPULATE_CMD above.
    /etc/proteus/bin/repopulate-wg-peers.sh 2>/dev/null || true
    systemctl restart proteus-proton-api-whitelist.service 2>/dev/null || true
    # A full ruleset load repopulates client_pivot from the boot SEED file, which
    # encodes the failsafe direction, not the mode in force right now. The two
    # legitimately differ (failsafe=open + mode=isolated is the default shape), so
    # re-assert the configured MODE on top of the freshly seeded set — otherwise
    # applying while isolated would silently reopen the client->LAN pivot.
    systemctl restart proteus-client-isolation.service 2>/dev/null || true
    # @trusted_src has no seed file, so the same flush leaves it empty and its
    # reconcile otherwise runs only at boot: re-applying on a box that HAS paired
    # a UDM would silently switch trusted egress off until the next reboot. The
    # script, not the unit — on a fresh install the unit file has only just been
    # copied and daemon-reload doesn't happen until --confirm. Unpaired boxes get
    # a no-op (an empty list is a complete teardown).
    /etc/proteus/bin/proteus-trusted-egress.sh \
        || warn "trusted egress not reconciled; @trusted_src stays empty (feature off) until proteus-trusted-egress.service runs"
    # 5. fail-closed routing (routeguard.sh): the catch rule, the ingress sink,
    # and a sentinel in every table a slot state file names. On an upgrade the
    # slot units are already active, so `enable --now` would not re-run them,
    # and the routing layer would otherwise wait for each slot's next rebuild.
    # shellcheck disable=SC2046
    /etc/proteus/bin/routeguard.sh $(awk -F= '/^RT_TABLE=[0-9]+$/ {print $2}' /etc/proteus/state/*.state 2>/dev/null) \
        || warn "routeguard.sh reported a problem; the firewall guards still apply. Re-run it by hand to see why."
    # 6. instruct
    log "APPLIED. Verify you still have SSH and (once bootstrapped) client egress,"
    log "then run:  sudo ./install/install.sh --confirm"
    log "If anything is wrong, it auto-reverts in ${NFT_REVERT_SECONDS}s."
}

confirm() {
    # Stop first, then look: once the timer is stopped nothing can start the
    # revert, so the check below cannot race it.
    systemctl stop "${REVERT_UNIT}.timer" 2>/dev/null || true
    # If the revert already fired, the old ruleset and file are back (on a
    # fresh Debian box, the package's accept-all table) and "ruleset kept"
    # would be false: every later step (services, mint) would build on a box
    # with no kill-switch, and each boot would load the old file.
    if [[ -e "$NFT_REVERTED_MARK" ]] || systemctl is-active --quiet "${REVERT_UNIT}.service" 2>/dev/null; then
        die "the auto-revert already ran: the previous ruleset and $NFT_CONF are back. Re-run the install to apply again."
        return 1
    fi
    systemctl reset-failed "${REVERT_UNIT}.service" "${REVERT_UNIT}.timer" 2>/dev/null || true
    log "revert timer cancelled; ruleset kept"
}
