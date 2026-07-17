#!/usr/bin/env bash
# Install staged files and apply networking behind an auto-reverting guard.
# Depends on common.sh + render.sh (STAGE dir already rendered).

REVERT_UNIT=multivpn-nft-revert
# Repo root: apply.sh lives at <repo>/install/lib/apply.sh. The runtime scripts
# the systemd units + rotation call all live under <repo>/etc/multivpn/bin and
# must be copied to /etc/multivpn/bin (the path every unit/doctor/apply expects).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

apply_files() {
    local stage=${1:?stage dir}
    # validate the rendered ruleset BEFORE it lands on disk (a bad render must
    # not sit at /etc/nftables.conf where a reboot would load it)
    nft -c -f "$stage/nftables.conf" || { die "rendered nftables failed nft -c; not installing"; return 1; }
    install -d -m 0755 /etc/multivpn /etc/multivpn/bin /etc/multivpn/state /var/log/multivpn /etc/unbound/unbound.conf.d
    install -o root -g root -m 0644 "$stage/multivpn.env" /etc/multivpn/multivpn.env
    install -o root -g root -m 0644 "$stage/unbound-multivpn-dns.conf" /etc/unbound/unbound.conf.d/multivpn-dns.conf
    install -o root -g root -m 0644 "$stage/nftables.conf" /etc/nftables.conf
    local u
    for u in "$stage"/multivpn-*.service "$stage"/multivpn-*.timer; do
        [[ -e "$u" ]] || continue
        install -o root -g root -m 0644 "$u" "/etc/systemd/system/$(basename "$u")"
    done
    # Runtime scripts/modules the units + rotation pipeline execute. Everything
    # in the repo bin/ (shell, python, extensionless) is installed executable;
    # the [[ -f ]] guard skips __pycache__ and any stray subdirs.
    local f
    for f in "$REPO_ROOT"/etc/multivpn/bin/*; do
        [[ -f "$f" ]] || continue
        install -o root -g root -m 0755 "$f" "/etc/multivpn/bin/$(basename "$f")"
    done
    log "staged files + systemd units + $(ls "$REPO_ROOT"/etc/multivpn/bin | grep -vc __pycache__) bin scripts installed"
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
    install -o root -g root -m 0644 /dev/stdin /etc/sysctl.d/99-multivpn.conf <<< "net.ipv4.ip_forward=1"
    # 4. repopulate sets that 'flush ruleset' emptied (the scar)
    /etc/multivpn/bin/repopulate-wg-peers.sh 2>/dev/null || true
    systemctl start multivpn-proton-api-whitelist.service 2>/dev/null || true
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
