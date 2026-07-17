#!/bin/bash
# Re-mint and swap the dns-6 tunnel. Triggered by dns-latency-check.sh or
# manually. Momentary DNS outage during swap (~2-3s) is accepted.
#
# Cooldown-gated: will refuse to rotate more than once per hour unless -f.
set -euo pipefail

FORCE=${FORCE:-0}
[[ ${1:-} == "-f" || ${1:-} == "--force" ]] && FORCE=1

AUTO_DIR=/etc/multivpn/wg/proton/auto
# DNS instance/index come from the installer-rendered env; fall back to the
# historical production values (dns-6 / index 6) so an un-migrated box works.
[[ -r /etc/multivpn/multivpn.env ]] && source /etc/multivpn/multivpn.env
SLOT="${MULTIVPN_DNS_INSTANCE:-dns-6}"
DNS_IDX="${MULTIVPN_DNS_INDEX:-6}"
STATE_MARK="/etc/multivpn/state/${SLOT}-rotate.last"
COOLDOWN=3600

log() { printf "[%(%FT%T%z)T] rotate-dns: %s\n" -1 "$*" >&2; }

if [[ $FORCE -eq 0 && -f $STATE_MARK ]]; then
    last=$(cat "$STATE_MARK")
    now=$(date +%s)
    delta=$((now - last))
    if [[ $delta -lt $COOLDOWN ]]; then
        log "cooldown: last rotation ${delta}s ago, skipping (use -f to override)"
        exit 0
    fi
fi

log "rotating $SLOT (FORCE=$FORCE)"

if ! /etc/multivpn/bin/proton-mint --slot $SLOT --out-dir $AUTO_DIR >/dev/null; then
    log "ERR: mint failed"
    exit 1
fi

new_conf=$(ls -1t $AUTO_DIR/$SLOT-*.conf | head -1)
log "minted: $new_conf"

/etc/multivpn/bin/vpnns-down.sh $SLOT || true
/etc/multivpn/bin/vpnns-up.sh "$SLOT" "$new_conf" "$DNS_IDX"
ln -sfn "$new_conf" "$AUTO_DIR/$SLOT.conf"

/etc/multivpn/bin/repopulate-wg-peers.sh

# Unbound binds a UDP socket to outgoing-interface 172.31.6.1 on v-dns-6. When
# we tore down and recreated the veth, that socket went stale — unbound keeps
# sending queries that never return. A restart rebinds cleanly. 1-2s DNS gap.
systemctl restart unbound

# Prune — keep newest 2 dns-6 mints
mapfile -t stale < <(ls -1t $AUTO_DIR/$SLOT-*.conf 2>/dev/null | tail -n +3)
for f in "${stale[@]}"; do
    log "pruned $f"
    rm -f "$f"
done

date +%s > "$STATE_MARK"
log "done: $SLOT -> $new_conf"
