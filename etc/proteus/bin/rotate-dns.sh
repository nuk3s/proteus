#!/bin/bash
# Re-mint and swap the dns-6 tunnel. Triggered by dns-latency-check.sh or
# manually. Momentary DNS outage during swap (~2-3s) is accepted.
#
# Cooldown-gated: will refuse to rotate more than once per hour unless -f.
set -euo pipefail

FORCE=${FORCE:-0}
[[ ${1:-} == "-f" || ${1:-} == "--force" ]] && FORCE=1

AUTO_DIR=/etc/proteus/wg/proton/auto
# DNS instance/index come from the installer-rendered env; fall back to the
# historical production values (dns-6 / index 6) so an un-migrated box works.
[[ -r /etc/proteus/proteus.env ]] && source /etc/proteus/proteus.env
# UI-set overrides survive installer re-runs
[ -f /etc/proteus/proteus-local.env ] && . /etc/proteus/proteus-local.env
# shellcheck source=/dev/null
. /etc/proteus/bin/history.sh
SLOT="${PROTEUS_DNS_INSTANCE:-dns-6}"
DNS_IDX="${PROTEUS_DNS_INDEX:-6}"
STATE_MARK="/etc/proteus/state/${SLOT}-rotate.last"
COOLDOWN="${PROTEUS_DNS_ROTATE_COOLDOWN:-3600}"

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

# Read before this rotation overwrites it, for the history row below.
OLD_LOGICAL=$(grep -s '^LOGICAL_NAME=' "/etc/proteus/state/$SLOT.meta" | cut -d= -f2- || true)

if ! /etc/proteus/bin/proton-mint --slot $SLOT --out-dir $AUTO_DIR >/dev/null; then
    log "ERR: mint failed"
    exit 1
fi

new_conf=$(ls -1t $AUTO_DIR/$SLOT-*.conf | head -1)
log "minted: $new_conf"

# Snapshot the resolver cache before touching the tunnel: clients depend on
# it (serve-stale), and the restart below used to wipe it on every rotation.
CACHE_DUMP=$(mktemp /tmp/unbound-cache-dump.XXXXXX)
unbound-control dump_cache > "$CACHE_DUMP" 2>/dev/null || true

/etc/proteus/bin/vpnns-down.sh $SLOT || true
/etc/proteus/bin/vpnns-up.sh "$SLOT" "$new_conf" "$DNS_IDX"
ln -sfn "$new_conf" "$AUTO_DIR/$SLOT.conf"

# Display metadata: $new_conf was minted by the same proton-mint used for the
# proton-N slots, so it carries the same "# logical=" / "# exit_country="
# header comments — parse those for the history row and the .meta sidecar.
# SECURITY: same rule as rotate-slot.sh — this is third-party (Proton) data,
# so it goes ONLY into the .meta sidecar, never the .state file (.state is
# dot-sourced as root by repopulate-wg-peers.sh/vpnns-down.sh). Strip control
# chars as defense in depth.
NEW_LOGICAL=$(sed -n 's/^# logical=//p' "$new_conf" | head -n1)
new_country=$(sed -n 's/^# exit_country=//p' "$new_conf" | head -n1)
logical_clean=$(printf '%s' "$NEW_LOGICAL" | tr -d '\000-\037')
country_clean=$(printf '%s' "$new_country" | tr -d '\000-\037')
meta="/etc/proteus/state/$SLOT.meta"
{
    echo "LOGICAL_NAME=$logical_clean"
    echo "EXIT_COUNTRY=$country_clean"
    echo "MINTED_AT=$(date -Is)"
} > "$meta"
chgrp proteus-ui "$meta" 2>/dev/null || true
chmod 640 "$meta" 2>/dev/null || true
history_append "$SLOT" "${OLD_LOGICAL:-?}" "${logical_clean:-?}" "dns-latency" "promoted" "1"

/etc/proteus/bin/repopulate-wg-peers.sh

# Unbound binds its outgoing socket to the dns transit IP on the veth. When
# we tore down and recreated the veth, that socket went stale — unbound keeps
# sending queries that never return. A restart rebinds cleanly. 1-2s DNS gap.
systemctl restart unbound

# Reload the pre-rotation cache once the control socket is back.
for _i in 1 2 3 4 5; do
    unbound-control status >/dev/null 2>&1 && break
    sleep 1
done
if [[ -s "$CACHE_DUMP" ]]; then
    if unbound-control load_cache < "$CACHE_DUMP" >/dev/null 2>&1; then
        log "restored resolver cache across restart"
    else
        log "WARN: cache restore failed (starting cold)"
    fi
fi
rm -f "$CACHE_DUMP"

# Prune — keep newest 2 dns-6 mints
mapfile -t stale < <(ls -1t $AUTO_DIR/$SLOT-*.conf 2>/dev/null | tail -n +3)
for f in "${stale[@]}"; do
    log "pruned $f"
    rm -f "$f"
done

date +%s > "$STATE_MARK"
log "done: $SLOT -> $new_conf"
