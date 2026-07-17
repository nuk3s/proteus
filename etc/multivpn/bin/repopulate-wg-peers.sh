#!/usr/bin/env bash
# Re-populate the nftables wg_peers set from /etc/multivpn/state/*.state.
# Run after nftables.service loads (e.g. on boot) — the set is declared empty
# in /etc/nftables.conf and is populated live by vpnns-up.sh during the day.

set -u

shopt -s nullglob

for st in /etc/multivpn/state/*.state; do
    # shellcheck disable=SC1090
    WG_ENDPOINT_IP=""
    . "$st"
    if [[ -z "${WG_ENDPOINT_IP:-}" && -n "${WG_CONF:-}" && -r "$WG_CONF" ]]; then
        WG_ENDPOINT_IP=$(awk -F'= *' '
            /^Endpoint[[:space:]]*=/ {
                ep=$2; gsub(/[[:space:]]/,"",ep)
                if (ep ~ /^\[/) next
                sub(/:[0-9]+$/, "", ep)
                print ep; exit
            }
        ' "$WG_CONF")
    fi
    if [[ -n "${WG_ENDPOINT_IP:-}" ]]; then
        nft "add element inet filter wg_peers { ${WG_ENDPOINT_IP} }" 2>/dev/null || true
    fi
done
