#!/usr/bin/env bash
# Queue the units that refill the nftables sets after a full ruleset load.
#
# Run by the nftables.service drop-in (etc/systemd/system/nftables.service.d/
# proteus.conf) after every start and every reload of /etc/nftables.conf. A full
# load empties every set and map it declares. This is the same refill list the
# installer runs after its own load (REPOPULATE_CMD in install/lib/apply.sh):
#
#   proteus-wg-peers.service             @wg_peers, from the slot state files
#   proteus-client-isolation.service     @client_pivot, back to the configured
#                                        mode (the load restored the boot seed)
#   proteus-proton-api-whitelist.service @proton_api
#   proteus-trusted-egress.service       @trusted_src, which has no seed at all
#
# @source_pin and @vpn_dispatch are not refilled: they hold the dispatcher's
# picks, and it makes new ones on each client's next flow.
set -euo pipefail

log() { printf '[%(%FT%T%z)T] proteus-nft-repopulate: %s\n' -1 "$*" >&2; }

# Boot, shutdown and rescue. systemd reports "initializing" until basic.target
# is up. nftables.service has no After= dependencies at all
# (DefaultDependencies=no adds no ordering, and Debian's unit names none), so it
# starts at the very beginning of boot and its one `nft -f` normally finishes
# before basic.target. The four units have default dependencies, which order
# them after basic.target, so none of them can have run yet. The enabled ones
# start after nftables in their normal boot order and refill their sets
# themselves. @wg_peers fills from vpnns-up.sh as each slot comes up, and
# @proton_api from the whitelist timer (OnBootSec=5min plus a random delay) or
# an earlier slot rotation, which starts the whitelist service. If a slow boot
# lets the load finish after basic.target, the state is already "starting" and
# the refill is queued as below. While the system is stopping, starting units
# only fights the shutdown. In rescue or emergency mode ("maintenance") the
# operator has chosen not to start services.
#
# "starting" is deliberately NOT skipped. systemd reports it until the boot's job
# queue first drains, and a slow unit, or a job a timer starts during boot, can
# keep it there long after the four units have run. apt-daily-upgrade can be
# one, when its Persistent= timer catches up at boot, and an nftables upgrade
# inside it runs try-restart. Skipping then would leave every set empty with
# nothing queued to refill it. Queueing costs nothing extra for a unit whose
# boot job is still pending: the new job merges into it.
state=$(systemctl is-system-running 2>/dev/null || true)
case "$state" in
    running|degraded|starting) ;;
    *)
        log "system state is '${state:-unknown}'; not queueing the set refill"
        exit 0
        ;;
esac

# Queue only units this box has. A missing or masked one makes systemctl exit
# non-zero, and a non-zero exit here should mean a refill could not be queued,
# not that the box predates a unit. A unit that is installed but NOT enabled is
# still queued. Fresh installs enable neither proteus-wg-peers.service nor
# proteus-proton-api-whitelist.service (vpnns-up.sh and the daily timer keep
# those sets filled during normal operation), yet after a full load nothing else
# refills either set soon, and the kill-switch lets WireGuard handshakes out
# only to addresses in @wg_peers. All four are safe to run at any time: each rebuilds its set from
# its own source of truth, and on a box that never paired a UDM
# proteus-trusted-egress.sh finds nothing configured and leaves the feature off.
present() {
    local u
    for u in "$@"; do
        if [[ "$(systemctl show -P LoadState "$u" 2>/dev/null || true)" == loaded ]]; then
            printf '%s\n' "$u"
        else
            log "$u is not installed; skipped"
        fi
    done
}

mapfile -t units < <(present proteus-wg-peers.service proteus-client-isolation.service \
    proteus-proton-api-whitelist.service proteus-trusted-egress.service)

# restart, never start, for all four. A `start` of proteus-wg-peers.service,
# which is RemainAfterExit=yes and so stays active, does nothing. The other
# three are RemainAfterExit=no, and a `start` would run one that is idle, but
# one that is already running (a web UI save, the whitelist timer, a slot
# rotation) merges the new start into the running start job and runs nothing
# more. If that run filled its set before this load, the set stays empty. A
# `restart` of an idle unit is a plain start; of a running one, systemd stops
# the run and starts a fresh one against the new ruleset. The scripts tolerate
# the stop: each rebuilds its set from scratch on the next run.
# proteus-trusted-egress.sh swaps @trusted_src in one nft transaction and adds
# every rule and route it needs before it removes a stale one (pref 90 before
# any pref-100 rule, and after the last one on the way out), so a kill at any
# point leaves a consistent rule set that the next run finishes, and the kernel
# drops its flock when the process dies.
#
# --no-block on every job, never a waiting call. This runs inside
# nftables.service's own start or reload job, and all four units are ordered
# After=nftables.service, so their jobs cannot begin until that job ends. A
# blocking `systemctl restart` here would wait for a job that is waiting for
# us, and the wait never times out: a oneshot unit has no start timeout by
# default. With --no-block systemctl returns once the jobs are queued, and they
# run in their usual order when nftables.service's job ends, right after this
# script returns.
#
# Running the refill scripts inline would not work either: they would run inside
# nftables.service's sandbox, where Debian's ProtectSystem=full makes /etc
# read-only, and proteus-client-isolation.sh writes its boot seed under
# /etc/proteus/nft.
if (( ${#units[@]} == 0 )); then
    log "none of the refill units is installed; nothing queued"
    exit 0
fi

# Every start of a unit counts against its start limit: a failed run and each
# automatic retry of it (Restart=on-failure), and every start or restart anyone
# queues, this helper's included. proteus-trusted-egress.service allows three a
# minute (StartLimitBurst=3); the other three have systemd's default of five in
# ten seconds. proteus-wg-peers.service is restarted on every load, so a few
# loads in a row reach it. Past the limit systemd refuses the start and nothing
# retries: an empty @wg_peers stops every WireGuard handshake at the
# kill-switch, and an empty @trusted_src drops the trusted VLAN's traffic over
# wg-udm. reset-failed clears the counter of every unit about to be queued. It
# queues no job, so it cannot deadlock.
systemctl reset-failed "${units[@]}" 2>/dev/null || true
if systemctl --no-block restart "${units[@]}"; then
    log "queued set refill: ${units[*]}"
else
    log "could not queue the whole set refill; see systemctl's error above"
    exit 1
fi
