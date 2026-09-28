# Operations

All commands below run on the gateway, as root via sudo.

## Quick health check

```bash
# All five rotating slots + dns-6 handshaking
sudo systemctl is-active proteus-dispatcher unbound
for n in 1 2 3 4 5 6; do
    ns=ns-proton-$n; [[ $n == 6 ]] && ns=ns-dns-6
    echo -n "$ns: "; sudo ip netns exec "$ns" wg show wg0 | grep "latest handshake"
done

# Dispatcher pool should list exactly 5 instances, no dns-6, no -s
sudo journalctl -u proteus-dispatcher -n 5 --no-pager | grep -oE 'loaded .*instance.*'

# DNS working
dig @127.0.0.1 +short cloudflare.com A
dig @172.16.1.5 +short example.com A

# Kill-switch drop counter (should be near-zero in steady state)
sudo nft list chain inet filter output | grep output-dropped

# Marked-egress guards. In steady state neither counter moves. Two operator
# actions raise marked_leak_fwd by design, because each briefly leaves an
# established trusted flow without its mark: a full `nft -f` reload, and
# removing a trusted range. Any other increase means a VPN-bound packet was
# routed somewhere other than a slot veth and the firewall stopped it; routing
# should have stopped it first. `sudo journalctl -k | grep nft-marked-leak`
# shows which interface (logging is rate-limited to 5 lines a second).
# own_icmp_err_tunnelled is NOT a leak signal: it counts the box's own ICMP
# errors about a tunnelled flow (a client left while a remote kept sending)
# that would have left off-tunnel, dropped in chain output by design. It moves
# in normal operation. One exception: on a box whose client or wg-udm MTU is
# below the tunnel MTU (1420), a value that climbs steadily can mean PMTU
# errors the remote never got. The rule's comment in /etc/nftables.conf says
# how to route those into the tunnel instead.
sudo nft list counters table inet filter

# Fail-closed routing (routeguard.sh): the catch rule, the ingress sink, and a
# blackhole sentinel at the end of every table a mark rule points at (listed
# after the real default route while the slot is up).
# The catch rule is `not fwmark 0x0/0xffffffff blackhole`. A line reading
# "not from all blackhole" (no "fwmark 0") is that rule typed without the mask:
# the kernel stored mark 0/mask 0, which matches nothing. Re-run
# routeguard.sh, which adds the masked rule; don't type it in by hand.
ip rule show pref 32000                  # "not from all fwmark 0 blackhole"
ip rule show pref 32020                  # "iif <client iface> lookup 900", "iif wg-udm lookup 900" ([detached] until wg-udm exists)
ip route show table 900                  # "default dev proteus-null"
for t in $(ip rule show | awk '/fwmark/ && /lookup/ {print $NF}' | sort -un); do
    echo "table $t: $(ip route show table "$t" | tr '\n' ';')"
done

# The ingress sink transmits nothing while nftables is loaded: chain forward
# drops unmarked client egress (unmarked-client-egress) before the sink's
# device ever sends it, and the box's own traffic never matches the sink's
# iif-keyed rules. So watch the DELTA, not the value: note TX packets now and
# compare later. Growth means packets got past chain forward to the sink (no
# ruleset, or an edited one). A proteus-null created before routeguard.sh
# turned IPv6 off on it can carry a nonzero baseline from router
# solicitations. Do NOT delete and recreate proteus-null to reset the count:
# deleting it removes table 900's route, and the sink falls through to main
# until routeguard.sh runs again.
ip -s link show proteus-null             # TX packets: same as your last reading
```

## Web UI

`https://<mgmt-ip>:8443/` (the cert is self-signed, so the browser warns on first visit). That's
expected; there's no public CA behind it (see architecture.md → "Web UI").

First-time setup, or resetting a lost passphrase:

```bash
sudo /etc/proteus/bin/proteus-ui-passwd
# interactive: prompts twice, no echo, refuses anything under 12 characters

# or scripted:
printf '%s\n' "$PASSPHRASE" | sudo /etc/proteus/bin/proteus-ui-passwd --stdin

sudo systemctl start proteus-ui.service
```

The installer enables `proteus-ui.service` but does not start it. Until a passphrase is set the
daemon refuses to start (there's no plaintext fallback), so on a fresh install (or after any
reboot before the first `proteus-ui-passwd` run) it will show up in `systemctl --failed`. That's
expected. Set the passphrase and start it; it won't self-recover on its own.

Pause/resume auto-rotation lives on the knobs tab. It writes/removes
`/etc/proteus/state/rotation-paused`; every rotation script checks that flag on entry. A
rotate-now from the UI always overrides the pause.

Every other knob write lands in `/etc/proteus/proteus-local.env`, an overlay sourced after
`proteus.env` that survives installer re-runs (`install.sh` never touches it). Most knobs apply on
the next warmup pass, rotation, or DNS check; no restart needed. Two under the Advanced group,
`PROTEUS_SPREAD_BAND` and `PROTEUS_PIN_TTL_S`, restart `proteus-dispatcher.service` when set,
which drops all current client pins; the UI shows a confirm step before sending those. The UI
does not display or edit DNS upstreams at all. Changing the gateway resolver means re-rendering
unbound's config from `UNBOUND_UPSTREAM` (and with it `UNBOUND_MODULE_CONFIG`, which decides
whether the validator runs), not writing an env var.

The privileged broker (`proteus-ui-apply.service`) listens on the unix socket
`/run/proteus/apply.sock`, group `proteus-ui`, socket-activated. The web daemon
(`proteus-ui.service`) holds no root; it can only ask the broker to act.

Logging posture: the UI writes no access log. Rotation history is RAM-only, capped at the last 50
events, and is lost on reboot. As of this feature the dispatcher no longer logs per-client flow
lines at the default level (moved to DEBUG); the box keeps no browsing trail by default.

## Deploy a config change to nftables safely

Always stage a revert timer before swapping the live ruleset. Fifteen minutes is long enough to test, short enough that a lockout self-recovers.

```bash
# 1. Snapshot known-good
sudo cp /etc/nftables.conf /etc/nftables.conf.pre-change

# 2. Arm the revert (cancels itself if we succeed). It copies the old file
#    back over /etc/nftables.conf, loads it, and repopulates exactly as step 4
#    does. Restoring the file matters as much as the load: step 3 overwrites
#    it, so a revert that only reloaded the ruleset would leave the new file
#    for the next boot to load. And a revert that fires unattended must not
#    leave @trusted_src empty or the client pivot in the wrong mode.
sudo systemctl reset-failed nft-revert.timer nft-revert.service 2>/dev/null || true
sudo systemd-run --unit=nft-revert --on-active=900 /bin/sh -c \
    'cp /etc/nftables.conf.pre-change /etc/nftables.conf && /usr/sbin/nft -f /etc/nftables.conf && { /etc/proteus/bin/repopulate-wg-peers.sh; systemctl restart proteus-proton-api-whitelist.service; systemctl restart proteus-client-isolation.service; /etc/proteus/bin/proteus-trusted-egress.sh; }'

# 3. Apply the new ruleset
sudo cp /path/to/new.conf /etc/nftables.conf
sudo nft -f /etc/nftables.conf

# 4. Repopulate what `flush ruleset` empties (the same list install/lib/apply.sh runs)
sudo /etc/proteus/bin/repopulate-wg-peers.sh
sudo systemctl restart proteus-proton-api-whitelist.service
sudo systemctl restart proteus-client-isolation.service   # re-asserts the isolation MODE over the boot seed
sudo /etc/proteus/bin/proteus-trusted-egress.sh           # @trusted_src has no seed at all

# 5. Test. If good:
sudo systemctl stop nft-revert.timer
# If bad, it reverts itself at T+15min: the old file is back in place and
# loaded. Don't manually hurry that.
```

A full reload also empties `@source_pin` and `@vpn_dispatch`. Established flows keep their slot (the mark lives in conntrack), but a client's next new flow is dispatched afresh and may get a different exit. Between steps 3 and 4 an established trusted flow has no mark and is dropped, which is what `marked_leak_fwd` counts. To change a few chains without either effect, load a delta file with no `flush ruleset` that runs `flush chain inet filter <chain>` and then redefines only those chains; sets and maps keep their contents. The revert in step 2 still reloads the whole old file, so if it fires you get both effects once.

`systemctl restart nftables` and `systemctl reload nftables` are safe on a box with the proteus drop-in, `/etc/systemd/system/nftables.service.d/proteus.conf` (the installer puts it there; `systemctl cat nftables` shows it last). Debian's stock unit runs `nft flush ruleset` as its ExecStop, so a stock restart, including the try-restart the nftables package runs on upgrade, leaves the box with no ruleset until the reload finishes, and with none at all if the reload fails. The drop-in clears that ExecStop. A restart or reload is then a single `nft -f /etc/nftables.conf`, and because the file starts with `flush ruleset` the kernel either swaps in the whole new ruleset or, if the file fails to load, keeps the old one with its sets intact.

After a successful load, `proteus-nft-repopulate.sh` queues the four refills from step 4 as their units: `proteus-wg-peers`, `proteus-client-isolation`, `proteus-proton-api-whitelist` and `proteus-trusted-egress`. They start as systemctl returns and run in the background, so the sets stay empty until each one finishes, and a failure shows in that unit's status and the journal rather than in systemctl's exit code: `journalctl -u nftables -u 'proteus-*' --since -5min`. Everything above about a full reload still applies: client pins are gone, and each client's next flow may get a different exit. With the new file in place, `sudo systemctl reload nftables` does steps 3 and 4 in one command, but a delta file is still the better tool for a small change. The helper queues nothing while `systemctl is-system-running` reports `initializing`, `stopping`, or `maintenance`. At boot, `initializing` is where the first load normally lands, and none of the refill units has run yet: the enabled ones start in their boot order, `vpnns-up.sh` adds each slot's endpoint to `@wg_peers` as the slot comes up, and the whitelist timer fills `@proton_api` (`OnBootSec=5min`, plus up to 30 minutes of `RandomizedDelaySec`) unless a slot rotation starts the whitelist service first. In rescue or emergency mode, run step 4 by hand if you need the sets.

With the drop-in, `systemctl stop nftables` leaves the ruleset loaded, and so does shutdown. The unit is inactive after a stop all the same, and the next start of any unit with `Wants=nftables.service` starts it again: a full load of whatever `/etc/nftables.conf` holds at that moment, then the refill. The four refill units all want it, so a web UI save (it restarts `proteus-trusted-egress`), the whitelist timer and every slot rotation (`rotate-slot.sh` starts the whitelist service) each trigger that load. Don't leave nftables stopped: run `sudo systemctl start nftables` once you are done. If you edit `/etc/nftables.conf` while it is stopped, whichever start comes next, yours or one of theirs, loads the new file with no revert timer armed, so arm one (steps 1 and 2) before you edit. If you really need the box with no ruleset, run `sudo nft flush ruleset` yourself. (The ingress sink in `routeguard.sh` keeps client traffic off the uplink even with no ruleset, but the box has no firewall while it lasts.) A box without the drop-in, such as one built by hand, still has Debian's behaviour: there, use `nft -f` and never `systemctl restart` or `stop`.

See `gotchas.md` → "nftables safety revert" for why not to rely on `nft -c` alone.

## Bootstrap Proton SSO (one-time + whenever token expires)

```bash
sudo /etc/proteus/bin/proton-mint --bootstrap
# Prompts for Proton username, password, TOTP. Writes refresh token to
# /etc/Proton/ (0600, owned root). After this, rotation runs unattended
# until the refresh token expires (weeks-months typically).
```

Symptom of expired token: rotation logs "auth failed / 401 from /auth/v4". Re-run `--bootstrap`. There is **no** API key — Proton doesn't offer one, and the "OpenVPN/IKEv2 credentials" shown in the Proton dashboard are for tunnel auth only.

## Add or replace a slot

Rotation is automatic, but manual mint is occasionally needed:

```bash
# Mint a fresh config for slot N
sudo /etc/proteus/bin/proton-mint --slot proton-3 --out-dir /etc/proteus/wg/proton/auto

# Bring it up (or replace what's live)
sudo /etc/proteus/bin/vpnns-up.sh proton-3 /etc/proteus/wg/proton/auto/proton-3-<latest>.conf

# Tell dispatcher to re-read state (main process only: the default
# --kill-who=all would also HUP its nft children and ExecStartPre)
sudo systemctl kill --kill-who=main --signal=HUP proteus-dispatcher.service
```

The signal handler only sets a flag. The next new flow or the janitor's next
pass (at most 60 s) applies it, so the "loaded N VPN instance(s)" log line can
lag the signal by up to a minute on a quiet VLAN. Each pick applies a pending
reload before it chooses, so a flow that arrives after the signal normally
gets the new list. For an instant it may not: a pick already under way when
the signal lands, or one that arrives while the janitor is mid-reload, uses
the previous list for that one decision.

## Force a rotation now (bypass the timer)

```bash
sudo systemctl start proteus-rotate-slot@proton-4.service
sudo journalctl -u proteus-rotate-slot@proton-4.service -f
```

Expect ~10-60s for mint + handshake + probes. On success you'll see "promoted" in the log.

## Diagnose a DNS failure

```bash
# Is unbound alive?
sudo systemctl status unbound

# Is dns-6 handshaking?
sudo ip netns exec ns-dns-6 wg show | grep handshake

# Does the tunnel reach Proton's in-tunnel resolver? (ICMP to 10.2.0.1 is not
# the client path — query it the way unbound does.)
sudo ip netns exec ns-dns-6 dig @10.2.0.1 . NS

# Is NetShield actually filtering? First returns nothing (NXDOMAIN), second an address.
dig +short @172.16.1.5 doubleclick.net
dig +short @172.16.1.5 cloudflare.com

# Is the fwmark/source-IP steering in place?
ip rule | grep -E '172.31.6.1|fwmark 0x6'
ip route show table 106

# Egress counter (should grow with query volume)
sudo nft list chain inet filter output | grep unbound-dns-egress

# Unbound internal stats
sudo unbound-control stats_noreset | grep -E 'cachehits|cachemiss|queries_timed_out|recursivereplies'
```

Occasional first-query timeouts are unbound's UDP retry budget on a cold cache: the tunnel RTT to `10.2.0.1` is 11-16ms, but qname-minimisation turns one cold name into several sequential upstream queries and any single lost UDP datagram costs a full retry. `+time=5 +tries=2` on dig gets ~100% pass rate. Not worth tuning `infra-host-ttl` unless rate drops below ~90%.

### Manually rotate dns-6 (force past the cooldown)

```bash
sudo /etc/proteus/bin/rotate-dns.sh -f
```

Use when you suspect the current dns-6 exit has a slow path to Proton's resolver and don't want to wait for the 15-min timer. The automatic `proteus-dns-latency.timer` handles the unattended case (rotates when a UDP `. NS` query from `ns-dns-6` to `10.2.0.1` crosses 150ms, throttled to once per hour). Restarting unbound is part of the rotation, so expect a 1-2s DNS gap and a cold cache afterward.

## Diagnose a client slot problem

```bash
# Is the slot's WG interface handshaking?
sudo ip netns exec ns-proton-N wg show

# Is its state file current?
cat /etc/proteus/state/proton-N.state

# Are its ip rules in place?
ip rule | grep "fwmark 0x${N}"
ip route show table $((100+N))

# Is @wg_peers up-to-date?
sudo nft list set inet filter wg_peers

# Which slot is each client pinned to? source_pin holds client-VLAN hosts;
# vpn_dispatch is their per-destination fallback, and the ONLY map for trusted
# traffic from wg-udm (the router masquerades, so it dispatches per destination)
sudo nft list map inet filter source_pin
sudo nft list map inet filter vpn_dispatch | head -30

# Force a refresh of peer whitelist after any manual change
sudo /etc/proteus/bin/repopulate-wg-peers.sh
```

## Recover from a total netns mess

```bash
# Wipe everything related to slot N and bring it back from scratch
sudo /etc/proteus/bin/vpnns-down.sh proton-N
sudo /etc/proteus/bin/vpnns-up.sh proton-N /etc/proteus/wg/proton/auto/proton-N.conf
sudo systemctl kill --kill-who=main --signal=HUP proteus-dispatcher.service
```

If a *staging* instance (`proton-N-s`) got orphaned because `rotate-slot.sh` was killed mid-attempt:

```bash
sudo /etc/proteus/bin/vpnns-down.sh proton-N-s
```

(Note the index math: staging index = `100 + slot_idx`, so fwmark `0x65..0x69` and table `201..205` for slots 1..5.)

A slot's two `ip rule`s **stay behind on purpose**, for staging and live slots alike. Live slot N has `from 172.31.N.1` at pref 400+N and `fwmark 0xN` at pref 500+N, both looking up table 100+N; its staging twin `proton-N-s` has `from 172.31.$((100+N)).1` at pref 500+N and `fwmark $((0x64+N))` at pref 600+N, looking up table 200+N. `vpnns-down.sh` leaves them pointing at a table that holds only `blackhole default`, so a stopped slot's traffic fails closed instead of falling through to `main`. Don't delete them by hand. If you do anyway, marked traffic falls to the `pref 32000 not fwmark 0x0/0xffffffff blackhole` catch rule, which is also closed, but you have removed one of the routing layer's defences for that slot. Never `ip route flush table 10N`/`20N`: an empty table is exactly the fall-through the fix removed. If a table ever lacks its sentinel, run `sudo /etc/proteus/bin/routeguard.sh 10N` (it also re-asserts the catch rule and the ingress sink).

## Rebuild dispatcher after code changes

`SIGHUP` re-reads **state files only**, not the Python source. Dispatcher code changes require a restart:

```bash
sudo systemctl restart proteus-dispatcher.service
sudo journalctl -u proteus-dispatcher.service -n 5 --no-pager
```

Confirm the pool count in the "loaded N VPN instance(s)" log line.

## Check rotation timer spread

```bash
systemctl list-timers 'proteus-rotate-slot@proton-*.timer'
```

Good spread means the five slots rotate at different hours — if all cluster at the same time, reduce load by staggering the `Persistent=true` schedule (or just let `RandomizedDelaySec=12h` do its work over a few days).

## Inspect slot-health (Tier 1 / Tier 2 signals)

```bash
# Per-slot judgment by slot-warmup
for f in /run/proteus-slot-health/proton-*.state; do
    echo "=== $(basename "$f" .state) ==="
    sudo cat "$f"
done

# Auto-rotations triggered by Tier 2 (FAIL_STREAK >= 5 + cooldown)
sudo journalctl -t slot-warmup --since "30 min ago" | grep -E "auto-rotation|ALL_FAIL"

# Confirm dispatcher is honoring DEGRADED state. From a fresh client,
# new flows should never be assigned to a slot whose state file says
# STATUS=degraded:
sudo nft list map inet filter vpn_dispatch | head -20
```

Smoke-test the dispatcher's filter without breaking anything:

```bash
# 1. Mark proton-3 as degraded for ~10s
sudo tee /run/proteus-slot-health/proton-3.state <<EOF
INSTANCE=proton-3
STATUS=degraded
LAST_OUTCOME=all_fail
LAST_PASS_AT=$(date +%s)
FAIL_STREAK=4
LAST_ROT_TRIGGER_AT=0
EOF

# 2. Hit a fresh destination from a client and confirm it didn't
#    map to mark 0x3:
#       from a VLAN client:  curl -sI https://example.com/
sudo nft list map inet filter vpn_dispatch | grep example.com
# expected: a mark other than 0x00000003

# 3. The next slot-warmup pass (within 10s) overwrites the state
#    file with STATUS=ok if the slot is actually healthy. No cleanup needed.
```

## Diagnose "first connection to a fresh site is slow"

Symptom: LXC / VLAN client reports `tcp_connect` of 2-20s on the first HTTPS hit to a domain not seen recently; subsequent hits to the same host are fast. This is Proton's exit-side flow-state going cold after ~25-35s of no user-plane traffic per slot — the WG transport stays up but the first SYN through the cold path is dropped.

The `proteus-slot-warmup.timer` (10s cadence) is the fix. Verify:

```bash
# Timer is running
systemctl list-timers proteus-slot-warmup.timer --no-pager | head -3

# Recent passes — most slots should show code=200 connect<0.5s total<1.5s
sudo journalctl -t slot-warmup --since "2 min ago" --no-pager | tail -30
```

Some per-pass failures (code=000) are expected and benign — they're the warmup itself catching the cold window. What matters is that the *next* pass 10s later shows the slot warm again. If you see consistent fails on the same slot across many passes, that slot's Proton exit is actually bad — it'll be rotated out by the next `proteus-rotate-slot@proton-N.timer` fire.

Measure the effect from an actual client (LXC on 172.16.1.0/24):

```bash
for host in openbsd.org apache.org python.org nginx.org gnu.org; do
    ip=$(dig +short $host A | head -1)
    curl -s -o /dev/null --resolve $host:443:$ip \
         -w "$host: connect=%{time_connect}  total=%{time_total}\n" \
         --max-time 15 https://$host/
done
```

Expect ≥80% of runs under 200ms TCP connect. If most are >2s, check `proteus-slot-warmup.service` status and whether the timer is actually firing.

## Emergency: client VLAN is losing connectivity

Typical causes in order of likelihood:

1. `@wg_peers` got flushed by an `nft -f` without a follow-up `repopulate-wg-peers.sh`. Run it.
2. All five slots failed rotation in the same window. Check `journalctl -u 'proteus-rotate-slot@*'` — the old slots should still be up since a failed rotation leaves the incumbent exit in place, but if Proton's API is throwing 500s your mints are failing. Re-bootstrap SSO if auth errors; wait out API issues.
3. Dispatcher crashed. `sudo systemctl status proteus-dispatcher`. `bypass` on the NFQUEUE rule means that with no dispatcher listening, a new flow's first packet goes on unmarked, and chain forward drops it at `unmarked-client-egress` (that rule's counter climbs while the dispatcher is down) — this is the safe behavior, not a bug.
4. UniFi IPS rule dropping SSH / client traffic from upstream. Toggle it off at the controller to confirm. The VM is not at fault — don't blame the kill-switch without evidence of output-chain drops.

## Before reporting success after a change

1. Ruleset counters sane (`nft-*-dropped` not climbing for normal traffic).
2. At least one full rotation cycle completed cleanly (watch `proteus-rotate-slot@proton-1.service` fire).
3. DNS resolution via both `127.0.0.1` and `172.16.1.5`.
4. A forwarded HTTPS connection from a client in 172.16.1.0/24 actually reaches the internet.
5. `ss -tnp | grep sshd` on the VM shows your live SSH source IP — narrowing any inbound rule without this check risks lockout, and has caused one before.
