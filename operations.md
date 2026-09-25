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

# 2. Arm the revert (cancels itself if we succeed)
sudo systemctl reset-failed nft-revert.timer nft-revert.service 2>/dev/null || true
sudo systemd-run --unit=nft-revert --on-active=900 \
    /usr/sbin/nft -f /etc/nftables.conf.pre-change

# 3. Apply the new ruleset
sudo cp /path/to/new.conf /etc/nftables.conf
sudo nft -f /etc/nftables.conf

# 4. Repopulate sets that flush ruleset empties
sudo /etc/proteus/bin/repopulate-wg-peers.sh
sudo systemctl start proteus-proton-api-whitelist.service

# 5. Test. If good:
sudo systemctl stop nft-revert.timer
# If bad, it reverts itself at T+15min. Don't manually hurry that.
```

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

# Tell dispatcher to re-read state
sudo systemctl kill -s HUP proteus-dispatcher.service
```

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

# Which slot is each client pinned to? (source_pin is the one that matters;
# vpn_dispatch is the per-destination fallback)
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
sudo systemctl kill -s HUP proteus-dispatcher.service
```

If a *staging* instance (`proton-N-s`) got orphaned because `rotate-slot.sh` was killed mid-attempt:

```bash
sudo /etc/proteus/bin/vpnns-down.sh proton-N-s
ip rule | grep "from 172.31.$((100+N)).1"   # should be empty; if not:
sudo ip rule del from "172.31.$((100+N)).1" lookup $((200+N))
sudo ip rule del fwmark $((0x64+N)) lookup $((200+N))
```

(Note the index math: staging index = `100 + slot_idx`, so fwmark `0x65..0x69` and table `201..205` for slots 1..5.)

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
3. Dispatcher crashed. `sudo systemctl status proteus-dispatcher`. `bypass` on the NFQUEUE rule means packets without a dispatcher are dropped by default policy — this is the safe behavior, not a bug.
4. UniFi IPS rule dropping SSH / client traffic from upstream. Toggle it off at the controller to confirm. The VM is not at fault — don't blame the kill-switch without evidence of output-chain drops.

## Before reporting success after a change

1. Ruleset counters sane (`nft-*-dropped` not climbing for normal traffic).
2. At least one full rotation cycle completed cleanly (watch `proteus-rotate-slot@proton-1.service` fire).
3. DNS resolution via both `127.0.0.1` and `172.16.1.5`.
4. A forwarded HTTPS connection from a client in 172.16.1.0/24 actually reaches the internet.
5. `ss -tnp | grep sshd` on the VM shows your live SSH source IP — narrowing any inbound rule without this check risks lockout, and has caused one before.
