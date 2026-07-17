# Operations

Log in as `admin@10.0.0.119` — NOPASSWD sudo. Every command below is from that account.

## Quick health check

```bash
# All five rotating slots + dns-6 handshaking
sudo systemctl is-active multivpn-dispatcher unbound
for n in 1 2 3 4 5 6; do
    ns=ns-proton-$n; [[ $n == 6 ]] && ns=ns-dns-6
    echo -n "$ns: "; sudo ip netns exec "$ns" wg show wg0 | grep "latest handshake"
done

# Dispatcher pool should list exactly 5 instances, no dns-6, no -s
sudo journalctl -u multivpn-dispatcher -n 5 --no-pager | grep -oE 'loaded .*instance.*'

# DNS working
dig @127.0.0.1 +short cloudflare.com A
dig @172.16.1.5 +short example.com A

# Kill-switch drop counter (should be near-zero in steady state)
sudo nft list chain inet filter output | grep output-dropped
```

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
sudo /etc/multivpn/bin/repopulate-wg-peers.sh
sudo systemctl start multivpn-proton-api-whitelist.service

# 5. Test. If good:
sudo systemctl stop nft-revert.timer
# If bad, it reverts itself at T+15min. Don't manually hurry that.
```

See `gotchas.md` → "nftables safety revert" for why not to rely on `nft -c` alone.

## Bootstrap Proton SSO (one-time + whenever token expires)

```bash
sudo /etc/multivpn/bin/proton-mint --bootstrap
# Prompts for Proton username, password, TOTP. Writes refresh token to
# /etc/Proton/ (0600, owned root). After this, rotation runs unattended
# until the refresh token expires (weeks-months typically).
```

Symptom of expired token: rotation logs "auth failed / 401 from /auth/v4". Re-run `--bootstrap`. There is **no** API key — Proton doesn't offer one, and the "OpenVPN/IKEv2 credentials" shown in the Proton dashboard are for tunnel auth only.

## Add or replace a slot

Rotation is automatic, but manual mint is occasionally needed:

```bash
# Mint a fresh config for slot N
sudo /etc/multivpn/bin/proton-mint --slot proton-3 --out-dir /etc/multivpn/wg/proton/auto

# Bring it up (or replace what's live)
sudo /etc/multivpn/bin/vpnns-up.sh proton-3 /etc/multivpn/wg/proton/auto/proton-3-<latest>.conf

# Tell dispatcher to re-read state
sudo systemctl kill -s HUP multivpn-dispatcher.service
```

## Force a rotation now (bypass the timer)

```bash
sudo systemctl start multivpn-rotate-slot@proton-4.service
sudo journalctl -u multivpn-rotate-slot@proton-4.service -f
```

Expect ~10-60s for mint + handshake + probes. On success you'll see "promoted" in the log.

## Diagnose a DNS failure

```bash
# Is unbound alive?
sudo systemctl status unbound

# Is dns-6 handshaking?
sudo ip netns exec ns-dns-6 wg show | grep handshake

# Does the tunnel reach Quad9?
sudo ip netns exec ns-dns-6 ping -c 3 9.9.9.9

# Is the fwmark/source-IP steering in place?
ip rule | grep -E '172.31.6.1|fwmark 0x6'
ip route show table 106

# Egress counter (should grow with query volume)
sudo nft list chain inet filter output | grep unbound-dns-egress

# Unbound internal stats
sudo unbound-control stats_noreset | grep -E 'cachehits|cachemiss|queries_timed_out|recursivereplies'
```

Occasional first-query timeouts (~1 in 20) are unbound's UDP retry budget on cold-cache + Proton+Quad9 RTT. `+time=5 +tries=2` on dig gets ~100% pass rate. Not worth tuning `infra-host-ttl` unless rate drops below ~90%.

### Manually rotate dns-6 (force past the cooldown)

```bash
sudo /etc/multivpn/bin/rotate-dns.sh -f
```

Use when you suspect the current dns-6 exit has a bad Quad9 path and don't want to wait for the 15-min timer. The automatic `multivpn-dns-latency.timer` handles the unattended case (rotates when `ns-dns-6 → 9.9.9.9` average RTT crosses 120ms, throttled to once per hour).

## Diagnose a client slot problem

```bash
# Is the slot's WG interface handshaking?
sudo ip netns exec ns-proton-N wg show

# Is its state file current?
cat /etc/multivpn/state/proton-N.state

# Are its ip rules in place?
ip rule | grep "fwmark 0x${N}"
ip route show table $((100+N))

# Is @wg_peers up-to-date?
sudo nft list set inet filter wg_peers

# What is the dispatcher mapping destinations to?
sudo nft list map inet filter vpn_dispatch | head -30

# Force a refresh of peer whitelist after any manual change
sudo /etc/multivpn/bin/repopulate-wg-peers.sh
```

## Recover from a total netns mess

```bash
# Wipe everything related to slot N and bring it back from scratch
sudo /etc/multivpn/bin/vpnns-down.sh proton-N
sudo /etc/multivpn/bin/vpnns-up.sh proton-N /etc/multivpn/wg/proton/auto/proton-N.conf
sudo systemctl kill -s HUP multivpn-dispatcher.service
```

If a *staging* instance (`proton-N-s`) got orphaned because `rotate-slot.sh` was killed mid-attempt:

```bash
sudo /etc/multivpn/bin/vpnns-down.sh proton-N-s
ip rule | grep "from 172.31.$((100+N)).1"   # should be empty; if not:
sudo ip rule del from "172.31.$((100+N)).1" lookup $((200+N))
sudo ip rule del fwmark $((0x64+N)) lookup $((200+N))
```

(Note the index math: staging index = `100 + slot_idx`, so fwmark `0x65..0x69` and table `201..205` for slots 1..5.)

## Rebuild dispatcher after code changes

`SIGHUP` re-reads **state files only**, not the Python source. Dispatcher code changes require a restart:

```bash
sudo systemctl restart multivpn-dispatcher.service
sudo journalctl -u multivpn-dispatcher.service -n 5 --no-pager
```

Confirm the pool count in the "loaded N VPN instance(s)" log line.

## Check rotation timer spread

```bash
systemctl list-timers 'multivpn-rotate-slot@proton-*.timer'
```

Good spread means the five slots rotate at different hours — if all cluster at the same time, reduce load by staggering the `Persistent=true` schedule (or just let `RandomizedDelaySec=12h` do its work over a few days).

## Inspect slot-health (Tier 1 / Tier 2 signals)

```bash
# Per-slot judgment by slot-warmup
for f in /run/multivpn-slot-health/proton-*.state; do
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
sudo tee /run/multivpn-slot-health/proton-3.state <<EOF
INSTANCE=proton-3
STATUS=degraded
LAST_OUTCOME=all_fail
LAST_PASS_AT=$(date +%s)
FAIL_STREAK=4
LAST_ROT_TRIGGER_AT=0
EOF

# 2. Hit a fresh destination from a client and confirm it didn't
#    map to mark 0x3:
#       claude@lantester $ curl -sI https://example.com/
sudo nft list map inet filter vpn_dispatch | grep example.com
# expected: a mark other than 0x00000003

# 3. The next slot-warmup pass (within 10s) overwrites the state
#    file with STATUS=ok if the slot is actually healthy. No cleanup needed.
```

## Diagnose "first connection to a fresh site is slow"

Symptom: LXC / VLAN client reports `tcp_connect` of 2-20s on the first HTTPS hit to a domain not seen recently; subsequent hits to the same host are fast. This is Proton's exit-side flow-state going cold after ~25-35s of no user-plane traffic per slot — the WG transport stays up but the first SYN through the cold path is dropped.

The `multivpn-slot-warmup.timer` (10s cadence) is the fix. Verify:

```bash
# Timer is running
systemctl list-timers multivpn-slot-warmup.timer --no-pager | head -3

# Recent passes — most slots should show code=200 connect<0.5s total<1.5s
sudo journalctl -t slot-warmup --since "2 min ago" --no-pager | tail -30
```

Some per-pass failures (code=000) are expected and benign — they're the warmup itself catching the cold window. What matters is that the *next* pass 10s later shows the slot warm again. If you see consistent fails on the same slot across many passes, that slot's Proton exit is actually bad — it'll be rotated out by the next `multivpn-rotate-slot@proton-N.timer` fire.

Measure the effect from an actual client (LXC on 172.16.1.0/24):

```bash
for host in openbsd.org apache.org python.org nginx.org gnu.org; do
    ip=$(dig +short $host A | head -1)
    curl -s -o /dev/null --resolve $host:443:$ip \
         -w "$host: connect=%{time_connect}  total=%{time_total}\n" \
         --max-time 15 https://$host/
done
```

Expect ≥80% of runs under 200ms TCP connect. If most are >2s, check `multivpn-slot-warmup.service` status and whether the timer is actually firing.

## Emergency: client VLAN is losing connectivity

Typical causes in order of likelihood:

1. `@wg_peers` got flushed by an `nft -f` without a follow-up `repopulate-wg-peers.sh`. Run it.
2. All five slots failed rotation in the same window. Check `journalctl -u 'multivpn-rotate-slot@*'` — the old slots should still be up since rotation is atomic, but if Proton's API is throwing 500s your mints are failing. Re-bootstrap SSO if auth errors; wait out API issues.
3. Dispatcher crashed. `sudo systemctl status multivpn-dispatcher`. `bypass` on the NFQUEUE rule means packets without a dispatcher are dropped by default policy — this is the safe behavior, not a bug.
4. UniFi IPS rule dropping SSH / client traffic from upstream. User has a toggle for it. The VM is not at fault — don't blame the kill-switch without evidence of output-chain drops.

## Before reporting success after a change

1. Ruleset counters sane (`nft-*-dropped` not climbing for normal traffic).
2. At least one full rotation cycle completed cleanly (watch `multivpn-rotate-slot@proton-1.service` fire).
3. DNS resolution via both `127.0.0.1` and `172.16.1.5`.
4. A forwarded HTTPS connection from a client in 172.16.1.0/24 actually reaches the internet.
5. `ss -tnp | grep sshd` on the VM shows your live SSH source IP — narrowing any inbound rule without this check risks lockout (user has been burned before).
