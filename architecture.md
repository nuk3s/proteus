# Architecture

## Why network namespaces per tunnel

Proton WireGuard configs all use the same inner subnet (`10.2.0.0/24`) with `AllowedIPs=0.0.0.0/0`. Running two Proton tunnels in one namespace collides on both the address and the default route. Per-netns isolation sidesteps this uniformly, and the same pattern applies cleanly to Mullvad when it's added later.

WireGuard interface creation follows the wireguard.com/netns pattern: `ip link add wg0 type wireguard` in the **main ns** so its encrypted UDP socket binds there (subject to the main-ns kill-switch), then `ip link set wg0 netns <ns>` moves the plaintext end into the target ns. The peer endpoint is added to `@wg_peers` **before** the interface comes up so the handshake is never dropped.

## Routing — how a client packet finds its tunnel

Inbound flow from `ens19`:

1. **prerouting_mangle** (priority mangle, -150). Filters out the packets we don't touch (non-client-VLAN, private destinations, multicast, etc.).
2. If the packet already has a ct mark → copy to meta mark, return. Flows stay on their tunnel even if the map entry expired.
3. Else look up `ip daddr map @vpn_dispatch`. Hit → use that mark, save to ct mark, return.
4. Miss + `ct state new` → **NFQUEUE 0**. Dispatcher picks a slot, inserts `(daddr, mark)` into the map with 12h timeout, re-injects.
5. After mark is set, `ip rule fwmark 0xN lookup 10N` routes to the per-slot veth → into `ns-proton-N` → out `wg0` (MASQUERADE on wg0 in the ns).

Return traffic follows the ct state established,related accept on the forward chain.

## The kill-switch

`/etc/nftables.conf` `chain output` (main ns) has policy **drop**. Locally-generated traffic must match one of:

- `oif lo`
- ct state established,related (so we answer returning flows without listing every peer)
- `ip daddr $RFC1918` — mgmt LAN, client VLAN, transit /30s
- icmp / icmpv6
- `oifname ens18 udp sport 68 dport 67` — dhcp client
- `oifname ens18 udp dport 51820 ip daddr @wg_peers` — WG handshakes / keepalives to active peers only
- `meta skuid "_apt" oifname ens18 tcp dport {80,443}` — apt fetches
- `meta skuid "systemd-timesync" oifname ens18 udp dport 123` — NTP
- `oifname ens18 tcp dport 443 ip daddr @proton_api` — Proton control-plane
- `meta skuid "unbound" meta mark 0x6 oifname v-dns-6` — DNS resolver to dedicated tunnel

Anything else is counter-logged (`nft-output-dropped`) and dropped. Packets generated *inside* a VPN netns traverse that ns's own output chain (policy accept), not this one.

## Reputation gating (rotation)

**Design:** run empirical probes from inside the staging netns. This tests the thing that actually matters — "does this exit IP behave like a normal user" — without leaking the correlation "mgmt IP queried reputation service about exit X" to any third party.

Two tiers:

- **Mandatory** (≥4 of 5 must PASS, max 1 ERROR, any BLOCK fails):
  - `api.github.com/zen` — GitHub's "zen" plaintext endpoint, simple and rarely blocked by legitimate ISPs.
  - `www.google.com/generate_204` — captive-portal probe that returns 204. Google aggressively blocks exits with bad reputation.
  - `duckduckgo.com/?q=…&format=json` — DuckDuckGo's JSON API. Blocks on bad rep; permissive on well-behaved VPN exits.
  - `www.cloudflare.com/` — accepts 200/301/302/308 (Cloudflare regional redirects are normal). Cloudflare TLS-resets exits with bad reputation, and a *huge* fraction of the consumer web sits behind Cloudflare — so an exit that fails Cloudflare is a user-visible disaster regardless of what `generate_204` says.
  - `www.youtube.com/` — accepts 200/3xx (YouTube geo-redirects are normal). Same logic as Cloudflare: the captive-portal probes are far more permissive than user-facing services. An exit that gets reset by YouTube means video streaming will visibly fail, so reject it at mint.
- **Advisory** (block → flag, don't fail):
  - `www.reddit.com/.json` — Reddit 403s a large fraction of Proton streaming exits by **policy, not reputation**. Treating this as mandatory would fail most candidates.

Each probe rotates through 5 user agents (Chrome/Windows, Safari/Mac, Firefox/Linux, Safari/iPhone, Chrome/Android) to avoid UA-based heuristic blocks. Before any probe runs, the script issues a single warmup `HEAD https://proton.me/` through the staging netns so the first real probe doesn't catch Proton's 25–35s exit-side cold window — without that, transient cold-catches falsely fail otherwise-good exits.

`rotate-slot.sh` does **mint-retry with N=5 attempts per rotation**. First passer is promoted. All-fail = leave the old slot alone; next timer fire tries again. AbuseIPDB is reserved as a fallback if empirical probes prove insufficient later.

## Health-aware dispatch (Tier 1)

Each `slot-warmup` pass writes a per-slot health file at `/run/multivpn-slot-health/proton-N.state`:

```
INSTANCE=proton-N
STATUS=ok|degraded
LAST_OUTCOME=ok|warmed|all_fail
LAST_PASS_AT=<unix-ts>
FAIL_STREAK=<int>
LAST_ROT_TRIGGER_AT=<unix-ts>
```

`STATUS=degraded` after `FAIL_STREAK >= DEGRADED_AFTER` (default 2 consecutive ALL_FAILs ≈ 20s of solid failure). Any single PASS resets `FAIL_STREAK=0` → `STATUS=ok`.

`dispatcher.py` picks a slot for each new client via `pick_distributed`: it takes the fresh, non-degraded slots scoring within `SPREAD_BAND` (default 40) of the current best — "slots that don't suck" — and assigns the **least-loaded** of those by current pin count, tie-breaking toward the higher score. This fans clients out across the strong slots (spreading bandwidth and handing each a distinct exit IP) instead of piling everyone onto the single top-scored slot. If no slot has a fresh score it falls back to a healthy random pick; if all are DEGRADED it rides the full pool with a warning. Only real client-VLAN sources are pinned (`is_pinnable_source` drops stray 0.0.0.0/off-VLAN packets). Existing sticky-map entries are unaffected (a source already pinned to slot N stays until its pin TTL expires or the janitor evicts it on degrade).

Effect: a transient ALL_FAIL window on one slot stops affecting NEW clients within ~10s of the warmup detecting it, and load spreads across the healthy slots as clients connect.

## Auto-rotation of persistently bad slots (Tier 2)

When `FAIL_STREAK >= ROT_THRESHOLD` (default 5 ≈ 50s of solid failure) and the per-slot cooldown has elapsed (default 300s), `slot-warmup.sh` invokes `systemctl start --no-block multivpn-rotate-slot@proton-N.service`. The cooldown prevents mint-storms when a slot is borderline. The 50s threshold is intentionally above the ~25-35s cold-window so a transient cold-catch doesn't trigger a rotation — only a slot that's been failing through multiple warmup passes (and presumably the dispatcher has already DEGRADED it for live traffic) gets evicted.

The rotation itself is the same code path as the daily timer — mint, stage, probe, promote — so the auto-trigger is just a faster heartbeat for "this exit is broken, find a new one" without waiting for the next scheduled rotation.

## DNS — dedicated tunnel

Separate `dns-6` Proton tunnel carrying DNS traffic only. Local unbound listens on `127.0.0.1` + `172.16.1.5` and forwards `.` to Quad9 (`9.9.9.9` + `149.112.112.112` — no Cloudflare per user preference).

Two mechanisms steer unbound's upstream queries into the dns-6 tunnel:

1. **Source-IP routing rule.** Unbound is configured with `outgoing-interface: 172.31.6.1` — the main-ns side of the dns-6 transit /30. `ip rule from 172.31.6.1 lookup 106 priority 406` (installed by `vpnns-up.sh`) routes any packet with that source via table 106 → `v-dns-6`. **This is the primary steering mechanism.**
2. **Fwmark stamp.** `chain output_route { type route hook output priority mangle; meta skuid "unbound" meta mark set 0x6; }` stamps unbound's packets with mark 0x6. The kill-switch then requires all three of `skuid=unbound`, `mark=0x6`, `oifname=v-dns-6` to accept the egress — defense-in-depth.

*Why both?* The route-hook reroute didn't work on this kernel (see `gotchas.md`). The source-IP rule is the reliable steering; the mark-stamp is retained purely so the kill-switch rule can require a three-way match for the accept.

`dns-6` is not part of the client-traffic rotation pool — the dispatcher's `_load_instances()` filters on `^proton-\d+$`. DNS survives slot rotation cleanly because it rides its own independent tunnel.

`dns-6` has its own separate rotation trigger: `multivpn-dns-latency.timer` fires every 15 min, measures `ns-dns-6 → 9.9.9.9` RTT, and calls `rotate-dns.sh` if latency exceeds 120ms. The cooldown in `rotate-dns.sh` (1h) prevents thrashing when no available exit has a good Quad9 path. The cold-DNS experience is dominated by tunnel RTT × qname-minimisation steps, so a faster exit directly shortens first-hit latency for users.

Per-netns resolv.conf files (`/etc/netns/ns-proton-N/resolv.conf`) also point at Quad9, so `ip netns exec` bind-mounts that over `/etc/resolv.conf` for reputation probes and anything else run inside a rotating netns — no leak to the mgmt network's resolver (which the kill-switch doesn't permit anyway).

## Rotation lifecycle

`multivpn-rotate-slot@proton-N.timer` (daily + 12h jitter, persistent) → `rotate-slot.sh N`:

1. For attempt in 1..5:
   1. `proton-mint --slot proton-N-s --out-dir /etc/multivpn/wg/proton/auto` → writes a fresh WG config using a brand-new keypair and a Proton API-registered peer selection.
   2. `vpnns-up.sh proton-N-s <conf> $((100 + N))` — stage under name `proton-N-s`, index `100+N` (so staging slots use fwmark `0x65..0x69`, table `201..205`, veth `v-proton-N-s`/`v-proton-N-s-ns` — fits in 15-char kernel veth name limit because the suffix is `-s`, not `-new`).
   3. Wait for handshake (poll `wg show` up to 30s).
   4. Egress probe: `ip netns exec ns-proton-N-s curl https://checkip.amazonaws.com --retry 3 --retry-all-errors --retry-delay 2 --max-time 12` (picked because Amazon doesn't rate-limit and returns the exit IP as plaintext — no TLS chain or JSON parsing to add a failure mode).
   5. `reputation-probe.sh ns-proton-N-s` — tiered verdict.
   6. Pass → `break`; Fail → cleanup staging (`vpnns-down.sh proton-N-s`, `rm` config), sleep, retry.
2. If no passer after 5 attempts → log + exit 2. Old slot untouched.
3. On passer:
   1. `vpnns-up.sh proton-N <new_conf>` — replace the live slot in place. Same fwmark/table/transit means `@vpn_dispatch` entries are still valid.
   2. `systemctl kill -s HUP multivpn-dispatcher` — re-read state (pool names haven't changed, just endpoint).
   3. Prune old `/etc/multivpn/wg/proton/auto/proton-N-*.conf` except the two most recent.

**Endpoint-collision dedup**: after mint, `rotate-slot.sh` parses the new
config's `Endpoint = X.X.X.X:51820` line and compares against
`WG_ENDPOINT_IP=` in every sibling `proton-N.state` file. On match, the
mint is discarded and the attempt is counted as a failure (the existing
5-retry loop handles it). Reason: two slots on the same Proton physical
server share an exit IP (privacy regression) AND share exit-side flow-
state, which silently degrades the warmup keepalive and reintroduces
cold-SYN drops. See `gotchas.md` → "Two slots on the same Proton physical
server degrade each other" for the full story.

**On client keypair freshness**: an earlier version of this design assumed
each `proton-mint` call would register a fresh client pubkey with Proton.
In practice the Proton API at `/vpn/v1/certificate` accepts a fresh pubkey
in the request body and signs a cert for it, but does NOT register that
pubkey with the WG edge — handshakes from a freshly-minted key fail.
`proton-mint` therefore reuses the account's pre-registered WG keypair
across all mints; only the chosen server endpoint changes per rotation
(see the comment block in `proton-mint` line ~131). Unlinkability across
rotations comes from the changing exit IP — and from the endpoint-collision
dedup above ensuring rotations actually produce a different IP — NOT from
a per-rotation client pubkey.

**Why 5 rotation attempts per timer fire**: mint latency is ~2-4s, handshake ~1-3s, probes ~5-15s. Five attempts is ~2 minutes worst-case, which is well inside `RandomizedDelaySec=12h`. Gives tolerance to a bad-reputation exit without aborting the daily rotation entirely.

## Stickiness vs rotation — why they coexist cleanly

The sticky map `@vpn_dispatch` maps `daddr → mark`, not `daddr → endpoint`. Rotation replaces the endpoint (WG peer) associated with a mark but leaves the mark itself alone. So:

- A flow to destination D got mark 3 this morning, went through the proton-3 slot.
- Midday, proton-3 rotates to a new Proton exit. `@vpn_dispatch[D] = 3` is untouched.
- A new flow to D this afternoon still maps to mark 3 → now goes out the new exit.
- Same destination, same slot, but a different IP on the exit side — the user's per-destination consistency is preserved semantically (same "lane") without pinning to a specific exit IP.

Conntrack provides the mid-stream safety: if a long-lived flow exists when the map entry expires, `meta mark set ct mark` in `prerouting_mangle` restores the mark from the flow's own ct state.

## Boot ordering

`nftables.service` loads ruleset → `multivpn-dns-tunnel.service` brings up dns-6 → `unbound.service` starts (Before relationship) → `multivpn-proton@proton-{1..5}.service` bring up the rotating slots (each `ExecStart=vpnns-up.sh %i /etc/multivpn/wg/proton/auto/%i.conf`, Before=`multivpn-dispatcher.service`) → `multivpn-dispatcher.service` binds NFQUEUE 0 with the 5-slot pool loaded. `multivpn-proton-api-whitelist.service` and `repopulate-wg-peers.sh` refresh the sets that `flush ruleset` empties. `multivpn-slot-warmup.timer` starts 45s after boot (once the pool is up) and fires every 10s to keep Proton's exit-side flow state warm.

The `proton-N.conf` stable symlink is what `multivpn-proton@.service` reads — `rotate-slot.sh` updates it on every successful promotion, so the next boot always picks up the most recently promoted config for each slot.

## Forward-chain ordering vs asymmetric client-to-mgmt flows

The VM is the default gateway for the client VLAN (172.16.1.0/24). The upstream switch (UniFi) also has an interface on that VLAN as the DHCP server, so when a host on the mgmt LAN (10.0.0.0/24) SSHes into a VLAN client, UniFi short-cuts the forward path directly to the VLAN — the VM never sees the SYN. The SYN-ACK, however, leaves the VLAN client through its default gateway (us) and has to forward out ens18 toward UniFi → mgmt.

From the VM's conntrack perspective this is a SYN-ACK with no prior SYN in the state table, which gets classified `ct state invalid` and would be dropped by the default hygiene rule. To allow the legitimate VLAN→RFC1918 transit, the forward chain places the `client-to-private` accept **before** `ct state invalid drop`. Internet-bound flows still hit the invalid drop after that, so the kill-switch story is intact; only RFC1918 transit is exempt.

UniFi won't let us install a non-/32 route via 172.16.1.5 (it holds the /24 for DHCP), so symmetric routing at the upstream isn't available. The forward-chain reorder is the pragmatic workaround.

## Cold-tunnel warmup

Observed behavior (empirical, confirmed with tcpdump on v-proton-N and wg0 inside the ns): if a Proton slot has no user-plane TCP activity for ~25-35s, the first SYN on the next client flow is silently dropped upstream of the WG tunnel, even though the WG handshake is fresh (PersistentKeepalive=25 keeps the *transport* alive; Proton's *exit-side* NAT/flow-state decays independently). TCP retries fix it in 2-20s at the cost of user-visible first-hit latency.

`multivpn-slot-warmup.service` fires every 10s (timer + 2s accuracy jitter). Each pass issues parallel `curl -I https://proton.me/` against every slot in the rotating pool (`^proton-\d+$`, matches the dispatcher filter, skips dns-6 and `-s` staging). proton.me is chosen because it's operated by Proton — they already see our WG handshake every 25s, so this keepalive adds no third-party correlation.

Parallelization matters. With a serial loop, a pass over 5 cold slots took ~20s (5 × 4s timeout), pushing per-slot re-hit interval past the cold threshold. Backgrounding the curls and `wait`-ing bounds wall time to the slowest single slot, so every slot gets refreshed every ~10s regardless of how many are momentarily cold.

Measured effect on fresh client connections (LXC curl to 8 unique public hostnames, sampled post-warmup steady-state): 7/8 under 200ms TCP connect. Before the warmup, the same test had all 5-8 destinations in the 2-20s range. The remaining occasional slow hit is tolerable — it lines up with Proton's 30-35s cold-cycle hitting the exact instant a client SYN goes out.
