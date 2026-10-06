# Architecture

## Why network namespaces per tunnel

Proton WireGuard configs all use the same inner subnet (`10.2.0.0/24`) with `AllowedIPs=0.0.0.0/0`. Running two Proton tunnels in one namespace collides on both the address and the default route. Per-netns isolation sidesteps this uniformly, and the same pattern applies cleanly to Mullvad when it's added later.

WireGuard interface creation follows the wireguard.com/netns pattern: `ip link add wg0 type wireguard` in the **main ns** so its encrypted UDP socket binds there (subject to the main-ns kill-switch), then `ip link set wg0 netns <ns>` moves the plaintext end into the target ns. The peer endpoint is added to `@wg_peers` **before** the interface comes up so the handshake is never dropped.

## Routing — how a client packet finds its tunnel

Inbound flow from `ens19`:

1. **prerouting_mangle** (priority mangle, -150). Filters out the packets we don't touch (non-IPv4, not from the client VLAN or a trusted source on `wg-udm`, private destinations, multicast, etc.).
2. If the packet already has a ct mark → copy to meta mark, return. Flows stay on their tunnel even if the map entries expired.
3. Else look up `ip saddr map @source_pin` (the per-client pin). Hit → use that mark, save to ct mark, return. This is what makes every flow from one device leave through the same exit.
4. Else look up `ip daddr map @vpn_dispatch` (per-destination fallback). Hit → same.
5. Miss + `ct state new` → **NFQUEUE 0**. The dispatcher picks a slot (`pick_distributed`, below), pins the source in `@source_pin` for `PROTEUS_PIN_TTL_S` (default 6h), records `(daddr, mark)` in `@vpn_dispatch` (12h), sets the mark, re-injects. The verdict sets the packet mark; `chain prerouting_ctsave`, the next chain on the hook, copies it into the ct mark so the rest of the flow keeps it even if the map insert failed. If the key is already in the map with another mark (two new flows from one host raced through the queue), nft keeps the old mark, and the dispatcher reads it back and verdicts with it, so the host and the flow stay on one exit.
6. After mark is set, `ip rule fwmark 0xN lookup 10N` routes to the per-slot veth → into `ns-proton-N` → out `wg0` (MASQUERADE on wg0 in the ns).

Trusted traffic arriving on `wg-udm` (see Trusted-VLAN egress below) takes the same path minus step 3: the router masquerades, so every trusted host shares one source address and a pin would carry nothing. It dispatches per destination, `@vpn_dispatch` is its primary map, and the dispatcher writes it no source pin. Each decision is balanced against the map it lands in.

The dispatcher re-reads the slot list on SIGHUP (rotate-slot.sh sends one after every promotion, vpnns-up.sh and vpnns-down.sh whenever a live slot comes up or stops). The handler only sets a flag; the reload happens at the next pick or janitor pass, because the handler can fire while the dispatcher already holds its own lock (see `_install_signal_handlers` in `dispatcher.py`). Two re-reads cover a lost signal. The janitor (every 60 s) re-reads the list itself, so a slot that comes back with no SIGHUP is used again within a minute; a read that finds no slot at all is ignored there. And while the list is empty (the only slot, or every slot, restarting), each new flow is dropped, so a new flow re-reads it too, at most once a second.

The janitor also drains the map entries of a slot that has stopped or been removed: those lead to the slot's blackhole sentinel, and a pinned client would hang until its pin expired. It waits until two passes in a row find no state file for the mark, since a restart is gone for a few seconds only, and it only ever removes live-slot marks (0x1-0x63, never the DNS tunnel's). A degraded slot's entries are evicted too, on the first pass.

Return traffic follows the ct state established,related accept on the forward chain.

**VPN-bound traffic fails closed.** A dispatched packet leaves by its slot veth or not at all, including mid-rebuild, after a failed rebuild, while a slot is stopped, and with no ruleset loaded. Two layers enforce it (see `gotchas.md` → "An empty slot table routes VPN traffic out the uplink"):
- **Routing** (`routeguard.sh`, armed at boot by `proteus-routeguard.service` before any interface comes up, then by `vpnns-up.sh`/`vpnns-down.sh`, the dispatcher's `ExecStartPre` and the installer). Every slot table ends in `blackhole default metric 4294967295`, below the real `default via <veth>`. The slot's rules persist across rebuild and stop. A static `pref 32000 not fwmark 0x0/0xffffffff blackhole` catches marks with no slot rule (typed without the mask, the kernel stores mark 0/mask 0 and the rule matches nothing; `routeguard.sh` adds it correctly, so re-run that rather than adding it by hand). The ingress sink (pref 32010/32020, table 900 → dummy `proteus-null`) sends anything from the client interface or `wg-udm` that reaches it with a public destination to a dummy device instead of `main`, with or without nftables. An empty table would otherwise let the rule walk fall through to `main`.
- **Firewall.** `chain prerouting_ctsave` saves the dispatcher's verdict in conntrack. `chain forward` opens with drops for meta-marked, and original-direction ct-marked, packets whose `oifname` is not `v-proton-*` (counter `marked_leak_fwd`), and for unmarked client/trusted traffic to a public address (`unmarked-client-egress`), ahead of every accept, the ct-established one included. `chain postrouting_guard` allows marked egress only via `v-proton-*`, the DNS veth and `lo`, for forwarded and locally generated packets alike (counter `marked_leak_post`). `chain output` drops the box's own ICMP errors about a tunnelled flow's reply leg that would leave off-tunnel: they carry the flow's ct mark but, with the default `net.ipv4.icmp_errors_use_inbound_ifaddr=0`, route via `main` (counter `own_icmp_err_tunnelled`). Errors routed into a slot veth are left alone.

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

Three explicit drops sit **above** `ct state established,related accept` and every accept after it:

- `unbound-dns-killswitch` (uid `unbound`, daddr `10.2.0.1`, leaving anything but `v-dns-6`) and `unbound-upstream-tunnel-only` (uid `unbound`, original direction, dport 53/853 off `v-dns-6`; upstream-agnostic if the forwarder ever changes, and `ct direction original` keeps replies to clients untouched). The DNS upstream (`10.2.0.1`) is RFC1918 and would otherwise be covered by the `$RFC1918` accept. They precede the ct-established accept because conntrack keys on the 5-tuple: a flow that established over the tunnel would stay ESTABLISHED after a route flip.
- `own-icmp-error-for-tunnelled-flow`: the box's own ICMP errors about the reply leg of a dispatched flow, when they would leave by anything but a slot veth (see the Routing section above). As RELATED packets they would otherwise pass the ct-established accept.

The unbound egress accept (`unbound-dns-egress`) also sits above the ct-established accept, right after the two DNS drops.

After `chain output` comes `chain postrouting_guard`, which sees locally generated and forwarded packets alike: anything with a nonzero meta mark, or an original-direction ct mark, leaving by an interface other than `v-proton-*`, the DNS veth or `lo` is dropped (counter `marked_leak_post`). For the box's own traffic that covers unbound's marked queries if routing ever sends them elsewhere.

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

Each probe rotates through 5 user agents (Chrome/Windows, Safari/Mac, Firefox/Linux, Safari/iPhone, Chrome/Android) to avoid UA-based heuristic blocks. The Cloudflare canaries and the YouTube playability probe are the exceptions: their UA is pinned, because their verdict depends on which site variant answers. Before any probe runs, the script issues a single warmup `HEAD https://proton.me/` through the staging netns so the first real probe doesn't catch Proton's 25–35s exit-side cold window — without that, transient cold-catches falsely fail otherwise-good exits.

`rotate-slot.sh` does **mint-retry with N=5 attempts per rotation**. First passer is promoted. All-fail = leave the old slot alone; next timer fire tries again. AbuseIPDB is reserved as a fallback if empirical probes prove insufficient later.

### Cloudflare canaries, live checks and the exit ledger

Added 2026-09. Status-code probes cannot see a Cloudflare challenge, and a
challenge is what a client on a bad exit actually experiences. So:

- Every probe (built-in and custom) now classifies Cloudflare's own verdict from
  the response: `cf-mitigated: challenge` is a challenge page, an `error code:
  1NNN` body is a hard block (1015 rate limit, 1006 to 1008 IP ban, 1020 site
  rule), and a response without a `cf-ray` header is not Cloudflare at all and
  is skipped rather than judged. `BLOCK` lines say which.
- A built-in canary basket (`/etc/proteus/canaries.json`, default discord,
  digitalocean, patreon) is probed with a pinned desktop user agent and
  fixed headers so verdicts compare across exits and over time. Measured
  2026-09-03 from five gate-approved US exits: discord and digitalocean passed
  all five, patreon three, udemy two. udemy left the default basket on
  2026-09-04: it challenges about 90% of Proton exits and flags rejected and
  accepted candidates at the same rate, so it costs a probe per exit and tells
  the two apart no better than a coin. `PROTEUS_CF_TIER` ("Require cf ok" in
  the UI) decides what a canary verdict does. With `mandatory`, the default,
  every active canary gates and "cf ok" is required. With `advisory` the
  canaries run and the badges show, but nothing acts on them: the gate does not
  reject on a canary, mint does not steer by canary results, the dispatcher
  keeps flagged slots eligible, and a live check never rotates on a canary.
  Set it in the UI or in `proteus-local.env`: `rotate-slot.sh` and
  `reputation-probe.sh` do not read `proteus.env`.
- `slot-warmup.sh` re-runs the canaries and the mandatory custom checks on
  promoted slots (one slot every 20 passes, offset from the streaming check) and
  rotates a slot after two consecutive failures of one check, behind a shared
  per-slot cooldown. The first flagged canary writes `CF_CLEAN=no` to
  `.cf-state.<slot>`. With cf ok required, from then on the dispatcher gives
  the slot no new clients on every pick path. When no slot is cf ok, new clients use a flagged
  slot. A flag holds until a newer verdict replaces it. Existing pins stay
  until the rotation. A run writes a verdict only from an observation: a run
  with an unreachable canary and no flagged canary leaves the verdict as it was.
  With cf ok required, a slot with no verdict, or with a flag, gets a quick
  check at the next live-check turn, about 200 s later, beside the round-robin
  slot. So a flag is
  confirmed or cleared in one turn. The canary streak counts flags and
  unreachable results. It caps the quick checks per exit at
  `PROTEUS_LIVECHECK_FAILS`. A slot that is rotating gets none. With
  `PROTEUS_LIVECHECK=off` nothing can confirm a flag, so each warmup pass
  removes a `CF_CLEAN=no` verdict. A live check never touches the health score.
  Each live check runs as its own oneshot unit,
  `proteus-livecheck@<slot>.service` (started from the warmup pass with
  `--no-block`), so a slow canary run never stalls the ten-second warmup, and
  it skips itself while that slot is rotating. The rotation guards in
  `slot-warmup.sh` and the UI read the state that `systemctl is-active` prints
  for `proteus-rotate-slot@<slot>.service`, because it exits 3 for a running
  oneshot unit.
- The web UI shows `cf ok`, `cf N flagged` or `cf unchecked` on each tunnel
  card. With cf ok required, a banner shows when no running tunnel is cf ok.
- Every verdict lands in `/etc/proteus/state/exit-ledger.jsonl`, keyed by exit
  and entry IP. `proton-mint` uses it: load is a filter, not a ranking; odd
  rotation attempts explore servers with no history until the known-good pool
  reaches `PROTEUS_MINT_POOL_TARGET`; exits promoted within
  `PROTEUS_MINT_REUSE_MIN_S` are set aside; the least recently promoted exit is
  drawn first, preferring a /24 no sibling holds. `proteus-cf-report` prints
  pass rates, attainability, diversity and the agreement table used to
  calibrate the basket against an operator's own checks.
- The ledger also decides when strictness would be self-defeating. A canary no
  exit passes across 8 distinct exits is quarantined (probed, not counted). When
  fewer exits than slots met the standard in 24 h the standard is "not
  attainable" and canary-triggered live rotations pause. When a rotation
  exhausts its verdict attempts it ends all-fail and the current exit stays.
  With cf ok required, a candidate that fails a canary is never promoted. A flagged slot then keeps
  its place with no new clients, and the next confirmed flag after the cooldown
  starts the next attempt. A promotion writes the verdict its gate observed:
  flagged when a canary challenged or blocked it (possible only in advisory),
  cf ok when every active canary was clean, unchecked when one was unreachable.
- `rotate-slot.sh` now counts only verdict failures against `MAX_ATTEMPTS`;
  mint errors, endpoint collisions and staging or egress transients no longer
  burn an attempt (the loop is bounded at 14 iterations regardless). With
  transients no longer charged to it, the verdict budget went from 5 to 8 on
  2026-09-04. Rotation now
  has a 25-minute wall-clock deadline of its own and an exit trap that tears
  down the staging tunnel, and the unit's start timeout is 45 minutes.

## Health-aware dispatch (Tier 1)

Each `slot-warmup` pass writes a per-slot health file at `/run/proteus-slot-health/proton-N.state`:

```
INSTANCE=proton-N
STATUS=ok|degraded
LAST_OUTCOME=ok|warmed|all_fail
LAST_PASS_AT=<unix-ts>
FAIL_STREAK=<int>
LAST_ROT_TRIGGER_AT=<unix-ts>
```

`STATUS=degraded` after `FAIL_STREAK >= DEGRADED_AFTER` (default 2 consecutive ALL_FAILs ≈ 20s of solid failure). Any single PASS resets `FAIL_STREAK=0` → `STATUS=ok`.

`dispatcher.py` picks a slot for each new client via `pick_distributed`: it takes the fresh, non-degraded slots scoring within `SPREAD_BAND` (default 40) of the current best — "slots that don't suck" — and assigns the **least-loaded** of those by current pin count, tie-breaking toward the higher score. This fans clients out across the strong slots (spreading bandwidth and handing each a distinct exit IP) instead of piling everyone onto the single top-scored slot. If no slot has a fresh score it falls back to a healthy random pick; if all are DEGRADED it rides the full pool with a warning. Only real client-VLAN sources are pinned (`is_pinnable_source` drops stray 0.0.0.0/off-VLAN packets). Existing sticky-map entries are unaffected (a source already pinned to slot N stays until its pin TTL expires or the janitor evicts it because the slot degraded or stopped).

Effect: a transient ALL_FAIL window on one slot stops affecting NEW clients within ~10s of the warmup detecting it, and load spreads across the healthy slots as clients connect.

## Trusted-VLAN egress (added 2026-09)

The isolated client VLAN is not the only way to reach the rotating exits. A host
on an ordinary VLAN can egress through them while keeping its own address, its
own VLAN and its own local DNS, with the choice of *which* hosts made in the
upstream router's UI rather than here.

The upstream router (a UniFi gateway) cannot point a policy route at a LAN next
hop — its Traffic Routes select a WAN, a VPN tunnel or a local network, and
nothing else. So proteus presents itself as a WireGuard **VPN client target**:
it runs a WireGuard server on `wg-udm` (default `10.99.99.0/30`, UDP 51821, MTU
1420), the router connects to it exactly as it would to a commercial VPN
provider, and that connection then appears as a selectable egress in Traffic
Routes, per network or per device.

- **Ingress.** `prerouting_mangle` accepts two origins: the client VLAN on its
  own interface, and sources inside `@trusted_src` arriving on `wg-udm`. The set
  is empty unless configured, so an unpaired box behaves exactly as it did
  before the feature existed. `iifname` is used rather than `iif` so the ruleset
  loads on a box where the tunnel does not exist.
- **Dispatch.** Per destination, not per source: the router masquerades, so
  every trusted host arrives as the tunnel address. `@source_pin` is skipped
  for `wg-udm` and each new destination gets a `@vpn_dispatch` entry (12h),
  with the same health-aware placement as the client VLAN.
- **Return.** Replies leave through the tunnel via routing table 110, selected by
  an `ip rule` on destination alone. Two higher-priority rules keep that from
  capturing traffic it should not: one pins packets *originating* on proteus to
  the main table, the other pins the client VLAN **to that destination** — a rule
  per trusted range, source and destination both. The first keeps proteus'
  replies to a trusted VLAN (web UI, SSH) on the management interface instead of
  the tunnel; it fixes the reply route only. Whether a trusted VLAN may reach the
  UI at all is the input chain's call: `proteus-ui-mgmt` accepts `LAN_MGMT` plus
  the one CIDR in `UI_MGMT_EXTRA` on the management interface, so a trusted VLAN
  that should reach the UI goes in `UI_MGMT_EXTRA`. That traffic must also arrive
  on the management interface: a UniFi Traffic Route scoped to all destinations
  (not just Internet) sends it in through `wg-udm` instead, where the input chain
  drops it. The second rule keeps a client-VLAN host's transit to a trusted VLAN
  going out the management interface instead of into the tunnel.
  Scoping the second by destination is what keeps it from matching all
  client-VLAN egress: a source-only rule would resolve on `main`'s default route
  and stop evaluation before the `fwmark` rules that select a slot's table, so
  client traffic would leave over the WAN with the VPN skipped.
  The reconcile adds before it removes: new rules and routes go in first and
  only stale ones come out, so a range that stays configured never loses its
  return path, and a removed range's return routes leave the slots before its
  rules go. Table 110 ends in a blackhole catch, and the tunnel subnet has a
  rule and a route there as well, so a reply whose route went away with
  `wg-udm` is dropped rather than routed out the uplink (see gotchas.md).
- **MTU.** 1420 to match the Proton tunnels, so the forward chain's existing
  `rt mtu` MSS clamp produces the right value in both directions. This also
  covers for the router, which does not clamp on its own VPN-client interfaces.
- **Boundaries.** The range list is validated to be private, to avoid the client
  VLAN, and to avoid the management subnet unless it names a single host — the
  guard that stops an operator routing the subnet holding the gateway into a
  tunnel. Traffic from the tunnel to an RFC1918 destination is dropped and
  logged as `nft-trusted-lan`, because the cause is a Traffic Route scoped to
  all destinations rather than to Internet.
- **Pairing.** Generated in the web UI under Settings, downloaded as a `.conf`,
  and pasted into the router. The router's private key is rendered once and
  never stored on the gateway; re-pairing issues a new one and invalidates the
  old. A paired box raises the tunnel even with an empty range list, so the peer
  can be confirmed and the arriving source addresses observed before anything is
  routed — until a range is added, nothing is forwarded and no route or policy
  rule exists. An unpaired box has no interface at all.

Example ranges in this document use `192.168.7.0/24` and `10.99.99.0/30`; the
shipped default list is empty.

## Auto-rotation of persistently bad slots (Tier 2)

When `FAIL_STREAK >= ROT_THRESHOLD` (default 5 ≈ 50s of solid failure) and the per-slot cooldown has elapsed (default 300s), `slot-warmup.sh` invokes `systemctl start --no-block proteus-rotate-slot@proton-N.service`. The cooldown prevents mint-storms when a slot is borderline. The 50s threshold is intentionally above the ~25-35s cold-window so a transient cold-catch doesn't trigger a rotation — only a slot that's been failing through multiple warmup passes (and presumably the dispatcher has already DEGRADED it for live traffic) gets evicted.

The rotation itself is the same code path as the daily timer — mint, stage, probe, promote — so the auto-trigger is just a faster heartbeat for "this exit is broken, find a new one" without waiting for the next scheduled rotation.

## DNS — dedicated tunnel

Separate `dns-6` Proton tunnel carrying DNS traffic only. Local unbound listens on `127.0.0.1` + `172.16.1.5` and forwards `.` to `10.2.0.1` (`UNBOUND_UPSTREAM`) over plain UDP — Proton's in-tunnel NetShield resolver. `10.2.0.1` is the gateway address inside *every* Proton WireGuard tunnel, so it survives a dns-6 rotation without any config rewrite. NetShield (level from `PROTEUS_NETSHIELD_LEVEL`, baked into the tunnel certificate at key registration) filters ads/trackers/malware; because client port-53 traffic is redirected to unbound, this is the layer that actually reaches clients.

DNSSEC validation is off: the drop-in sets `module-config: "iterator"`. NetShield answers a blocked name with a bare unsigned NXDOMAIN and NXDOMAINs the DS query for it too, so a validating resolver can't prove insecure delegation and returns SERVFAIL for every blocked ad domain instead of a clean NXDOMAIN. `10.2.0.1` validates upstream itself, so the loss is last-hop only and that hop is inside WireGuard. Anyone pointing `UNBOUND_UPSTREAM` back at a public resolver must restore both the validator and `forward-tls-upstream`. `UNBOUND_MODULE_CONFIG` picks the line automatically: `iterator` for an upstream in `10.2.0.0/16`, `validator iterator` otherwise.

Single upstream by design. A public fallback resolver would silently disable NetShield filtering the moment `10.2.0.1` hiccups, which defeats the point; `serve-expired` plus `rotate-dns.sh` cover short outages instead.

Because the upstream is now RFC1918, a routing fallback is a privacy leak rather than a firewall drop, so `chain output` carries a dedicated kill-switch (`unbound-dns-killswitch`): any packet from uid `unbound` to `10.2.0.1` leaving on anything other than `v-dns-6` is logged and dropped, above the ct-established accept.

Two mechanisms steer unbound's upstream queries into the dns-6 tunnel:

1. **Source-IP routing rule.** Unbound is configured with `outgoing-interface: 172.31.6.1` — the main-ns side of the dns-6 transit /30. `ip rule from 172.31.6.1 lookup 106 priority 406` (installed by `vpnns-up.sh`) routes any packet with that source via table 106 → `v-dns-6`. **This is the primary steering mechanism.**
2. **Fwmark stamp.** `chain output_route { type route hook output priority mangle; meta skuid "unbound" meta mark set 0x6; }` stamps unbound's packets with mark 0x6. The kill-switch then requires all three of `skuid=unbound`, `mark=0x6`, `oifname=v-dns-6` to accept the egress — defense-in-depth.

*Why both?* The route-hook reroute didn't work on this kernel (see `gotchas.md`). The source-IP rule is the reliable steering; the mark-stamp is retained purely so the kill-switch rule can require a three-way match for the accept.

`dns-6` is not part of the client-traffic rotation pool — the dispatcher's `load_instances()` (in `dispatcher_logic.py`) filters on `^proton-\d+$`. DNS survives slot rotation cleanly because it rides its own independent tunnel.

`dns-6` has its own separate rotation trigger: `proteus-dns-latency.timer` fires every 15 min, measures a UDP `. NS` query from `ns-dns-6` to `10.2.0.1`, and calls `rotate-dns.sh` if the query time exceeds 150ms. The cooldown in `rotate-dns.sh` (1h) prevents thrashing when no available exit has a good path. The threshold is sized to the target: the old 300ms figure assumed a TCP transaction over a ~220ms Quad9 path and could never fire against an 11-16ms in-tunnel resolver, which would have retired health-driven DNS rotation without anyone noticing. Worst measured exit was 71ms, so 150 leaves roughly 2x headroom. The cold-DNS experience is dominated by tunnel RTT × qname-minimisation steps, so a faster exit directly shortens first-hit latency for users.

Per-netns resolv.conf files (`/etc/netns/ns-proton-N/resolv.conf`) still point at Quad9 (`DNS_UPSTREAMS`), so `ip netns exec` bind-mounts that over `/etc/resolv.conf` for reputation probes and anything else run inside a rotating netns — no leak to the mgmt network's resolver (which the kill-switch doesn't permit anyway). The split from the gateway resolver is deliberate: clients get NetShield filtering via unbound, while the probe namespaces stay on an unfiltered public resolver so exit health-checking is never coupled to an ad blocklist. Point the probes at NetShield and a user who adds an ad domain to their custom check list makes every exit look broken, wedging rotation.

## Rotation lifecycle

`proteus-rotate-slot@proton-N.timer` (daily + 12h jitter, persistent) → `rotate-slot.sh N`:

1. For attempt in 1..8 (verdict attempts; at most 14 iterations in total):
   1. `proton-mint --slot proton-N-s --out-dir /etc/proteus/wg/proton/auto` → writes a fresh WG config using a brand-new keypair and a Proton API-registered peer selection.
   2. `vpnns-up.sh proton-N-s <conf> $((100 + N))` — stage under name `proton-N-s`, index `100+N` (so staging slots use fwmark `0x65..0x69`, table `201..205`, veth `v-proton-N-s`/`v-proton-N-s-ns` — fits in 15-char kernel veth name limit because the suffix is `-s`, not `-new`).
   3. Wait for handshake (poll `wg show` up to 30s).
   4. Egress probe: `ip netns exec ns-proton-N-s curl https://1.1.1.1/cdn-cgi/trace --retry 3 --retry-all-errors --retry-delay 2 --max-time 12`, parsing the exit IP out of the `ip=` line. The URL is an IP literal so the probe needs no resolver: a staging namespace resolves through the tunnel it is testing, and on some exits that resolver does not answer, which used to fail the probe on name resolution and burn the whole retry budget for a reason unrelated to the exit. (It replaced `checkip.amazonaws.com` on 2026-09-04.)
   5. `reputation-probe.sh ns-proton-N-s` — tiered verdict.
   6. Pass → `break`; Fail → cleanup staging (`vpnns-down.sh proton-N-s`, `rm` config), sleep, retry.
2. If no passer after 8 verdict attempts (or 14 iterations, or the 25-minute deadline) → log + exit 2. Old slot untouched.
3. On passer:
   1. `vpnns-up.sh proton-N <new_conf>` — replace the live slot in place. Same fwmark/table/transit means `@vpn_dispatch` entries are still valid. During the sub-second rebuild the slot's traffic hits the blackhole sentinel and is dropped silently (clients retransmit into the rebuilt tunnel), never routed out the uplink.
   2. `systemctl kill --kill-who=main --signal=HUP proteus-dispatcher.service` — re-read state (pool names haven't changed, just endpoint). `--kill-who=main` because the default, `all`, also signals the dispatcher's `nft` children and its `routeguard.sh` ExecStartPre, which SIGHUP kills.
   3. Prune old `/etc/proteus/wg/proton/auto/proton-N-*.conf` except the two most recent.

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

Both sticky maps (`@source_pin`: `saddr → mark`, `@vpn_dispatch`: `daddr → mark`) map to a **mark**, not to an endpoint. Rotation replaces the endpoint (WG peer) associated with a mark but leaves the mark itself alone. So, taking the destination map as the example:

- A flow to destination D got mark 3 this morning, went through the proton-3 slot.
- Midday, proton-3 rotates to a new Proton exit. `@vpn_dispatch[D] = 3` is untouched.
- A new flow to D this afternoon still maps to mark 3 → now goes out the new exit.
- Same destination, same slot, but a different IP on the exit side — the user's per-destination consistency is preserved semantically (same "lane") without pinning to a specific exit IP.

Conntrack provides the mid-stream safety: if a long-lived flow exists when the map entry expires, `meta mark set ct mark` in `prerouting_mangle` restores the mark from the flow's own ct state.

## Web UI

`proteus-ui.service` is an unprivileged Python-stdlib TLS daemon (`ThreadingHTTPServer` wrapped in
an `ssl.SSLContext`) listening on `UI_PORT` (default 8443). Who reaches it is decided by the input
chain: `proteus-ui-mgmt` accepts `LAN_MGMT` plus `UI_MGMT_EXTRA` (one extra CIDR, e.g. a trusted
VLAN) on the management interface, and `proteus-ui-client` adds the client VLAN only when the
installer renders it (`UI_CLIENT_VLAN_ACCESS=yes`; the default is `no`). Nothing accepts the UI port
on `wg-udm`. It runs as system user `proteus-ui` with an empty `CapabilityBoundingSet` and
`NoNewPrivileges=yes`, and never writes production state directly: it reads the per-slot
`.state`/`.meta` files, the slot-health files, and the `/run/proteus` snapshots
(`dispatcher-status.json`, `rotation-history.jsonl`) through group membership, and reads timer
schedules via unprivileged `systemctl show`. Every mutation (set a knob, force a rotation,
pause/resume auto-rotation, restart the dispatcher) goes out as one JSON line to
`proteus-ui-apply`'s unix socket; the daemon itself has no path to root.

`proteus-ui-apply.socket` / `.service` is the privileged broker on the other side of that socket,
`/run/proteus/apply.sock` (mode 0660, group `proteus-ui`), socket-activated so root code only
runs on demand. It's the sole writer of `/etc/proteus/proteus-local.env`, the rotation-paused flag
file, the `proteus-rotate-slot@.timer` drop-in, and the manual-rotation trigger files under
`/run/proteus`. It validates every command against a fixed schema (ranges, not just types) and
builds argv arrays directly, no shell on any input path, so the unprivileged daemon is untrusted
from the broker's point of view. It's the same trust boundary sudo would give, without a sudoers
file.

`/run/proteus` (tmpfiles.d) and `/etc/proteus/state` are SETGID group `proteus-ui` (mode 2750), so
files written by the root-run dispatcher and rotation scripts inherit the group automatically;
no `CAP_CHOWN` needed on either side.

## Boot ordering

`proteus-routeguard.service` arms the catch rule and the ingress sink and `nftables.service` loads the ruleset, both before `network-pre.target` and neither waiting for the other, so a ruleset that fails to load still leaves the routing layer in place before any interface is up (the sink needs `PROTEUS_CLIENT_IFACE` for that: the client address does not exist yet) → `proteus-dns-tunnel.service` brings up dns-6 → `unbound.service` starts (Before relationship) → `proteus-proton@proton-{1..5}.service` bring up the rotating slots (each `ExecStart=vpnns-up.sh %i /etc/proteus/wg/proton/auto/%i.conf`, Before=`proteus-dispatcher.service`) → `proteus-dispatcher.service` binds NFQUEUE 0 with the 5-slot pool loaded. `proteus-proton-api-whitelist.service` and `repopulate-wg-peers.sh` refresh the sets that `flush ruleset` empties. nftables.service also carries the proteus drop-in (`nftables.service.d/proteus.conf`): stop runs no flush, and after every start or reload `proteus-nft-repopulate.sh` queues the set refills. At boot the helper normally sees `initializing` and queues nothing, leaving the refills to the boot order; its job is a later `systemctl restart` or `reload`, including the package's try-restart on upgrade. `proteus-slot-warmup.timer` starts 45s after boot (once the pool is up) and fires every 10s to keep Proton's exit-side flow state warm.

`proteus-ui-apply.socket` is `WantedBy=sockets.target`, independent of the dispatch chain above:
it just listens, so it's always ready even before the broker service itself has run once.
`proteus-ui.service` (`After=`/`Wants=proteus-ui-apply.socket`) starts in parallel with the rest of
boot; the installer enables it but the service itself refuses to start until a passphrase has been
set (see `operations.md`), so on a freshly installed or freshly rebooted box it's expected to sit
in `systemctl --failed` until `proteus-ui-passwd` runs.

The `proton-N.conf` stable symlink is what `proteus-proton@.service` reads — `rotate-slot.sh` updates it on every successful promotion, so the next boot always picks up the most recently promoted config for each slot.

## Forward-chain ordering vs asymmetric client-to-mgmt flows

The VM is the default gateway for the client VLAN (172.16.1.0/24). The upstream switch (UniFi) also has an interface on that VLAN as the DHCP server, so when a host on the mgmt LAN (10.0.0.0/24) SSHes into a VLAN client, UniFi short-cuts the forward path directly to the VLAN — the VM never sees the SYN. The SYN-ACK, however, leaves the VLAN client through its default gateway (us) and has to forward out ens18 toward UniFi → mgmt.

From the VM's conntrack perspective this is a SYN-ACK with no prior SYN in the state table, which gets classified `ct state invalid` and would be dropped by the default hygiene rule. To allow the legitimate VLAN→RFC1918 transit, the forward chain places the `client-to-private` accept **before** `ct state invalid drop`. Internet-bound flows still hit the invalid drop after that, so the kill-switch story is intact; only RFC1918 transit is exempt.

UniFi won't let us install a non-/32 route via 172.16.1.5 (it holds the /24 for DHCP), so symmetric routing at the upstream isn't available. The forward-chain reorder is the pragmatic workaround.

## Cold-tunnel warmup

Observed behavior (empirical, confirmed with tcpdump on v-proton-N and wg0 inside the ns): if a Proton slot has no user-plane TCP activity for ~25-35s, the first SYN on the next client flow is silently dropped upstream of the WG tunnel, even though the WG handshake is fresh (PersistentKeepalive=25 keeps the *transport* alive; Proton's *exit-side* NAT/flow-state decays independently). TCP retries fix it in 2-20s at the cost of user-visible first-hit latency.

`proteus-slot-warmup.service` fires every 10s (timer + 2s accuracy jitter). Each pass issues parallel `curl -I https://proton.me/` against every slot in the rotating pool (`^proton-\d+$`, matches the dispatcher filter, skips dns-6 and `-s` staging). proton.me is chosen because it's operated by Proton — they already see our WG handshake every 25s, so this keepalive adds no third-party correlation.

Parallelization matters. With a serial loop, a pass over 5 cold slots took ~20s (5 × 4s timeout), pushing per-slot re-hit interval past the cold threshold. Backgrounding the curls and `wait`-ing bounds wall time to the slowest single slot, so every slot gets refreshed every ~10s regardless of how many are momentarily cold.

Measured effect on fresh client connections (LXC curl to 8 unique public hostnames, sampled post-warmup steady-state): 7/8 under 200ms TCP connect. Before the warmup, the same test had all 5-8 destinations in the 2-20s range. The remaining occasional slow hit is tolerable — it lines up with Proton's 30-35s cold-cycle hitting the exact instant a client SYN goes out.
