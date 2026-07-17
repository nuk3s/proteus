# Gotchas

Non-obvious behaviors we hit during build-out. Each one cost real time; if you're about to make a similar change, read the relevant entry first.

## `type route` hook doesn't reliably reroute on this kernel

**Kernel:** 6.12.74 (Debian 13 trixie).

Intent: mark locally-generated packets from uid `unbound` with fwmark `0x6` so `ip rule fwmark 0x6 lookup 106` routes them out the `v-dns-6` veth.

```nft
chain output_route {
    type route hook output priority mangle; policy accept;
    meta skuid "unbound" meta mark set 0x6;
}
```

Mangle fires — diagnostic counter on the rule shows skuid match and mark set. But the routing decision is **not** re-evaluated after the mark lands: packets still egress the main-table default (ens18). `ip route get 9.9.9.9 mark 0x6` correctly returns `via 172.31.6.2 dev v-dns-6 table 106` at the CLI, so the rule/table are fine — the reroute just doesn't happen inside netfilter's output path.

**Workaround:** deterministic source-IP rule. Unbound's `outgoing-interface: 172.31.6.1` binds the source address to the main-ns side of v-dns-6. `ip rule from 172.31.6.1 lookup 106 priority 406` (installed by `vpnns-up.sh` for every slot, not just dns-6) routes any packet with that source via the right table. Works first try.

**We retained the route-hook chain anyway** — the kill-switch accept rule (`meta skuid "unbound" meta mark 0x6 oifname "v-dns-6"`) requires three conditions. The mark-stamp plus the source-IP rule plus the skuid match all hold, giving defense-in-depth.

**If you port this design to a different kernel**: test with a diagnostic counter on the `output_route` chain first. If the reroute works there (TX on v-dns-6 grows without the source-IP rule), you can drop the source-IP rule to simplify. Don't remove the kill-switch three-way accept regardless.

## veth interface names have a 15-character limit

**Symptom:** `Error: argument "v-proton-3-new-ns" is wrong: name is too long`.

`v-proton-3-new-ns` is 17 chars. The kernel `IFNAMSIZ` is 16 including the trailing null, so 15 usable.

**Convention:** staging suffix is `-s`, not `-new`. Gives `v-proton-3-s-ns` = 15 chars exactly. `vpnns-up.sh` sanity-checks this and errors early if `${#VETH_NS} > 15`.

Don't let a future refactor "clarify" the staging suffix — it has to stay ≤2 chars.

## `flush ruleset` empties named sets

Any `nft -f /etc/nftables.conf` flushes @wg_peers and @proton_api. The ruleset *declares* them but the elements are populated at runtime by:

- `repopulate-wg-peers.sh` (scans `/etc/multivpn/state/*.state`)
- `multivpn-proton-api-whitelist.service` (resolves `vpn-api.proton.me` + siblings)

**After any nft reload**, run both. The deploy script for DNS (`/tmp/deploy-dns.sh`) does this in order: reload → repopulate → restart dependent services. If you skip it: all WG handshakes start failing silently within a keepalive interval because the kill-switch no longer permits them.

## The netns default resolver would leak, so we bind-mount

Main ns's `/etc/resolv.conf` points at the lab's AdGuard resolver (`10.0.0.22`), which is unreachable from inside a tunnel ns (the kill-switch would drop it, and even if it didn't, using the LAN's resolver for client traffic would be a DNS leak).

`ip netns exec <ns>` consults `/etc/netns/<ns>/resolv.conf` if present and bind-mounts it over `/etc/resolv.conf` for spawned processes. `vpnns-up.sh` writes Quad9 into that file for every netns it creates. Removing this file (or relying on systemd-resolved's stub) reintroduces the leak.

## Fresh tunnels throw transient TLS "unexpected eof"

First HTTPS connection through a freshly-minted WG tunnel sometimes aborts with OpenSSL `SSL_read: unexpected EOF`. It's not a config issue — appears to be a warm-up artifact on Proton's end (possibly MTU-discovery-related). Curl invocations inside staging netns use `--retry 3 --retry-all-errors --retry-delay 2 --max-time 12` so the second or third try wins. Don't remove the retry flags.

## Dig `+short` + bogus subdomain → empty output looks like a timeout

If you test the resolver with `dig @127.0.0.1 +short rand-123.example.org A | head -1`, NXDOMAIN returns empty output — indistinguishable from a timeout in a shell script. We wasted 20 minutes thinking DNS was broken because of this.

Use real TLDs for smoke tests (`cloudflare.com`, `debian.org`, …) or check `dig`'s status field directly instead of relying on empty stdout as a signal.

## Unbound UDP retry budget is tight on first queries

Cold-cache first query to a zone that Quad9 hasn't cached nearby can exceed unbound's initial UDP timeout (376ms). Round-trip budget on our path is ~150-200ms for `tunnel RTT + Quad9 RTT`, so anything >200ms at Quad9 side can retry — and if that retry also needs TCP for a big DNSSEC chain, you might exceed `dig`'s `+time=3`. Use `+time=5 +tries=2` for hand-tests. ~95% pass rate at `+time=3`, ~100% at `+time=5`. Not worth tuning — just set client timeouts reasonably.

## SIGHUP to the dispatcher re-reads state, not code

`multivpn-dispatcher.service` reloads the instance pool on SIGHUP — but only by re-running `_load_instances()` on the already-imported Python module. Code changes in `dispatcher.py` require a full `systemctl restart`. The line in `journalctl` you want to confirm is "loaded N VPN instance(s): …" after the restart.

## Don't query AbuseIPDB / Scamalytics from the mgmt IP

The user explicitly rejected this path. Querying from `10.0.0.121` correlates "mgmt IP just asked about exit IP X" on a non-privacy-centric vendor's logs — exactly the correlation Proton's privacy model is designed to avoid. Empirical probes from *inside* the staging netns test what actually matters (does the exit behave normally) without creating that correlation.

AbuseIPDB is kept as a documented fallback if empirical probes later prove insufficient, but the default path is always in-tunnel probes first. If you add a new reputation signal, it also runs inside the netns.

## Reddit advisory is deliberate — don't promote it to mandatory

Reddit 403s a large fraction of Proton streaming exits **by policy, not by reputation**. Observed 3/5 streaming-pool slots getting 403 at Reddit despite clean mandatory probes. If you make Reddit mandatory, rotation will usually fail because *every* candidate Proton gives you has Reddit blocked.

Keep it advisory (reports "ADVISORY BLOCK: reddit" in the log but doesn't fail the verdict) unless the tier structure changes.

## The UniFi IPS sometimes drops SSH to the VM

This is **not** the VM's kill-switch. If SSH times out and you see no output-chain drops on the VM side (via console) and the SSH counters look normal, it's the upstream IPS rule. The user has a toggle for it.

**Rule**: do not poll/retry on SSH timeout. Tell the user and wait. Don't dig into the VM firewall without first verifying the VM is actually receiving the TCP SYN.

## Verify live SSH source before narrowing inbound rules

Before any change that tightens `input` on `ens18`, run:

```bash
ss -tnp | grep :22
```

Confirm the source IP of your own session and that the `ssh-mgmt` rule accepts that address. Past incident: the user was locked out when an inbound rule was narrowed based on a stale assumption about their source IP. The `systemd-run --on-active=900` revert-timer pattern in `/tmp/deploy-*.sh` scripts exists *because* of this.

## `type route` and `type filter` on the same hook coexist

They evaluate in priority order (mangle -150 → filter 0). Both see the packet. If you delete or modify the route chain, the filter chain is unaffected and vice versa. Safe to iterate on one without touching the other.

## conntrack entries survive across nft reloads

Flushing the ruleset doesn't wipe conntrack. If you change how marking works mid-flow, existing flows will continue using whatever ct mark they acquired before the change. For a clean test, drain flows with `conntrack -F` — but be aware this breaks any live sessions transiting the box.

## `ip rule` survives `nft -f`

`ip rule`/`ip route` are kernel policy-routing state, completely independent of nftables. An `nft -f` reload does not touch them. This is why the source-IP rule we added manually for dns-6 survived our subsequent ruleset swap — but don't rely on it: always install persistent rules in `vpnns-up.sh` so they're reproduced at every boot.

## Unbound socket goes stale when v-dns-6 is recreated

Unbound binds a UDP source socket to `172.31.6.1` (the main-ns side of v-dns-6) via `outgoing-interface:`. When `rotate-dns.sh` does `vpnns-down.sh dns-6 && vpnns-up.sh dns-6 <new-conf>`, the veth is destroyed and recreated with the same IP — but unbound's existing socket is now bound to a dead interface and all queries silently vanish (no `SERVFAIL`, no log — `dig` just times out).

**Symptom:** dns-6 handshake fresh, ping from inside ns-dns-6 to 9.9.9.9 works, but `dig @172.16.1.5` hangs.

**Fix:** `systemctl restart unbound` at the end of `rotate-dns.sh` (adds ~1-2s DNS gap to the swap). `unbound-control flush_infra all` is *not* sufficient — it clears RTT data but doesn't rebind the socket.

If you add another caller that recreates v-dns-6 (e.g., a future staged rotation), include the unbound restart.

## Stable `proton-N.conf` symlink must be kept in sync with promoted config

`rotate-slot.sh` writes a new timestamped config and calls `vpnns-up.sh` with that fresh path directly — but the `multivpn-proton@.service` boot unit reads the stable symlink `/etc/multivpn/wg/proton/auto/proton-N.conf`. If the symlink isn't updated on promotion, the next reboot (or any `systemctl restart multivpn-proton@proton-N`) silently reverts the slot to whatever config the symlink still points at — typically the *pre-rotation* one that may have been bad enough to trigger the rotation in the first place.

**Fix (landed 2026-04-21):** `rotate-slot.sh` now runs `ln -sfn "$good_conf" "${AUTO_DIR}/${SLOT}.conf"` right after the promote-time `vpnns-up.sh` call, before the "promoted" log line.

If you're debugging and see a slot's wg0 endpoint suddenly revert to an old IP after a restart, check the symlink target vs the `WG_CONF=` line in `/etc/multivpn/state/proton-N.state`. They should match.

## Proton exit-side flow state goes cold in ~25-35s

WireGuard PersistentKeepalive=25 keeps the encrypted transport alive, and `wg show` reports a fresh handshake. That is not enough. Proton's exit NAT/flow-state (or whatever gates scan-like patterns on their infrastructure) decays independently, and the first TCP SYN through a cold slot gets silently dropped upstream of wg0. TCP retries eventually make it through but at 2-20s of user-visible latency.

**Symptom:** `curl` from a client VLAN host to a fresh destination hangs 2-20s on TCP connect; subsequent connections to the same host are sub-second.

**Fix:** `multivpn-slot-warmup.timer` fires every 10s, issuing parallel `curl -I https://proton.me/` per slot. proton.me chosen so the keepalive doesn't leak correlation to a third party. Parallelization is load-bearing — a serial loop over cold slots takes ~20s end-to-end, pushing per-slot re-hit past the cold threshold.

**If you see the log full of `code=000 connect=0.000`:** those are expected during the cold cycle. What you want to verify is that the *next pass 10s later* shows `code=200 connect<0.5s`. If a slot stays consistently failed for many passes, that slot's Proton exit is unhealthy and rotation will eventually replace it.

**Don't "fix" this by dropping the timer cadence under 5s.** The curl requests hit proton.me — being overly aggressive is a bad-neighbor pattern and offers diminishing returns anyway.

**dns-6 is warmed the same way (landed 2026-07-12).** The dedicated DNS tunnel isn't in the rotating pool, so it used to cold-catch after idle — under light DNS load the first query after a >30s gap timed out before a retry warmed it. `slot-warmup.sh` now also fires a neutral `dig @9.9.9.9 . NS` (root NS, cached) through `ns-dns-6` every pass. Verified: a query after a 40s idle gap returns in ~24ms instead of timing out.

## Forward-chain: `client-to-private` must precede `ct state invalid drop`

UniFi is both the DHCP server on the client VLAN and the mgmt-LAN router. When a host on mgmt SSHes into a VLAN client, UniFi has a direct L3 interface on that VLAN and routes the SYN straight to the client without involving the proxy VM. But the VLAN client's default gateway *is* the proxy VM, so the SYN-ACK on the return leg traverses us — and we've never seen the SYN. Conntrack classifies the SYN-ACK as `ct state invalid` and the default hygiene rule drops it.

**Symptom:** single-homed VLAN clients are unreachable via SSH/HTTP from the mgmt LAN; dual-homing the client (adding a mgmt-NIC) "fixes" it because traffic then bypasses the proxy entirely.

**Fix (landed 2026-04-21):** in `/etc/nftables.conf` the `forward` chain places `iifname ens19 ip saddr $CLIENT_VLAN ip daddr $RFC1918 oifname ens18 accept` **before** `ct state invalid counter drop`. Only RFC1918 transit is exempt from the invalid-drop; internet-bound flows still get the strict check, so the kill-switch posture is unchanged.

**Don't try to fix this at UniFi instead.** UniFi's static-route UI refuses to install a non-/32 route via a host that's also a DHCP client on the destination network. So route-symmetry at the upstream is not available, and this forward-chain reorder is the reliable workaround. If you're ever in a position where UniFi CAN be configured with a proper non-/32 static route via 172.16.1.5, doing so and reverting the reorder is cleaner — but don't expect that to be possible.

**Test SSH from mgmt to a single-homed VLAN client** in your "before reporting success" checklist to confirm the ordering hasn't regressed.

## `@proton_api` empty after reboot blocks every mint

**Symptom:** right after a reboot, all mints fail with `server list fetch
failed: No working transports found` (the kill-switch drops the Proton API
HTTPS because the destination isn't in `@proton_api`), and `nft list set inet
filter proton_api` is empty. It stays broken until the daily
`multivpn-proton-api-whitelist.timer` fires.

**Root cause:** `multivpn-proton-api-whitelist.service` is a `oneshot` that runs
seconds into boot (`After=network-online.target`), does a single
`getent ahostsv4 vpn-api.proton.me`, and at that moment the path to the LAN
resolver (`10.0.0.22`) isn't ready — so it resolves nothing, logs
`no addresses resolved`, and exits. `flush ruleset` already emptied the set, so
it stays empty. `oneshot` can't `Restart=on-failure`, so nothing retries it.

**Fix (landed 2026-07-12):** `proton-api-whitelist` now retries resolution
(`RESOLVE_ATTEMPTS=10` × `RESOLVE_DELAY=3s`) before giving up, so a boot-time
DNS-not-ready window self-heals. This also hardens the pre-mint call
`rotate-slot.sh` makes. The daily timer remains the backstop.

**Manual unwedge if you hit an old build:** `sudo systemctl start
multivpn-proton-api-whitelist` once DNS is up, then mints work again.

## Corrupt `serverlist.json` wedges ALL minting (recurring; now serialized)

**Symptom:** every rotation fails at the mint step (`rotate-*` logs show
`mint failed` on all attempts, `ERR: all N attempts failed`), so no slot can
self-heal. A manual `proton-mint` prints `Unable to decode JSON file
"serverlist.json"` → `JSONDecodeError: Extra data: line ... (char N)` →
`VPN session could not be deserialized` → `server list fetch failed: 'NoneType'
object has no attribute 'get'` and exits 2. Because minting is dead, a single
bad exit cascades into a total client-egress outage over days (seen 2026-05-09,
and again 2026-07-12 where it had been silently broken since ~May 21).

**Root cause:** `proton-vpn-core` persists a ~23 MB shared cache at
`/var/cache/Proton/VPN/serverlist.json`. Multiple `multivpn-rotate-slot@` /
`rotate-dns` timers can fire in the same second (each `RandomizedDelaySec`, plus
`slot-warmup` auto-rotation triggers), and two `proton-mint` processes fetching
at once race on that write — leaving a complete JSON document with a stray
trailing byte. The library then can't deserialize the session (its `__setstate__`
loads the server list from cache), so even a fresh fetch fails.

**Recover (truncate-restore, no re-bootstrap needed — the SSO token is fine):**
the file is valid JSON plus junk at the tail, so keep the leading document:
```bash
sudo python3 - <<'PY'
import json
p="/var/cache/Proton/VPN/serverlist.json"
d=open(p,encoding="utf-8").read()
obj,end=json.JSONDecoder().raw_decode(d)      # first valid document
open(p,"w",encoding="utf-8").write(d[:end])   # drop the trailing byte(s)
json.load(open(p,encoding="utf-8"))           # verify
PY
sudo /etc/multivpn/bin/proton-mint --slot proton-1 --out-dir /tmp/t   # expect exit 0
```
Do NOT just delete it — with the cache absent the session still won't
deserialize; restoring a valid cache is what unblocks the fetch.

**Prevention (landed 2026-07-12):** two layers.
1. `proton-mint` takes a system-wide `flock` on `/run/multivpn-mint.lock`
   (`acquire_mint_lock`) before touching proton-vpn-core, so mints run one at a
   time regardless of how many timers fire — this closes the *concurrent-write*
   vector. The lock is fd-scoped, so a crashed mint can't deadlock the next one.
2. `proton-mint` then calls `serverlist_cache.repair()` (still under the lock):
   it validates the cache, truncate-repairs trailing junk, and — for a mid-file
   break from an *interrupted* write (reboot/kill), which truncate can't fix —
   restores from a maintained `serverlist.json.lastgood` snapshot. This is what
   makes minting self-heal after a crash instead of staying wedged. Verified
   live: a mid-file-corrupted cache is auto-restored and the mint succeeds.

If you add another caller of proton-vpn-core that writes the cache, it must take
the same lock (and ideally call `serverlist_cache.repair()` too).

## Two slots on the same Proton physical server degrade each other

If `proton-mint` happens to pick the same physical Proton server for two
different rotating slots, both their WG configs end up with identical
`Endpoint = X.X.X.X:51820` lines (Proton labels them as different "logical"
servers, e.g. `US-TX#560` vs `US-TX#561`, but they're the same physical box
with the same x25519 server pubkey and entry IP).

**Two regressions follow from a collision:**

1. **Privacy:** the public internet sees both slots as a single exit IP. So
   you have N rotating slots but <N unique exits, undermining the
   unlinkability the design assumes.
2. **Performance:** Proton's exit-side flow-state appears to coalesce both
   slots' keepalive traffic, and the warmup `curl -I https://proton.me/`
   probes from `multivpn-slot-warmup` start failing on the colliding slots
   (~30-70% pass rate vs the normal 100%). Cold-SYN drops resume on the
   client side — fresh-destination TCP connects regress from sub-200ms to
   the Linux SYN-retransmit pattern (3s, 11s).

**Fix (landed 2026-04-26):** `rotate-slot.sh` parses the `Endpoint = ` line
from each freshly-minted config and compares the IP against
`WG_ENDPOINT_IP=` in every sibling `proton-N.state` file. On collision the
mint is discarded, counted as a failed attempt, and the existing 5-attempt
retry loop tries again. After 5 failures the slot stays on its current
config (already-correct behavior).

**Symptom you'll observe if this regresses:** the `slot-warmup` per-slot
success-rate breakdown shows two slots with degraded `code=200` counts and
matching counts of `code=000`, while the other slots are clean.

```bash
sudo journalctl -t slot-warmup --since "2 min ago" --no-pager \
    | grep -oE "proton-[1-5]: code=[0-9]+" | sort | uniq -c | sort -rn
```

If you see this, check sibling endpoint IPs:
```bash
for n in 1 2 3 4 5; do echo -n "proton-$n: "; \
    sudo awk -F= '/^WG_ENDPOINT_IP=/ {print $2}' /etc/multivpn/state/proton-$n.state; done
```

If two match, the dedup either failed (bug — investigate `rotate-slot.sh`)
or the colliding pair was minted before the dedup landed (pre-2026-04-26
configs). Force-rotate one of the pair to break the tie:
`sudo systemctl start multivpn-rotate-slot@proton-N.service`.

## Health-aware dispatch: dispatcher restart required after dispatcher.py edits

`dispatcher.py` reads `/run/multivpn-slot-health/proton-N.state` on every
new-flow decision, so health changes pick up automatically. But the
dispatcher's *own* code only reloads on `systemctl restart
multivpn-dispatcher.service`. SIGHUP only re-reads `/etc/multivpn/state/`
(the instance pool), not the Python source. If you edit `_is_healthy()` or
`pick()` and SIGHUP, your changes won't take effect — restart instead.

Confirm the new code is live:
```bash
sudo journalctl -u multivpn-dispatcher.service -n 3 --no-pager
# Want to see "loaded N VPN instance(s)" *after* the timestamp of your edit.
```

## Health-state file is tmpfs

`/run/multivpn-slot-health/` is on tmpfs and disappears at boot. The
dispatcher treats a missing health file as `STATUS=ok` (the right default —
better than blocking traffic on every reboot). Within ~10s of boot,
`slot-warmup.timer` populates the directory and the dispatcher starts
filtering correctly.

If a slot is mysteriously skipped after a long no-traffic window, check
the state file directly — `cat /run/multivpn-slot-health/proton-N.state`
shows the current judgment and how it got there (FAIL_STREAK is the
useful field).

## Endpoint-collision dedup: known limitations

The dedup logic in `rotate-slot.sh` (added 2026-04-26 — see the entry above)
is intentionally simple. Two known limitations to be aware of before
extending it:

1. **Concurrent-rotation race.** Each `multivpn-rotate-slot@proton-N.timer`
   has `RandomizedDelaySec=12h` and runs as a separate systemd unit, so two
   rotations CAN start in the same ~30s window. If they do, both read the
   pre-rotation sibling state, both pick a fresh endpoint independently,
   and a fresh collision can land. The window is small (mint + stage + probe
   = ~10-30s) and the next timer fire on either slot will dedup correctly.
   Not currently fixed because the failure mode self-heals within 24h of
   the next rotation; if you find the collision rate is non-zero in steady
   state, an `flock` on `/run/multivpn-rotate.lock` around the
   mint→dedup→promote critical section is the cheap fix.

2. **IPv4-only endpoint parser.** `awk -F'[ =:]+' '/^Endpoint = / {print $2}'`
   correctly extracts `X.X.X.X` from `Endpoint = X.X.X.X:51820` but would
   split inside a bracketed IPv6 literal (`Endpoint = [2001:db8::1]:51820`)
   and produce junk. Proton's API currently returns IPv4 entry IPs only,
   so this isn't user-visible. If they ever start handing out IPv6
   endpoints, switch the parser to strip the trailing `:port` from the
   whole address-and-port token.

## Boot race: parallel slots collide on the shared `wg0` name in the main ns

**Symptom:** every boot, one or two `multivpn-proton@proton-N` slots come up as
a "zombie" — the netns exists but has no `wg0` and no routing table, and the
unit log shows `RTNETLINK answers: File exists`. Historically hit `proton-3` and
`proton-4`.

**Root cause:** all five `multivpn-proton@proton-N.service` units start in
parallel (`multivpn-proton@.service` orders them after `nftables.service` but
not against each other). Each runs `vpnns-up.sh`, which created the WireGuard
interface in the **main ns** as `wg0` before moving it into the slot's netns.
`wg0` is a single name in the shared main namespace, so two concurrent
`ip link add wg0` calls race: the loser gets `File exists`, and `set -euo
pipefail` aborts the script with the netns already created but `wg0` never made
and routing never configured.

**Fix (landed 2026-07-11):** `vpnns-up.sh` creates the link under a
per-instance-unique name `wg-${INSTANCE}` (`WG_TMP`), moves it into the netns,
then renames it to `wg0` inside the ns (`ip -n "$NS" link set "$WG_TMP" name
wg0`). Unique names never collide, so parallel boot is safe. Teardown also
`ip link del "$WG_TMP"` to clear a main-ns orphan from a prior crashed run. The
mechanic was validated on a real kernel: concurrent `ip link add wg0` reproduces
`File exists`; unique-name-then-rename does not.

**Don't** let a refactor "simplify" this back to a bare `ip link add wg0` — it
reintroduces the every-boot race. The unique name is load-bearing, not
cosmetic. (`wg-${INSTANCE}` must stay ≤15 chars; the script sanity-checks it.)

## Staging netns left behind on kill

If `rotate-slot.sh` dies between `vpnns-up.sh ...-s` and the promote-or-cleanup branch, the staging netns stays behind. Symptom: `ip netns list` shows `ns-proton-N-s`, and `ip rule` shows `from 172.31.N.1 lookup 10N` / `fwmark 0x65+N lookup 20N` for the orphan.

Cleanup: `vpnns-down.sh proton-N-s` handles the netns + state file + standard rules. Verify `ip rule` is clean afterward.
