# Gotchas

Non-obvious behaviors we hit during build-out. Each one cost real time; if you're about to make a similar change, read the relevant entry first.

## An empty slot table routes VPN traffic out the uplink

**Symptom (confirmed on the reference gateway with a capture):** every time a slot is rebuilt (promotion, `systemctl restart proteus-proton@…`, a DNS rotation), a burst of client packets leaves the **management uplink** un-tunnelled, still carrying their client-VLAN source address. The window was ~220 ms per rebuild on a healthy run. A rebuild that aborted half way held it open until the next good run, and a stopped slot held it open for as long as it stayed stopped. The upstream router happened to drop the packets as spoofed; nothing on the gateway did.

**Cause.** Policy routing does not stop at a table that has no matching route: `ip rule fwmark N lookup 10N` over an **empty** table 10N simply moves on to the next rule, and ends in `main`, whose default route is the uplink. `vpnns-up.sh` used to delete the fwmark rule and flush the table before rebuilding, and the table empties by itself anyway the moment the old veth is deleted. `vpnns-down.sh` deleted both. The firewall did not catch it either: `client-marked-to-vpn` and `ct state established,related accept` had no output-interface check, and there was no NAT or postrouting guard on the uplink.

Three more paths end the same way, because each leaves a dispatched flow with **no mark at all**, and an unmarked packet routes via `main`:
- A trusted range removed while one of its flows is established. `prerouting_mangle` no longer restores that flow's mark.
- A flow the NFQUEUE dispatcher placed. Its verdict sets the packet mark only; conntrack learned the mark from the map entry the dispatcher writes, on the flow's second packet. If that entry was missing by then (insert failed or timed out, map full, a reload or janitor eviction in between), the rest of the flow was unmarked, and an established TCP flow never goes back to the queue.
- No ruleset. A hand-run `nft flush ruleset`, Debian's stock `systemctl restart nftables` (it flushes before it reloads) or `stop` (it leaves the box flushed), and a ruleset that fails to load at boot all leave it a plain router. Nothing restores any mark. The proteus drop-in for nftables.service removes the flush from restart and stop (see operations.md), but the routing layer below must hold without it.

**Fix: two layers, routing and firewall, each tested on its own.** `tests/rebuild_leak_sim.sh --matrix <pre-fix ref>` runs every scenario against each layer alone.
1. Routing (`routeguard.sh`), which needs no nftables:
   - Every slot table ends in `blackhole default metric 4294967295`, installed before any teardown. Rules are **kept** across rebuild and stop, so a slot is either routed through its veth or dropped, never `main`.
   - One static `not fwmark 0x0/0xffffffff blackhole` rule at pref 32000 catches a mark with no slot rule. Typed without the mask, `not fwmark 0` stores mark 0/mask 0 and matches nothing (`ip rule` then lists it as `not from all blackhole`), so re-run `routeguard.sh` rather than adding it by hand.
   - The ingress sink: `iif <client iface> lookup 900` and `iif wg-udm lookup 900` at pref 32020, where table 900 is `default dev proteus-null` (a dummy device), with RFC1918 destinations sent to `main` first at pref 32010. It keys on the ingress interface, so it holds for a flow that lost its mark and for a box with no ruleset.
   - `proteus-routeguard.service` arms the catch rule and the sink at boot, before any interface comes up and without waiting for nftables.service. Before it, the first arming was the first slot's `vpnns-up.sh` or the dispatcher's `ExecStartPre`, both after `network-online.target`, so a ruleset that failed to load at boot left clients a plain router until then. That early run keys the client interface on `PROTEUS_CLIENT_IFACE` by name (the rule attaches when udev names the NIC); on a box with only `PROTEUS_CLIENT_GW_IP` it covers `wg-udm` alone until the first slot comes up or the dispatcher starts. The name must be the NIC's primary name, not one of its altnames (`ip link` lists them as `altname`): the kernel attaches a waiting rule by primary name only, so a rule armed early on an altname stays detached for the whole boot, and nftables' `iifname` never matches an altname either. `routeguard.sh` warns about one once the network is up.
   - systemd-networkd deletes every ip rule and route it did not configure itself (`ManageForeignRoutingPolicyRules=` and `ManageForeignRoutes=` in `networkd.conf`, both on by default), and with them this whole layer, the slot rules and sentinels included. On a box whose network networkd runs, set `ManageForeignRoutingPolicyRules=no` and `ManageForeignRoutes=no` in a `/etc/systemd/networkd.conf.d/` drop-in. ifupdown does not touch them.
2. Firewall (`nftables.conf` and its template):
   - `chain prerouting_ctsave` copies the dispatcher's verdict into conntrack, so a dispatched flow keeps its slot for life.
   - `chain forward` opens with guards that drop meta-marked, and original-direction ct-marked, packets headed anywhere but `v-proton-*` (counter `marked_leak_fwd`), then `unmarked-client-egress`, which drops unmarked traffic from the client interface or `wg-udm` to a public address. The marked accepts are `oifname "v-proton-*"`-scoped too.
   - `chain postrouting_guard` is the last line for forwarded and local traffic alike: marked egress is allowed only via `v-proton-*`, the DNS veth and `lo` (counter `marked_leak_post`).
   - `chain output` drops the box's own ICMP errors about the reply leg of a dispatched flow (`own-icmp-error-for-tunnelled-flow`, counter `own_icmp_err_tunnelled`). When a client leaves the VLAN while a remote keeps sending, the box answers the remote with host-unreachable. Conntrack files that error as RELATED in the original direction with the flow's ct mark, but its meta mark is 0, so with the default `net.ipv4.icmp_errors_use_inbound_ifaddr=0` it routes via `main` out the uplink from the box's own address, quoting the client's VLAN address and port. The rule matches only errors headed off-tunnel: with that sysctl at 1 the error is sourced from the slot's transit address, routes into the slot veth and reaches the remote, and is left alone. Routing cannot see it (mark 0, `iif lo`); without this rule `postrouting_guard` catches it and `marked_leak_post` moves every day for no routing fault.

The firewall cannot cover its own absence, so the no-ruleset case is the routing layer's alone; every other case is closed by either layer on its own.

**Don't regress it:**
- Never `ip route flush table <slot table>` or `ip rule del` a slot rule in a code path that can run while traffic flows. Delete the specific route (`ip route del default via <transit> table N`), never the sentinel.
- Sentinels and the catch rule are `blackhole`, not `unreachable`. Both stop the leak, but `unreachable` answers the client with ICMP host-unreachable, and a client TCP stack aborts `connect()` on that at once: a few failed connects on every promotion. `blackhole` drops silently and the client's SYN retransmit lands in the rebuilt tunnel.
- `routeguard.sh TABLE` and `rg_sentinel_ensure` take slot tables only: 101..300 except 253..255. A blackhole default anywhere else does damage: in 255 (local) it cuts the box off, 0 and 254 are `main`, and in 900 it would drop every tunnel reply at the reverse-path check once the sink's device route went missing. Don't widen the check; a new table range belongs in `rg_table_ok` with its reason.
- The ingress sink must be a route to a real device, never `blackhole` or `unreachable`. With `rp_filter` on, a tunnel's reply to a client is validated by looking up its public source as if it had arrived on the client interface, which lands on the pref-32020 rule. A non-unicast answer there drops every tunnel reply.
- `rp_filter` must be 0 or 2, never 1, and `net.ipv6.conf.all.forwarding` must stay 0. Both come from `etc/sysctl.d/90-proxy-hardening.conf`, which the installer copies to `/etc/sysctl.d/` under the same name and loads; the file's comments give the reason for each value. Strict mode drops every tunnel reply, with the sink or without it: the lookup above never ends on the slot veth the reply came in on. The kernel uses the higher of `conf.all` and an interface's own value, so the file's `conf.all.rp_filter=2` also covers an interface set to 1. IPv6 forwarding off is what keeps client IPv6 from being routed when no ruleset is loaded, because the sink and its RFC1918 exemptions are IPv4-only. `tests/sysctl_hardening_test.sh` pins the values and reproduces the strict-mode drop.
- Keep `ct direction original` on the ct-mark guards. Replies to clients carry the flow's ct mark out the client interface (including the client-DNS redirect, whose flow is dispatched before the DNAT) and must pass.
- `fwmark_reflect` must stay 0 (the installer pins it in `99-proteus.conf`). With it on, the ICMP errors and TCP RSTs the box sends to a client inherit the flow's mark, and policy routing sends them into the slot tunnel instead of straight back out the client interface. The guards do not drop them (a slot veth is an allowed way out), so no counter shows it. `tcp_fwmark_accept` must stay 0 for a similar reason (pinned in `90-proxy-hardening.conf`): a client's TCP DNS query reaches unbound already marked, because the flow is dispatched before the redirect, and with it on unbound's accepted socket takes that mark and its answers route into the slot tunnel.
- Keep `own-icmp-error-for-tunnelled-flow` above `ct state established,related accept` in chain output. Below it, the accept passes the errors and they leave the uplink on any box whose `postrouting_guard` has been edited away.
- Reload with `nft -f` or `systemctl reload nftables`. `systemctl restart nftables` is only safe while `/etc/systemd/system/nftables.service.d/proteus.conf` is in place: without it, restart flushes the ruleset before reloading and stop leaves none (see operations.md).

## Re-adding the trusted-egress rules routed replies out the uplink

**Symptom:** none anyone saw; found in review. Every run of `proteus-trusted-egress.sh` (boot, every web UI save, every pairing) opened a window of a few milliseconds in which a slot's reply to a host on a trusted range left the management uplink. It only happens when the router does not masquerade into the tunnel: a masquerading router sends everything from the tunnel address, and replies to that are on-link on `wg-udm`.

**Cause.** The reply comes out of the slot namespace, which has a return route per trusted range, and `to <range> lookup 110 pref 100` sends it to `wg-udm`. The script deleted every rule at prefs 100, 95 and 90 and flushed table 110 before adding them back, and in between the lookup fell through to `main`. The forward chain accepts the packet as established, and the marked-traffic guards only look at the original direction. Removing a range, or switching the feature off, was worse: the slots kept their return routes, so that range's replies left the uplink until its flows ended or the slot rotated.

**Fix.**
- Make before break. The script adds what the new list needs first (table-110 routes, then pref 90, then pref 95 and pref 100 per range), then reads the installed rules and routes back with `ip -j` and removes only the stale ones: pref 100 first, pref 90 last, table-110 routes after the rules that led to them. A rule that stays is never touched, and table 110 is never flushed while the feature is on.
- A removed range's return routes leave the slots before its rules go. Without the route, a reply stays in the slot and follows its default route into its own tunnel, as it did before the feature existed. If a slot cannot be cleaned, the stale rules are kept and the run fails, so systemd retries it.
- Table 110 ends in `blackhole default metric 4294967295`, like the slot tables. When `wg-udm` goes down or is deleted, the kernel removes every route through it, and a pref-100 lookup then ends in the blackhole instead of `main`.
- Switching off (an empty list, or no pairing) closes the gate, then removes the slot return routes, then the rules with pref 90 last, then, when unpairing, the interface. If a slot cannot be cleaned, the rules and table 110 stay and the run exits 1 so systemd retries it: the slot's replies then reach `wg-udm` (or the catch, once the interface is gone) instead of `main`. Pref 90 stays with them, so the web UI is not affected.
- The tunnel subnet has its own pref-100 rule and table-110 route. Its replies otherwise use `wg-udm`'s connected route in `main`, which goes with the device, and would then leave by `main`'s default route.
- `ip rule add` failing "File exists" is not taken as proof the rule is installed. The kernel's duplicate test ignores any selector the new rule leaves out, so `from <mgmt ip> to X lookup main pref 90` blocks `from <mgmt ip> lookup main pref 90`. The script reads the rules back, removes such a look-alike and adds the rule again; one it may not remove (it carries a `tos`, say) fails the run before anything after it is applied.
- Slot cleanup leaves any return route that overlaps the client VLAN. `vpnns-up.sh` adds that one for the CIDR the slot was built with, and an installer apply that changes `PROTEUS_CLIENT_VLAN_CIDR` does not rebuild running slots.

**Don't regress it:**
- No `ip rule del pref N` or `ip route flush table 110` in the reconcile path. Those are for teardown only.
- Pref 90 goes in before any pref-100 rule and comes out after the last one. Without it, the web UI's replies to a trusted-VLAN host go down the tunnel.
- Don't swap the teardown order for a lasting `to <range> blackhole` rule. With the feature off, pref 90 and 95 are gone, and that rule would drop the web UI's replies and the client VLAN's pivot to the range.
- Don't read "File exists" from `ip rule add` as success on its own; check the rule is really there.

## `type route` hook doesn't reliably reroute on this kernel

**Kernel:** 6.12.74 (Debian 13 trixie).

Intent: mark locally-generated packets from uid `unbound` with fwmark `0x6` so `ip rule fwmark 0x6 lookup 106` routes them out the `v-dns-6` veth.

```nft
chain output_route {
    type route hook output priority mangle; policy accept;
    meta skuid "unbound" meta mark set 0x6;
}
```

Mangle fires — diagnostic counter on the rule shows skuid match and mark set. But the routing decision is **not** re-evaluated after the mark lands: packets still egress the main-table default (ens18). `ip route get 10.2.0.1 mark 0x6` correctly returns `via 172.31.6.2 dev v-dns-6 table 106` at the CLI, so the rule/table are fine — the reroute just doesn't happen inside netfilter's output path.

That address is no longer just a convenient example. Since the resolver forwards to `10.2.0.1` (in-tunnel NetShield), the upstream is RFC1918, so a routing fallback out ens18 matches the kill-switch's private-networks accept instead of hitting the default drop — a cleartext query on the mgmt LAN rather than a dropped packet. `chain output` therefore carries an explicit `unbound-dns-killswitch` rule (uid `unbound`, daddr `10.2.0.1`, `oifname != "v-dns-6"` → log + drop) placed above the ct-established accept. Don't reorder it below, and don't delete it if you change upstreams.

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

- `repopulate-wg-peers.sh` (scans `/etc/proteus/state/*.state`)
- `proteus-proton-api-whitelist.service` (resolves `vpn-api.proton.me` + siblings)

**After any nft reload**, run both, in this order: reload → repopulate → restart dependent services. `operations.md` → "Deploy a config change to nftables safely" has the full sequence. If you skip it: all WG handshakes start failing silently within a keepalive interval because the kill-switch no longer permits them.

`systemctl restart nftables` and `systemctl reload nftables` do this for you: the proteus drop-in runs `proteus-nft-repopulate.sh` after every load, which queues these two and the refills for `@client_pivot` and `@trusted_src`. A hand-run `nft -f` does not.

## The netns default resolver would leak, so we bind-mount

Main ns's `/etc/resolv.conf` points at the lab's AdGuard resolver (`10.0.0.22`), which is unreachable from inside a tunnel ns (the kill-switch would drop it, and even if it didn't, using the LAN's resolver for client traffic would be a DNS leak).

`ip netns exec <ns>` consults `/etc/netns/<ns>/resolv.conf` if present and bind-mounts it over `/etc/resolv.conf` for spawned processes. `vpnns-up.sh` writes `DNS_UPSTREAMS` (Quad9) into that file for every netns it creates. Removing this file (or relying on systemd-resolved's stub) reintroduces the leak.

This is the *probe* path, not the gateway resolver. Unbound forwards clients to `10.2.0.1` (`UNBOUND_UPSTREAM`, in-tunnel NetShield); the namespaces stay on a public unfiltered resolver on purpose. Repointing `DNS_UPSTREAMS` at NetShield would couple exit health-checking to an ad blocklist — add an ad domain to the custom check list and every exit fails its probes, wedging rotation. Keep the two variables separate.

## Fresh tunnels throw transient TLS "unexpected eof"

First HTTPS connection through a freshly-minted WG tunnel sometimes aborts with OpenSSL `SSL_read: unexpected EOF`. It's not a config issue — appears to be a warm-up artifact on Proton's end (possibly MTU-discovery-related). Curl invocations inside staging netns use `--retry 3 --retry-all-errors --retry-delay 2 --max-time 12` so the second or third try wins. Don't remove the retry flags.

## Dig `+short` + bogus subdomain → empty output looks like a timeout

If you test the resolver with `dig @127.0.0.1 +short rand-123.example.org A | head -1`, NXDOMAIN returns empty output — indistinguishable from a timeout in a shell script. We wasted 20 minutes thinking DNS was broken because of this.

Use real TLDs for smoke tests (`cloudflare.com`, `debian.org`, …) or check `dig`'s status field directly instead of relying on empty stdout as a signal.

## Unbound UDP retry budget is tight on first queries

A cold-cache name still costs several sequential upstream queries because of qname-minimisation, and any one lost UDP datagram burns unbound's initial timeout (376ms) before the retry. That is enough to blow past `dig`'s `+time=3` even though the hop to `10.2.0.1` is only 11-16ms. Use `+time=5 +tries=2` for hand-tests. ~95% pass rate at `+time=3`, ~100% at `+time=5`. Not worth tuning — just set client timeouts reasonably.

The old form of this entry blamed `tunnel RTT + Quad9 RTT` (~150-200ms) plus TCP fallback for a large DNSSEC chain. Both halves are gone: the upstream is in-tunnel and the validator is off (`module-config: "iterator"`), so there is no chain to fetch. If you ever point `UNBOUND_UPSTREAM` back at a public resolver, the validator comes back with it and so does that failure mode.

## SIGHUP to the dispatcher re-reads state, not code

`proteus-dispatcher.service` reloads the instance pool on SIGHUP — but only by re-running `load_instances()` on the already-imported Python module, and not at once: the handler sets a flag, and the next pick or janitor pass does the reload (see `_install_signal_handlers` in `dispatcher.py` and operations.md → "Add or replace a slot"). The janitor re-reads the state files on every pass as well, so a missed SIGHUP costs at most a minute (about a second while the list is empty: then a new flow re-reads it too). Code changes in `dispatcher.py` require a full `systemctl restart`. The line in `journalctl` you want to confirm is "loaded N VPN instance(s): …" after the restart.

## Don't query AbuseIPDB / Scamalytics from the mgmt IP

This path is deliberately closed. Querying from the mgmt IP (`10.0.0.121`) correlates "mgmt IP just asked about exit IP X" on a non-privacy-centric vendor's logs — exactly the correlation Proton's privacy model is designed to avoid. Empirical probes from *inside* the staging netns test what actually matters (does the exit behave normally) without creating that correlation.

AbuseIPDB is kept as a documented fallback if empirical probes later prove insufficient, but the default path is always in-tunnel probes first. If you add a new reputation signal, it also runs inside the netns.

## Reddit advisory is deliberate — don't promote it to mandatory

Reddit 403s a large fraction of Proton streaming exits **by policy, not by reputation**. Observed 3/5 streaming-pool slots getting 403 at Reddit despite clean mandatory probes. If you make Reddit mandatory, rotation will usually fail because *every* candidate Proton gives you has Reddit blocked.

Keep it advisory (reports "ADVISORY BLOCK: reddit" in the log but doesn't fail the verdict) unless the tier structure changes.

## A client can go around Proteus if the router lets it

Proteus is the client VLAN's advertised gateway, but a device that ignores DHCP (a static setup, a buggy app, anything hostile) can send its traffic to any other router on the VLAN. If the upstream router holds an address there and forwards that VLAN to the internet, that device reaches the internet under the home IP and Proteus never sees a packet. IPv6 is the same: router advertisements on the VLAN hand every client a route that skips Proteus, which forwards IPv4 only. Nothing on the gateway can stop either one; the router's own policy is the control.

Check both from a host on the client VLAN, without touching its normal routing. Give one test socket a private firewall mark and a policy rule that sends only that mark via the router's client-VLAN address:

```bash
sudo ip route add default via <router's client-VLAN address> dev <client iface> table 4242
sudo ip rule add pref 900 fwmark 0x4242 lookup 4242
# fetch an IP-echo URL over a socket with SO_MARK 0x4242, bound to the host's client-VLAN address:
# it must time out. The same fetch without the mark must succeed and show a VPN exit.
sudo ip rule del pref 900 fwmark 0x4242 lookup 4242; sudo ip route flush table 4242
```

Confirm the router is really on the VLAN (it answers ARP and ping there), or a timeout proves nothing. For IPv6: the gateway's client interface accepts router advertisements, so `ip -6 route show default` empty and only a link-local address on it means nothing is advertising.

Re-check after router firmware updates and firewall or zone changes: the protection lives in the router's configuration, not here.

## The UniFi IPS sometimes drops SSH to the VM

This is **not** the VM's kill-switch. If SSH times out and you see no output-chain drops on the VM side (via console) and the SSH counters look normal, suspect the upstream IPS rule before the kill-switch — the fix is at the router, which has a toggle for it.

**Rule**: don't sit in a reconnect loop on an SSH timeout. Get on the console and confirm the VM is actually receiving the TCP SYN before you touch the VM firewall.

## Verify live SSH source before narrowing inbound rules

Before any change that tightens `input` on `ens18`, run:

```bash
ss -tnp | grep :22
```

Confirm the source IP of your own session and that the `ssh-mgmt` rule accepts that address. Past incident: SSH was locked out when an inbound rule was narrowed on a stale assumption about the admin source IP, and recovery needed console access. The `systemd-run --on-active=900` revert timer in `operations.md` → "Deploy a config change to nftables safely" exists *because* of this.

## `type route` and `type filter` on the same hook coexist

They evaluate in priority order (mangle -150 → filter 0). Both see the packet. If you delete or modify the route chain, the filter chain is unaffected and vice versa. Safe to iterate on one without touching the other.

## conntrack entries survive across nft reloads

Flushing the ruleset doesn't wipe conntrack. If you change how marking works mid-flow, existing flows will continue using whatever ct mark they acquired before the change. For a clean test, drain flows with `conntrack -F` — but be aware this breaks any live sessions transiting the box.

## `ip rule` survives `nft -f`

`ip rule`/`ip route` are kernel policy-routing state, completely independent of nftables. An `nft -f` reload does not touch them. This is why the source-IP rule we added manually for dns-6 survived our subsequent ruleset swap — but don't rely on it: always install persistent rules in `vpnns-up.sh` so they're reproduced at every boot.

## Unbound socket goes stale when v-dns-6 is recreated

Unbound binds a UDP source socket to `172.31.6.1` (the main-ns side of v-dns-6) via `outgoing-interface:`. When `rotate-dns.sh` does `vpnns-down.sh dns-6 && vpnns-up.sh dns-6 <new-conf>`, the veth is destroyed and recreated with the same IP — but unbound's existing socket is now bound to a dead interface and all queries silently vanish (no `SERVFAIL`, no log — `dig` just times out).

**Symptom:** dns-6 handshake fresh, `ip netns exec ns-dns-6 dig @10.2.0.1 . NS` answers, but `dig @172.16.1.5` hangs.

**Fix:** `systemctl restart unbound` at the end of `rotate-dns.sh` (adds ~1-2s DNS gap to the swap). `unbound-control flush_infra all` is *not* sufficient — it clears RTT data but doesn't rebind the socket.

If you add another caller that recreates v-dns-6 (e.g., a future staged rotation), include the unbound restart.

## `unbound-checkconf` on the drop-in alone green-lights configs that kill unbound

Cost us client DNS on 2026-08-06. `unbound-checkconf /etc/unbound/unbound.conf.d/proteus-dns.conf` exits 0 on a config that aborts the daemon at startup, because in isolation the drop-in has nothing to collide with — the distro's other drop-ins aren't parsed. Always check the merged tree:

```bash
sudo unbound-checkconf            # no arguments — reads /etc/unbound/unbound.conf and its includes
sudo systemctl restart unbound && sudo systemctl is-active unbound
dig +short @172.16.1.5 cloudflare.com A
```

**What the drop-in-only check missed:** `domain-insecure: "."`. It registers a *static* root trust anchor, which collides with Debian's autotrust anchor in `unbound.conf.d/root-auto-trust-anchor-file.conf` — a package file this repo does not manage, and therefore not part of a single-file check. Result: `trust anchor for '.' presented twice` → `validator: could not apply configuration settings` → `fatal error: failed to init modules`. It was never needed either: `module-config: "iterator"` already drops the validator, which makes everything insecure and leaves the autotrust anchor harmlessly unread. Don't add it back.

**Two more that even a full checkconf won't catch, because they're runtime:**

- **AppArmor.** Unbound runs under an **enforce**-mode profile (`/etc/apparmor.d/usr.sbin.unbound`), which grants `/etc/unbound/**`, `/var/lib/unbound/**`, `/usr/share/dns/root.*` and `/run/unbound.{pid,ctl}` on top of the `abstractions/base`, `nameservice` and `openssl` includes. Point a directive at a path outside all of that — a key file, a hints file — and it parses fine, then dies at startup with `Permission denied`. Read the profile rather than guessing which paths are covered: the `openssl` abstraction is why `tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt` works despite being outside the explicit list. Confirm a suspected denial with `journalctl -k | grep apparmor.*unbound`.
- **Backups left in `unbound.conf.d/`.** They're inert *only* because the include glob is `*.conf`. Save one as `proteus-dns-old.conf` and it gets parsed too: a duplicate `interface:` (bind conflict) plus a second `forward-zone "."`. Suffix backups `.bak` or `.YYYYMMDD`, or park them outside the directory.

**Restart inside the deploy window, not later:** `rotate-dns.sh` runs `systemctl restart unbound` on every DNS-tunnel rotation. Anything that survives checkconf but dies on restart won't surface when you deploy — it takes DNS down at the next unattended rotation, hours later, with nobody watching. Restart and verify resolution *inside* your deploy window, every time.

## Stable `proton-N.conf` symlink must be kept in sync with promoted config

`rotate-slot.sh` writes a new timestamped config and calls `vpnns-up.sh` with that fresh path directly — but the `proteus-proton@.service` boot unit reads the stable symlink `/etc/proteus/wg/proton/auto/proton-N.conf`. If the symlink isn't updated on promotion, the next reboot (or any `systemctl restart proteus-proton@proton-N`) silently reverts the slot to whatever config the symlink still points at — typically the *pre-rotation* one that may have been bad enough to trigger the rotation in the first place.

**Fix (landed 2026-04-21):** `rotate-slot.sh` now runs `ln -sfn "$good_conf" "${AUTO_DIR}/${SLOT}.conf"` right after the promote-time `vpnns-up.sh` call, before the "promoted" log line.

If you're debugging and see a slot's wg0 endpoint suddenly revert to an old IP after a restart, check the symlink target vs the `WG_CONF=` line in `/etc/proteus/state/proton-N.state`. They should match.

## Proton exit-side flow state goes cold in ~25-35s

WireGuard PersistentKeepalive=25 keeps the encrypted transport alive, and `wg show` reports a fresh handshake. That is not enough. Proton's exit NAT/flow-state (or whatever gates scan-like patterns on their infrastructure) decays independently, and the first TCP SYN through a cold slot gets silently dropped upstream of wg0. TCP retries eventually make it through but at 2-20s of user-visible latency.

**Symptom:** `curl` from a client VLAN host to a fresh destination hangs 2-20s on TCP connect; subsequent connections to the same host are sub-second.

**Fix:** `proteus-slot-warmup.timer` fires every 10s, issuing parallel `curl -I https://proton.me/` per slot. proton.me chosen so the keepalive doesn't leak correlation to a third party. Parallelization is load-bearing — a serial loop over cold slots takes ~20s end-to-end, pushing per-slot re-hit past the cold threshold.

**If you see the log full of `code=000 connect=0.000`:** those are expected during the cold cycle. What you want to verify is that the *next pass 10s later* shows `code=200 connect<0.5s`. If a slot stays consistently failed for many passes, that slot's Proton exit is unhealthy and rotation will eventually replace it.

**Don't "fix" this by dropping the timer cadence under 5s.** The curl requests hit proton.me — being overly aggressive is a bad-neighbor pattern and offers diminishing returns anyway.

**dns-6 is warmed the same way (landed 2026-07-12).** The dedicated DNS tunnel isn't in the rotating pool, so it used to cold-catch after idle — under light DNS load the first query after a >30s gap timed out before a retry warmed it. `slot-warmup.sh` now also fires a neutral `dig @10.2.0.1 . NS` (root NS, cached) over UDP through `ns-dns-6` every pass — same address unbound forwards to, so the warmed path is the one clients use. Verified: a query after a 40s idle gap returns in ~24ms instead of timing out.

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
`proteus-proton-api-whitelist.timer` fires.

**Root cause:** `proteus-proton-api-whitelist.service` is a `oneshot` that runs
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
proteus-proton-api-whitelist` once DNS is up, then mints work again.

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
`/var/cache/Proton/VPN/serverlist.json`. Multiple `proteus-rotate-slot@` /
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
sudo /etc/proteus/bin/proton-mint --slot proton-1 --out-dir /tmp/t   # expect exit 0
```
Do NOT just delete it — with the cache absent the session still won't
deserialize; restoring a valid cache is what unblocks the fetch.

**Prevention (landed 2026-07-12):** two layers.
1. `proton-mint` takes a system-wide `flock` on `/run/proteus-mint.lock`
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
   probes from `proteus-slot-warmup` start failing on the colliding slots
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
    sudo awk -F= '/^WG_ENDPOINT_IP=/ {print $2}' /etc/proteus/state/proton-$n.state; done
```

If two match, the dedup either failed (bug — investigate `rotate-slot.sh`)
or the colliding pair was minted before the dedup landed (pre-2026-04-26
configs). Force-rotate one of the pair to break the tie:
`sudo systemctl start proteus-rotate-slot@proton-N.service`.

## Health-aware dispatch: dispatcher restart required after dispatcher.py edits

`dispatcher.py` reads `/run/proteus-slot-health/proton-N.state` on every
new-flow decision, so health changes pick up automatically. But the
dispatcher's *own* code only reloads on `systemctl restart
proteus-dispatcher.service`. SIGHUP only re-reads `/etc/proteus/state/`
(the instance pool), not the Python source. If you edit `_is_healthy()` or
`pick()` and SIGHUP, your changes won't take effect — restart instead.

Confirm the new code is live:
```bash
sudo journalctl -u proteus-dispatcher.service -n 3 --no-pager
# Want to see "loaded N VPN instance(s)" *after* the timestamp of your edit.
```

## Health-state file is tmpfs

`/run/proteus-slot-health/` is on tmpfs and disappears at boot. The
dispatcher treats a missing health file as `STATUS=ok` (the right default —
better than blocking traffic on every reboot). Within ~10s of boot,
`slot-warmup.timer` populates the directory and the dispatcher starts
filtering correctly.

If a slot is mysteriously skipped after a long no-traffic window, check
the state file directly — `cat /run/proteus-slot-health/proton-N.state`
shows the current judgment and how it got there (FAIL_STREAK is the
useful field).

## Endpoint-collision dedup: known limitations

The dedup logic in `rotate-slot.sh` (added 2026-04-26 — see the entry above)
is intentionally simple. Two known limitations to be aware of before
extending it:

1. **Concurrent-rotation race.** Each `proteus-rotate-slot@proton-N.timer`
   has `RandomizedDelaySec=12h` and runs as a separate systemd unit, so two
   rotations CAN start in the same ~30s window. If they do, both read the
   pre-rotation sibling state, both pick a fresh endpoint independently,
   and a fresh collision can land. The window is small (mint + stage + probe
   = ~10-30s) and the next timer fire on either slot will dedup correctly.
   Not currently fixed because the failure mode self-heals within 24h of
   the next rotation; if you find the collision rate is non-zero in steady
   state, an `flock` on `/run/proteus-rotate.lock` around the
   mint→dedup→promote critical section is the cheap fix.

2. **IPv4-only endpoint parser.** `awk -F'[ =:]+' '/^Endpoint = / {print $2}'`
   correctly extracts `X.X.X.X` from `Endpoint = X.X.X.X:51820` but would
   split inside a bracketed IPv6 literal (`Endpoint = [2001:db8::1]:51820`)
   and produce junk. Proton's API currently returns IPv4 entry IPs only,
   so this isn't user-visible. If they ever start handing out IPv6
   endpoints, switch the parser to strip the trailing `:port` from the
   whole address-and-port token.

## Boot race: parallel slots collide on the shared `wg0` name in the main ns

**Symptom:** every boot, one or two `proteus-proton@proton-N` slots come up as
a "zombie" — the netns exists but has no `wg0` and no routing table, and the
unit log shows `RTNETLINK answers: File exists`. Historically hit `proton-3` and
`proton-4`.

**Root cause:** all five `proteus-proton@proton-N.service` units start in
parallel (`proteus-proton@.service` orders them after `nftables.service` but
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

If `rotate-slot.sh` dies between `vpnns-up.sh ...-s` and the promote-or-cleanup branch, the staging netns stays behind. Symptom: `ip netns list` shows `ns-proton-N-s`.

Cleanup: `vpnns-down.sh proton-N-s` removes the netns, the state file and the staging tunnel route. The two staging rules, `from 172.31.(100+N).1 lookup 20N` and `fwmark 0x(64+N) lookup 20N`, **stay** by design: they point at a table that now holds only the blackhole sentinel (see "An empty slot table routes VPN traffic out the uplink"). Don't delete them. Instead, check the table still has its sentinel: `ip route show table 20N` should print `blackhole default metric 4294967295`.

## Per-slot persistent WG keys (not one shared session key)

**Root cause of the 2026-08 "flaky TLS" reports (worst on clients hitting a
single-origin API host):** every tunnel (proton-1..N + dns-6) shared ONE
Proton WireGuard identity. `proton-mint` reused the account's single
session-mode key (`vpn_credentials.pubkey_credentials.wg_private_key`) for every
slot — its old docstring claimed "a fresh keypair per mint" but the code did the
opposite. Proton's session model is one key = one active tunnel; fanning that
key across 5+1 concurrent servers makes Proton's control plane roll the key's
authorized session between servers, so each slot goes dark for ~13-18s every
30-70s (synchronized across slots, underlay clean, each window ended by a forced
re-handshake). A client that reuses one long-lived connection (e.g. to an AWS
Global Accelerator anycast IP) rides through it; a client that opens a fresh
TCP+TLS per request to a single-origin host eats a TLS-EOF or connect-timeout
whenever a request lands in a blackout. Proven by A/B: a slot moved to its own
key went 50/50 clean while shared-key slots failed 20-30%.

**Fix (2026-08):** `proton-mint` now registers a **persistent** certificate
(`Mode: "persistent"` + a unique `DeviceName` on the `/vpn/v1/certificate` POST
— the shipped `proton-vpn-core` omits both, which is why an earlier fresh-key
attempt "failed the handshake": session-mode keys don't coexist). Each slot owns
one persistent key in `/etc/proteus/wg/proton/keys/<slot>.ed25519`, registered
ONCE (Proton 409s a re-registered key: "ClientPublicKey fingerprint conflict"),
and the keyfile is written only on a successful POST so its presence means
"registered". Rotation reuses the key and changes only the server. Persistent
keys coexist, each counts as one concurrent connection against the account cap,
and work on any server with no re-POST. Certs are minted for 365 days; refresh
by regenerating the key (`proton-mint --slot X --force-new-key`) since an
existing key can't be re-certified.

**Gotchas:** (1) persistent device entries are prunable ONLY via
account.protonvpn.com (DELETE needs full web-login scope) — don't churn a new
key per rotation or the dashboard fills with dead devices. (2) `--force-new-key`
leaves the old device behind until its cert expires. (3) Inventory with
`proton-mint --list`.
