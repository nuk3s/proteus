#!/usr/bin/env python3
"""trusted.py — which source ranges may use the rotating exits, and the UDM pairing.

One definition of the trusted-source list, shared by everything that needs it:
the nftables reconcile script, the namespace return routes, the dispatcher's
pinning rule and the web UI. Importable (stdlib only) and a CLI so the bash
side can ask the same question and get the same answer.

The file holds operator ranges only. The tunnel's own subnet is added by the
callers that need it, because whether the UDM masquerades into the tunnel is a
property of the UDM rather than of the operator's intent, and the answer is not
known until a real UDM is paired.

An empty list means the feature is off. Every consumer is written so that off
reproduces the pre-feature behaviour exactly, which is what makes this safe to
ship dark.

CLI:
  trusted.py list [--file /etc/proteus/trusted.json]
                   [--mgmt-cidr CIDR] [--client-cidr CIDR]   one CIDR per line
  trusted.py addr --cidr 10.99.99.0/30 [--which proteus|udm]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys

DEFAULT_PATH = "/etc/proteus/trusted.json"
MAX_TRUSTED = 8

# RFC 1918 only. ipaddress.IPv4Network.is_private also covers the wider IANA
# special-purpose registry (loopback, link-local, and the TEST-NET-* /
# documentation ranges), so a public-facing example range like
# 198.51.100.0/24 reads as "private" there even though it is not operator
# address space and must be rejected.
_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def is_private(net: ipaddress.IPv4Network) -> bool:
    """True iff `net` is RFC 1918 private space — not the same question as
    `ipaddress.IPv4Network.is_private`, which is broader (also loopback,
    link-local, TEST-NET-*, etc.) and wrong for this purpose; see `_RFC1918`
    above. Public now that dispatcher.py calls it too, not just this module.
    """
    return any(net.subnet_of(block) for block in _RFC1918)


def _net(value) -> ipaddress.IPv4Network | None:
    """Parse a CIDR strictly. `10.0.0.1/24` is an operator typo, not a request
    to silently widen to `10.0.0.0/24`, so host bits are an error rather than
    something we quietly discard."""
    try:
        return ipaddress.IPv4Network(str(value), strict=True)
    except (ValueError, TypeError):
        return None


def _lenient_net(value) -> ipaddress.IPv4Network | None:
    """Parse a *boundary* CIDR (the management subnet or client VLAN, not a
    trusted entry) permissively. Unlike a trusted entry, this value is only
    ever used to test containment, so "172.20.0.119/24" is a normal way for an
    operator or the installer to have written "the subnet this address is
    in", not a typo to reject."""
    try:
        return ipaddress.IPv4Network(str(value), strict=False)
    except (ValueError, TypeError):
        return None


def validate(obj, mgmt_cidr: str, client_cidr: str) -> tuple[bool, str, list]:
    """Validate `{"trusted": [{"cidr": ...}, ...]}`. Whole-list: one bad entry
    rejects the lot, matching how the canary and check lists behave.

    `mgmt_cidr` and `client_cidr` are parsed permissively (host bits allowed),
    but they are not optional: if either is missing or unparseable, the two
    guards that depend on them cannot be evaluated, and a validator that
    cannot see the boundary must refuse rather than silently skip the guard
    and accept the whole management subnet.

    The three guards, in the order an operator is most likely to trip them:

    * private ranges only, because a public range here would route somebody
      else's addresses into the tunnel;
    * no overlap with the client VLAN, which already has a path — two paths for
      one source is an asymmetry bug waiting to happen;
    * no overlap with the management subnet unless the entry is a single host,
      because routing the subnet proteus lives on into a tunnel is precisely how
      an operator locks themselves out of the box. One infra host is fine.

    An empty list is valid and means "off".
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("trusted"), list):
        return False, 'expected {"trusted": [...]}', []
    mgmt, client = _lenient_net(mgmt_cidr), _lenient_net(client_cidr)
    if mgmt is None or client is None:
        return False, "management or client subnet is unconfigured or unparseable", []
    items = obj["trusted"]
    if len(items) > MAX_TRUSTED:
        return False, f"too many ranges (max {MAX_TRUSTED})", []
    clean: list[dict] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            return False, "each entry must be an object with a cidr", []
        raw = str(item.get("cidr", ""))
        net = _net(raw)
        if net is None:
            return False, f"invalid CIDR {raw[:40]!r} (host bits must be zero)", []
        if not is_private(net):
            return False, f"{net} is not a private range", []
        if net.overlaps(client):
            return False, f"{net} overlaps the client VLAN", []
        if net.overlaps(mgmt) and net.prefixlen < 32:
            return False, f"{net} overlaps the management subnet; use a single /32", []
        key = str(net)
        if key in seen:
            return False, f"duplicate range {key}", []
        seen.add(key)
        clean.append({"cidr": key})
    return True, "", clean


def load(path: str = DEFAULT_PATH, mgmt_cidr: str | None = None,
         client_cidr: str | None = None) -> list[str]:
    """CIDR strings from trusted.json, or `[]` for absent, malformed or invalid.

    Never raises and never returns a partial list: a file the broker would have
    rejected is treated as off rather than half-applied, so a hand-edited file
    cannot widen access by being wrong in an interesting way.

    The shape and RFC1918 checks always apply — that is the floor every caller
    gets even if it does not know the management subnet or client VLAN. When
    both are supplied, the file is additionally run through the same
    `validate()` the broker uses, so a hand-edited file naming the management
    subnet, the client VLAN, a duplicate, or an overlong list is rejected
    outright rather than silently truncated or partially trusted.
    """
    try:
        with open(path) as f:
            obj = json.load(f)
    except (OSError, ValueError):
        return []
    if not isinstance(obj, dict) or not isinstance(obj.get("trusted"), list):
        return []
    if mgmt_cidr is not None and client_cidr is not None:
        ok, _, clean = validate(obj, mgmt_cidr, client_cidr)
        if not ok:
            return []
        return [item["cidr"] for item in clean]
    out: list[str] = []
    for item in obj["trusted"][:MAX_TRUSTED]:
        if not isinstance(item, dict):
            return []
        net = _net(item.get("cidr", ""))
        if net is None or not is_private(net):
            return []
        out.append(str(net))
    return out


def tunnel_addr(tunnel_cidr: str, which: str = "proteus") -> str:
    """proteus takes the first usable address of the tunnel subnet, the UDM
    the second. Raises on anything too small to hold both, or on a `which`
    that is not one of the two known peers.

    Indexes into the network directly rather than materialising
    `net.hosts()`, which would enumerate the whole subnet — seconds and
    gigabytes for something as large as a `/8`, when all that is needed is
    one of the first two addresses.
    """
    if which not in ("proteus", "udm"):
        raise ValueError(f"which must be 'proteus' or 'udm', not {which!r}")
    net = _net(tunnel_cidr)
    if net is None:
        raise ValueError(f"tunnel CIDR {tunnel_cidr!r} is not a plain IPv4 network")
    if net.prefixlen == 32:
        raise ValueError(f"tunnel CIDR {tunnel_cidr!r} must hold at least two addresses")
    if net.prefixlen == 31:
        # RFC 3021: a /31 has no network/broadcast address, both are usable.
        first, second = net[0], net[1]
    else:
        first, second = net[1], net[2]
    return str(first if which == "proteus" else second)


def parse_dns_list(value) -> list[str]:
    """`PROTEUS_UDM_DNS` as a normalised list of IP addresses.

    One address, or several separated by commas — WireGuard accepts
    `DNS = 10.0.0.1, 10.0.0.2`. Whitespace anywhere is insignificant, so
    `"10.0.0.53 ,10.0.0.54"` and `"10.0.0.53,10.0.0.54"` are the same list, and
    each address is round-tripped through `ipaddress` so the caller can join the
    result without re-normalising.

    Every entry must be a literal IPv4 or IPv6 address. UniFi's validator
    refuses anything else outright — "Invalid DNS in [Interface]. Use: DNS = IP
    Address" — so a hostname is not something to pass through and let the router
    complain about after the operator has pasted it in. Rejecting it here is
    what lets the failure name the knob instead.

    It is also why `render_udm_conf` does not screen this field for newlines and
    `#` the way it screens the keys and the endpoint: by the time a value gets
    past here it is a list of IP addresses and cannot be anything else.

    Raises `ValueError` saying what was wrong, phrased to read as one sentence
    after the caller prefixes the knob name.
    """
    text = str(value or "").strip()
    if not text:
        raise ValueError("is unset or empty")
    out: list[str] = []
    for part in text.split(","):
        item = part.strip()
        if not item:
            raise ValueError(f"has an empty entry in {text[:60]!r}")
        try:
            out.append(str(ipaddress.ip_address(item)))
        except ValueError:
            raise ValueError(f"entry {item[:40]!r} is not an IP address "
                             f"(UniFi accepts only IP addresses here)") from None
    return out


def render_udm_conf(*, udm_private: str, server_pub: str, endpoint: str,
                    tunnel_cidr: str, mtu: int, dns: str) -> str:
    """The WireGuard configuration the operator pastes into UniFi.

    `AllowedIPs = 0.0.0.0/0` is what makes UniFi treat this as a full-tunnel VPN
    client and therefore offer it as a selectable egress in Traffic Routes. It
    does not mean everything is tunnelled: what actually reaches the tunnel is
    decided by the Traffic Routes the operator writes.

    `DNS` is not optional and is not a tunnel resolver. UniFi refuses to save a
    VPN Client whose `[Interface]` has no `DNS` line ("Invalid DNS in
    [Interface]. Use: DNS = IP Address"), which is why it is rendered here; and
    the value belongs to the operator's LAN, because the point of this tunnel is
    that trusted hosts take their EGRESS through the rotating exits while still
    resolving names on the resolver they already use. Pointing it at a public or
    in-tunnel resolver would silently cost every trusted host its ad-blocking
    and its internal names.

    Each free-text field is interpolated verbatim into an INI-like file, so a
    newline or a `#` in one would let it inject a second `[Peer]` section, an
    extra `AllowedIPs` line, or a comment that swallows the rest of the line.
    None of these fields is validated elsewhere (unlike `tunnel_cidr`, which
    `_net()` already rejects if malformed, and `dns`, which `parse_dns_list()`
    reduces to IP addresses), so they are checked here instead.
    """
    for field, value in (("udm_private", udm_private), ("server_pub", server_pub),
                        ("endpoint", endpoint)):
        if any(ch in str(value) for ch in ("\n", "\r", "#")):
            raise ValueError(f"{field} must not contain a newline or '#'")
    mtu = int(mtu)
    dns_line = ", ".join(parse_dns_list(dns))
    net = _net(tunnel_cidr)
    if net is None:
        raise ValueError(f"tunnel CIDR {tunnel_cidr!r} is not a plain IPv4 network")
    return (
        "[Interface]\n"
        f"PrivateKey = {udm_private}\n"
        f"Address = {tunnel_addr(tunnel_cidr, 'udm')}/{net.prefixlen}\n"
        f"DNS = {dns_line}\n"
        f"MTU = {mtu}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )


def mgmt_ip_from(addr_output: str, mgmt_cidr: str) -> str | None:
    """proteus' own address inside the management subnet, parsed from
    `ip -4 -o addr show`. Used to fill the Endpoint the UDM dials, so pairing
    needs no extra configuration. Returns None when nothing matches.

    A `deprecated` address is skipped outright: it is on its way out and is a
    poor choice to hand to a peer that will dial it for a long time. A
    `secondary` address is kept only as a last-resort fallback — the primary
    address on an interface is preferred, so which address pairing picks does
    not depend on the order `ip` happens to print them in.
    """
    net = _lenient_net(mgmt_cidr)
    if net is None:
        return None
    fallback: str | None = None
    for line in addr_output.splitlines():
        if "deprecated" in line:
            continue
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "inet" and i + 1 < len(parts):
                try:
                    addr = ipaddress.IPv4Address(parts[i + 1].split("/")[0])
                except ValueError:
                    continue
                if addr not in net:
                    continue
                if "scope global" in line and "secondary" not in parts:
                    return str(addr)
                if fallback is None:
                    fallback = str(addr)
    return fallback


def mgmt_ip_from_fib_trie(text: str, mgmt_cidr: str) -> str | None:
    """proteus' own address inside the management subnet, parsed from
    `/proc/net/fib_trie`. Same contract as `mgmt_ip_from`: the first address
    inside `mgmt_cidr` that the kernel says is ours, or None.

    WHY THIS EXISTS, AND WHY IT MUST NOT GO BACK TO CALLING `ip`: the caller is
    proteus-ui-apply, the root broker, whose unit sets
    `RestrictAddressFamilies=AF_UNIX`. That denies AF_NETLINK, so `ip` cannot
    open the netlink socket it needs — it dies with "Cannot open netlink
    socket: Address family not supported by protocol" and exits 1. Pairing
    failed in production for exactly that reason. The sandbox is the boundary
    between an unprivileged web daemon and root and is not worth widening for
    an address lookup, and `/proc/net/fib_trie` is a plain file read that works
    under it unchanged.

    The format. The file prints the `Main:` table and then the `Local:` one, and
    only `Local:` lists the host's own addresses — `Main:` holds routes, which
    are addresses the box can *reach* rather than ones it *answers to*, so
    everything before `Local:` is skipped. Inside it, an address sits on a
    `|-- <ip>` line and the flag line or lines beneath it carry its scope and
    route type:

        |-- 192.0.2.119
           /32 host LOCAL
        |-- 192.0.2.255
           /32 link BROADCAST

    Only `host LOCAL` counts. The subnet's broadcast address is in the same
    table, one line away, and taking it would have the UDM dial a broadcast
    address as its Endpoint. A `+-- <prefix>` line is an internal trie node, not
    an address, and ends the run of flag lines belonging to the address above.
    """
    net = _lenient_net(mgmt_cidr)
    if net is None:
        return None
    in_local = False
    candidate: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not in_local:
            if line == "Local:":
                in_local = True
            continue
        if line.endswith(":") and " " not in line:
            break  # a further table; only Local: holds our own addresses
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "|--":
            candidate = None
            if len(parts) == 2:
                try:
                    addr = ipaddress.IPv4Address(parts[1])
                except ValueError:
                    continue
                if addr in net:
                    candidate = str(addr)
            continue
        if parts[0] == "+--":
            candidate = None
            continue
        if (candidate and parts[0].startswith("/") and len(parts) >= 3
                and parts[1] == "host" and parts[2] == "LOCAL"):
            return candidate
    return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    lst = sub.add_parser("list")
    lst.add_argument("--file", default=DEFAULT_PATH)
    lst.add_argument("--mgmt-cidr", default=None,
                     help="apply full validation, not just the shape/RFC1918 floor")
    lst.add_argument("--client-cidr", default=None,
                     help="apply full validation, not just the shape/RFC1918 floor")
    ad = sub.add_parser("addr")
    ad.add_argument("--cidr", required=True)
    ad.add_argument("--which", choices=("proteus", "udm"), default="proteus")
    args = p.parse_args(argv)
    if args.cmd == "list":
        for cidr in load(args.file, args.mgmt_cidr, args.client_cidr):
            print(cidr)
        return 0
    if args.cmd == "addr":
        try:
            print(tunnel_addr(args.cidr, args.which))
        except ValueError as e:
            print(f"trusted.py: {e}", file=sys.stderr)
            return 2
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
