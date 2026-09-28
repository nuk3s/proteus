"""Tests for etc/proteus/bin/trusted.py — the trusted-source list."""
from __future__ import annotations
import json
import time
from pathlib import Path

import pytest

import trusted

MGMT = "172.20.0.0/24"
CLIENT = "172.16.1.0/24"


def v(items, mgmt=MGMT, client=CLIENT):
    return trusted.validate({"trusted": items}, mgmt, client)


def test_validate_accepts_a_private_range() -> None:
    ok, reason, clean = v([{"cidr": "192.168.7.0/24"}])
    assert ok, reason
    assert clean == [{"cidr": "192.168.7.0/24"}]


def test_validate_accepts_an_empty_list_meaning_feature_off() -> None:
    ok, reason, clean = v([])
    assert ok, reason
    assert clean == []


def test_validate_rejects_public_ranges() -> None:
    ok, reason, _ = v([{"cidr": "198.51.100.0/24"}])
    assert not ok and "private" in reason


def test_validate_rejects_host_bits_set() -> None:
    ok, reason, _ = v([{"cidr": "192.168.7.5/24"}])
    assert not ok and "host bits" in reason


def test_validate_rejects_overlap_with_the_client_vlan() -> None:
    ok, reason, _ = v([{"cidr": "172.16.1.0/24"}])
    assert not ok and "client VLAN" in reason
    ok, reason, _ = v([{"cidr": "172.16.0.0/16"}])
    assert not ok and "client VLAN" in reason


def test_validate_rejects_the_management_subnet_but_allows_one_host() -> None:
    ok, reason, _ = v([{"cidr": "172.20.0.0/24"}])
    assert not ok and "management subnet" in reason
    ok, reason, _ = v([{"cidr": "172.20.0.0/16"}])
    assert not ok and "management subnet" in reason
    ok, reason, clean = v([{"cidr": "172.20.0.150/32"}])
    assert ok, reason
    assert clean == [{"cidr": "172.20.0.150/32"}]


def test_validate_rejects_duplicates_and_overlong_lists() -> None:
    ok, reason, _ = v([{"cidr": "192.168.7.0/24"}, {"cidr": "192.168.7.0/24"}])
    assert not ok and "duplicate" in reason
    ok, reason, _ = v([{"cidr": f"192.168.{i}.0/24"} for i in range(trusted.MAX_TRUSTED + 1)])
    assert not ok and "too many" in reason


def test_validate_rejects_junk_shapes() -> None:
    for bad in ({"trusted": "nope"}, {"nope": []}, [], "x", None):
        ok, _, _ = trusted.validate(bad, MGMT, CLIENT)
        assert not ok, bad
    ok, _, _ = v(["192.168.7.0/24"])
    assert not ok


def test_validate_guard_cidrs_are_permissive_but_required() -> None:
    # A guard written with host bits set (as the installer writes it, and as
    # mgmt_ip_from's own docstring calls sensible) still catches the overlap.
    ok, reason, _ = v([{"cidr": "172.20.0.0/24"}], mgmt="172.20.0.119/24")
    assert not ok and "management subnet" in reason

    # A guard that cannot be parsed at all must fail closed, not skip the
    # check it was supposed to perform.
    for bad_mgmt in ("", "garbage", None):
        ok, reason, _ = trusted.validate({"trusted": []}, bad_mgmt, CLIENT)
        assert not ok and "unconfigured or unparseable" in reason, bad_mgmt
    for bad_client in ("", "garbage", None):
        ok, reason, _ = trusted.validate({"trusted": []}, MGMT, bad_client)
        assert not ok and "unconfigured or unparseable" in reason, bad_client


def test_load_roundtrip_and_failure_modes(tmp_path: Path) -> None:
    p = tmp_path / "trusted.json"
    p.write_text(json.dumps({"trusted": [{"cidr": "192.168.7.0/24"}, {"cidr": "10.44.0.0/16"}]}))
    assert trusted.load(str(p)) == ["192.168.7.0/24", "10.44.0.0/16"]
    # 203.0.113.0/24 is an RFC 5737 documentation range, not RFC 1918 — it
    # exercises the same "public range must be rejected" path as
    # test_validate_rejects_public_ranges above, and (being RFC 5737) is safe
    # for the public mirror.
    for bad in ("not json", '{"trusted": 5}', '{"trusted": [{"cidr": "nope"}]}',
                '{"trusted": [{"cidr": "203.0.113.0/24"}]}', '{"trusted": ["192.168.7.0/24"]}', "{}"):
        p.write_text(bad)
        assert trusted.load(str(p)) == [], bad
    assert trusted.load(str(tmp_path / "missing.json")) == []


def test_load_truncates_rather_than_growing_unbounded(tmp_path: Path) -> None:
    p = tmp_path / "trusted.json"
    p.write_text(json.dumps({"trusted": [{"cidr": f"192.168.{i}.0/24"} for i in range(20)]}))
    assert len(trusted.load(str(p))) == trusted.MAX_TRUSTED


def test_load_with_both_cidrs_applies_full_validation(tmp_path: Path) -> None:
    p = tmp_path / "trusted.json"

    # Names the management subnet outright: passes the shape/RFC1918 floor,
    # but full validation must reject it.
    p.write_text(json.dumps({"trusted": [{"cidr": "172.20.0.0/24"}]}))
    assert trusted.load(str(p)) == ["172.20.0.0/24"]
    assert trusted.load(str(p), MGMT, CLIENT) == []

    # Names the client VLAN outright.
    p.write_text(json.dumps({"trusted": [{"cidr": "172.16.1.0/24"}]}))
    assert trusted.load(str(p)) == ["172.16.1.0/24"]
    assert trusted.load(str(p), MGMT, CLIENT) == []

    # A duplicate passes the floor (it does not dedupe) but not full validation.
    p.write_text(json.dumps({"trusted": [{"cidr": "192.168.7.0/24"},
                                          {"cidr": "192.168.7.0/24"}]}))
    assert trusted.load(str(p)) == ["192.168.7.0/24", "192.168.7.0/24"]
    assert trusted.load(str(p), MGMT, CLIENT) == []

    # Nine entries: the floor truncates to MAX_TRUSTED, full validation
    # rejects the list outright instead.
    p.write_text(json.dumps({"trusted": [{"cidr": f"192.168.{i}.0/24"}
                                          for i in range(trusted.MAX_TRUSTED + 1)]}))
    assert len(trusted.load(str(p))) == trusted.MAX_TRUSTED
    assert trusted.load(str(p), MGMT, CLIENT) == []


def test_tunnel_addresses() -> None:
    assert trusted.tunnel_addr("10.99.99.0/30", "proteus") == "10.99.99.1"
    assert trusted.tunnel_addr("10.99.99.0/30", "udm") == "10.99.99.2"
    for bad in ("10.99.99.0/32", "nonsense", "10.99.99.1/30"):
        with pytest.raises(ValueError):
            trusted.tunnel_addr(bad, "proteus")


def test_tunnel_addr_small_and_large_subnets() -> None:
    # /29: same first-two-hosts convention as /30.
    assert trusted.tunnel_addr("10.0.0.0/29", "proteus") == "10.0.0.1"
    assert trusted.tunnel_addr("10.0.0.0/29", "udm") == "10.0.0.2"
    # /31 (RFC 3021): no network/broadcast address, both addresses usable.
    assert trusted.tunnel_addr("10.0.0.0/31", "proteus") == "10.0.0.0"
    assert trusted.tunnel_addr("10.0.0.0/31", "udm") == "10.0.0.1"
    # An unrecognised `which` must not silently return either address.
    with pytest.raises(ValueError):
        trusted.tunnel_addr("10.99.99.0/30", "bogus")
    # Must index directly rather than materialise the whole subnet.
    start = time.monotonic()
    assert trusted.tunnel_addr("10.0.0.0/8", "proteus") == "10.0.0.1"
    assert time.monotonic() - start < 1.0


def test_render_udm_conf_has_the_fields_unifi_needs() -> None:
    out = trusted.render_udm_conf(udm_private="PRIV=", server_pub="PUB=",
                                  endpoint="192.0.2.9:51821",
                                  tunnel_cidr="10.99.99.0/30", mtu=1420,
                                  dns="192.168.1.53")
    assert "[Interface]" in out and "[Peer]" in out
    assert "PrivateKey = PRIV=" in out
    assert "Address = 10.99.99.2/30" in out
    assert "DNS = 192.168.1.53" in out
    assert "MTU = 1420" in out
    assert "PublicKey = PUB=" in out
    assert "Endpoint = 192.0.2.9:51821" in out
    # Full-tunnel is what makes UniFi offer this as a selectable egress.
    assert "AllowedIPs = 0.0.0.0/0" in out


def test_render_udm_conf_rejects_injection() -> None:
    with pytest.raises(ValueError):
        trusted.render_udm_conf(udm_private="PRIV=", server_pub="PUB=\n[Peer]",
                                endpoint="192.0.2.9:51821",
                                tunnel_cidr="10.99.99.0/30", mtu=1420,
                                dns="192.168.1.53")
    with pytest.raises(ValueError):
        trusted.render_udm_conf(udm_private="PRIV=", server_pub="PUB=",
                                endpoint="192.0.2.9:51821\nAllowedIPs = 0.0.0.0/0",
                                tunnel_cidr="10.99.99.0/30", mtu=1420,
                                dns="192.168.1.53")
    with pytest.raises(ValueError):
        trusted.render_udm_conf(udm_private="PRIV=\n# evil", server_pub="PUB=",
                                endpoint="192.0.2.9:51821",
                                tunnel_cidr="10.99.99.0/30", mtu=1420,
                                dns="192.168.1.53")


def test_parse_dns_list_accepts_one_address_a_list_or_ipv6() -> None:
    assert trusted.parse_dns_list("192.168.1.53") == ["192.168.1.53"]
    # WireGuard permits several; whitespace around the commas is insignificant
    # and the result comes back already normalised, so callers can join it
    # without thinking about spacing.
    assert trusted.parse_dns_list("10.0.0.53,10.0.0.54") == ["10.0.0.53", "10.0.0.54"]
    assert trusted.parse_dns_list("  10.0.0.53 ,\t10.0.0.54  ") == ["10.0.0.53", "10.0.0.54"]
    assert trusted.parse_dns_list("fd00::53") == ["fd00::53"]
    assert trusted.parse_dns_list("FD00:0:0:0:0:0:0:0053") == ["fd00::53"]


def test_parse_dns_list_rejects_what_unifi_would_reject() -> None:
    # UniFi's own validator says "Invalid DNS in [Interface]. Use: DNS = IP
    # Address" — a hostname is the mistake this exists to catch, and finding it
    # here means the failure can name the knob instead of coming back from a
    # router the operator has already pasted a one-shot private key into.
    for bad in ("resolver.internal", "adguard", "localhost",
                "", "   ", "\t\n ",
                "10.0.0.53,", ",10.0.0.53", "10.0.0.53,,10.0.0.54",
                "10.0.0.53/32", "10.0.0.256", "10.0.0.53 10.0.0.54",
                "not an ip", "0x0a000035", None):
        with pytest.raises(ValueError):
            trusted.parse_dns_list(bad)


def test_render_udm_conf_puts_exactly_one_dns_line_in_the_interface() -> None:
    out = trusted.render_udm_conf(udm_private="PRIV=", server_pub="PUB=",
                                  endpoint="192.0.2.9:51821",
                                  tunnel_cidr="10.99.99.0/30", mtu=1420,
                                  dns=" 10.0.0.53 ,10.0.0.54 ")
    dns_lines = [ln for ln in out.splitlines() if ln.startswith("DNS")]
    assert dns_lines == ["DNS = 10.0.0.53, 10.0.0.54"]
    interface, _, peer = out.partition("[Peer]")
    assert "DNS = 10.0.0.53, 10.0.0.54" in interface
    # DNS in [Peer] is not a WireGuard key at all; wg-quick would refuse the file.
    assert "DNS" not in peer


def test_render_udm_conf_refuses_a_dns_unifi_would_not_take() -> None:
    for bad in ("", "   ", "resolver.internal", "10.0.0.53,nope"):
        with pytest.raises(ValueError):
            trusted.render_udm_conf(udm_private="PRIV=", server_pub="PUB=",
                                    endpoint="192.0.2.9:51821",
                                    tunnel_cidr="10.99.99.0/30", mtu=1420, dns=bad)


def test_mgmt_ip_from_picks_the_address_inside_the_subnet() -> None:
    out = (
        "1: lo    inet 127.0.0.1/8 scope host lo\n"
        "2: ens18 inet 172.20.0.119/24 brd 172.20.0.255 scope global ens18\n"
        "3: ens19 inet 172.16.1.5/24 brd 172.16.1.255 scope global ens19\n"
    )
    assert trusted.mgmt_ip_from(out, "172.20.0.0/24") == "172.20.0.119"
    assert trusted.mgmt_ip_from(out, "192.168.99.0/24") is None
    assert trusted.mgmt_ip_from("", "172.20.0.0/24") is None
    assert trusted.mgmt_ip_from(out, "garbage") is None


def test_mgmt_ip_from_prefers_primary_over_secondary() -> None:
    # Secondary address listed first must not win over the primary listed
    # after it, regardless of print order.
    out = (
        "2: ens18 inet 172.20.0.50/24 brd 172.20.0.255 scope global secondary ens18\n"
        "3: ens18 inet 172.20.0.119/24 brd 172.20.0.255 scope global ens18\n"
    )
    assert trusted.mgmt_ip_from(out, "172.20.0.0/24") == "172.20.0.119"


def test_mgmt_ip_from_skips_deprecated_addresses() -> None:
    out = (
        "2: ens18 inet 172.20.0.50/24 brd 172.20.0.255 scope global deprecated ens18\n"
        "3: ens18 inet 172.20.0.119/24 brd 172.20.0.255 scope global ens18\n"
    )
    assert trusted.mgmt_ip_from(out, "172.20.0.0/24") == "172.20.0.119"


def test_mgmt_ip_from_with_two_plain_addresses_in_the_subnet() -> None:
    out = (
        "2: ens18 inet 172.20.0.50/24 brd 172.20.0.255 scope global ens18\n"
        "3: ens19 inet 172.20.0.119/24 brd 172.20.0.255 scope global ens19\n"
    )
    assert trusted.mgmt_ip_from(out, "172.20.0.0/24") == "172.20.0.50"


# A real /proc/net/fib_trie `Local:` excerpt from the gateway, structurally
# byte-for-byte — the indentation, the `|-- <ip>` lines and the flag lines under
# them are what the parser keys off. Only the management subnet is changed, from
# the operator's real one to the 172.20.0.0/24 the rest of this suite uses: the
# publish gate in scripts/build-public-mirror.sh refuses the lab range outright,
# and tests/ ships in the public mirror.
FIB_TRIE = """\
Local:
  +-- 0.0.0.0/0 3 0 5
     +-- 172.20.0.0/24 2 0 2
        |-- 172.20.0.119
           /32 host LOCAL
        |-- 172.20.0.255
           /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
     +-- 172.16.0.0/12 2 0 2
        +-- 172.16.1.0/24 2 0 2
           |-- 172.16.1.5
              /32 host LOCAL
"""


def test_mgmt_ip_from_fib_trie_finds_the_local_address() -> None:
    assert trusted.mgmt_ip_from_fib_trie(FIB_TRIE, "172.20.0.0/24") == "172.20.0.119"
    # A CIDR written with host bits set is how the installer writes it.
    assert trusted.mgmt_ip_from_fib_trie(FIB_TRIE, "172.20.0.119/24") == "172.20.0.119"
    # Deeper in the trie, and a second interface, are found just the same.
    assert trusted.mgmt_ip_from_fib_trie(FIB_TRIE, "172.16.1.0/24") == "172.16.1.5"
    assert trusted.mgmt_ip_from_fib_trie(FIB_TRIE, "127.0.0.0/8") == "127.0.0.0"


def test_mgmt_ip_from_fib_trie_never_returns_a_broadcast_address() -> None:
    # 172.20.0.255 sits in the Local: table beside the box's own address, one
    # `|--` line away from it, and is marked `link BROADCAST` rather than
    # `host LOCAL`. Handing it to the UDM would make the Endpoint a broadcast
    # address, so the flag line, not the section, is what decides.
    assert trusted.mgmt_ip_from_fib_trie(FIB_TRIE, "172.20.0.255/32") is None


def test_mgmt_ip_from_fib_trie_returns_none_when_nothing_matches() -> None:
    assert trusted.mgmt_ip_from_fib_trie(FIB_TRIE, "192.168.99.0/24") is None
    assert trusted.mgmt_ip_from_fib_trie(FIB_TRIE, "garbage") is None
    assert trusted.mgmt_ip_from_fib_trie("", "172.20.0.0/24") is None
    assert trusted.mgmt_ip_from_fib_trie("", "garbage") is None
    # No Local: section at all (a truncated read) is "nothing found", not a crash.
    assert trusted.mgmt_ip_from_fib_trie("Main:\n  +-- 0.0.0.0/0 3 0 5\n",
                                         "172.20.0.0/24") is None


def test_mgmt_ip_from_fib_trie_ignores_the_main_table() -> None:
    # The file prints Main: (routes — addresses the box can *reach*) before
    # Local: (addresses it *answers to*). The 172.20.0.7 entry below is given
    # the same `host LOCAL` shape a genuine local address has and comes first
    # in the file, so a parser that ignores the section boundary returns it.
    text = (
        "Main:\n"
        "  +-- 0.0.0.0/0 3 0 5\n"
        "     |-- 0.0.0.0\n"
        "        /0 universe UNICAST\n"
        "     +-- 172.20.0.0/24 2 0 2\n"
        "        |-- 172.20.0.0\n"
        "           /24 link UNICAST\n"
        "        |-- 172.20.0.7\n"
        "           /32 host LOCAL\n"
        "Local:\n"
        "  +-- 172.20.0.0/24 2 0 2\n"
        "     |-- 172.20.0.119\n"
        "        /32 host LOCAL\n"
    )
    assert trusted.mgmt_ip_from_fib_trie(text, "172.20.0.0/24") == "172.20.0.119"
    assert trusted.mgmt_ip_from_fib_trie(text, "172.20.0.7/32") is None


def test_cli_list_and_addr(tmp_path: Path, capsys) -> None:
    p = tmp_path / "trusted.json"
    p.write_text(json.dumps({"trusted": [{"cidr": "192.168.7.0/24"}]}))
    assert trusted.main(["list", "--file", str(p)]) == 0
    assert capsys.readouterr().out.split() == ["192.168.7.0/24"]
    assert trusted.main(["list", "--file", str(tmp_path / "missing.json")]) == 0
    assert capsys.readouterr().out == ""
    assert trusted.main(["addr", "--cidr", "10.99.99.0/30", "--which", "udm"]) == 0
    assert capsys.readouterr().out.strip() == "10.99.99.2"
    assert trusted.main(["addr", "--cidr", "bogus"]) == 2
