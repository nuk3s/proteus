# tests/ui_logic_test.py
from __future__ import annotations
import json
import threading
import ui_logic


def test_passphrase_roundtrip():
    stored = ui_logic.hash_passphrase("correct horse", iterations=1000)  # low iters for test speed
    assert ui_logic.verify_passphrase("correct horse", stored)
    assert not ui_logic.verify_passphrase("wrong", stored)


def test_passphrase_garbage_stored():
    assert not ui_logic.verify_passphrase("x", "not-a-hash")
    assert not ui_logic.verify_passphrase("x", "")


def test_passphrase_wrong_scheme():
    assert not ui_logic.verify_passphrase("x", "md5$1000$aa$bb")


def test_passphrase_nonascii_stored_no_crash():
    assert not ui_logic.verify_passphrase("x", "pbkdf2-sha256$1000$aa$éé")


def test_session_roundtrip():
    key = b"k" * 32
    tok = ui_logic.mint_session(key, now=1000.0)
    assert ui_logic.verify_session(key, tok, now=1000.0)
    assert ui_logic.verify_session(key, tok, now=1000.0 + ui_logic.SESSION_TTL_S - 1)


def test_session_expiry_and_tamper():
    key = b"k" * 32
    tok = ui_logic.mint_session(key, now=1000.0)
    assert not ui_logic.verify_session(key, tok, now=1000.0 + ui_logic.SESSION_TTL_S + 1)
    assert not ui_logic.verify_session(b"other" * 8, tok, now=1000.0)
    exp, nonce, sig = tok.split(".")
    assert not ui_logic.verify_session(key, f"{int(exp)+999999}.{nonce}.{sig}", now=1000.0)
    assert not ui_logic.verify_session(key, "garbage", now=1000.0)


def test_session_nonascii_token_no_crash():
    assert not ui_logic.verify_session(b"k" * 32, "1000.aa.éé")


def test_knob_accept_reject():
    ok, _ = ui_logic.validate_knob("PROTEUS_STREAMING_MIN_MBPS", "30")
    assert ok
    for key, bad in [
        ("PROTEUS_STREAMING_MIN_MBPS", "0"),
        ("PROTEUS_STREAMING_MIN_MBPS", "501"),
        ("PROTEUS_STREAMING_MIN_MBPS", "abc"),
        ("PROTEUS_STREAMING_MIN_MBPS", "30; rm -rf /"),
        ("PROTEUS_PROTON_COUNTRY", "nl"),
        ("PROTEUS_PROTON_COUNTRY", "NLX"),
        ("NOT_A_KNOB", "1"),
    ]:
        ok, reason = ui_logic.validate_knob(key, bad)
        assert not ok and reason


def test_knob_country_ok():
    assert ui_logic.validate_knob("PROTEUS_PROTON_COUNTRY", "CH")[0]


def test_knob_rejects_python_numeric_literals():
    assert not ui_logic.validate_knob("PROTEUS_STREAMING_MIN_MBPS", "5_0")[0]
    assert not ui_logic.validate_knob("PROTEUS_STREAMING_MIN_MBPS", "1e1")[0]


def test_knob_rejects_trailing_newline():
    assert not ui_logic.validate_knob("PROTEUS_STREAMING_MIN_MBPS", "30\n")[0]


def test_knob_float_accept_reject():
    assert ui_logic.validate_knob("PROTEUS_SCORE_LAT_COEF", "0.5")[0]
    assert not ui_logic.validate_knob("PROTEUS_SCORE_LAT_COEF", "1e1")[0]
    assert not ui_logic.validate_knob("PROTEUS_SCORE_LAT_COEF", "0_5")[0]


def test_udm_dns_knob_takes_ip_addresses_and_nothing_else():
    # Same parser the pairing uses, so the panel cannot save a value that then
    # fails at pairing time — which is the whole point of validating here.
    assert ui_logic.validate_knob("PROTEUS_UDM_DNS", "192.168.1.53")[0]
    assert ui_logic.validate_knob("PROTEUS_UDM_DNS", "10.0.0.53,10.0.0.54")[0]
    assert ui_logic.validate_knob("PROTEUS_UDM_DNS", "fd00::53")[0]
    for bad in ("resolver.internal", "localhost", "10.0.0.53,", "10.0.0.256"):
        ok, reason = ui_logic.validate_knob("PROTEUS_UDM_DNS", bad)
        assert not ok and "PROTEUS_UDM_DNS" in reason
    # These never reach the parser: the shared charset filter stops them first,
    # which is the point — a space is inert in the rendered config but not in the
    # overlay, which every script on the box sources.
    for bad in ("10.0.0.53, 10.0.0.54", "192.168.1.53/32", "$(reboot)"):
        ok, reason = ui_logic.validate_knob("PROTEUS_UDM_DNS", bad)
        assert not ok and reason
    # Shipped empty on purpose: the right answer is site-specific.
    assert ui_logic.KNOBS["PROTEUS_UDM_DNS"].default == ""
    # Drawn by the trusted-egress pane, not the generic grouped list.
    assert ui_logic.KNOBS["PROTEUS_UDM_DNS"].group == "udm"
    assert "udm" not in dict(ui_logic.KNOB_GROUPS)


def test_knob_kick_units():
    assert ui_logic.KNOBS["PROTEUS_SPREAD_BAND"].kick == "proteus-dispatcher.service"
    assert ui_logic.KNOBS["PROTEUS_ROT_THRESHOLD"].kick is None


def test_schema_export_is_json_safe():
    json.dumps(ui_logic.knob_schema())  # for /api/status


SLOT_STATE = """\
INSTANCE=proton-1
WG_ENDPOINT_IP=192.0.2.10
UP_TIME=2026-08-01T10:00:00+00:00
LOGICAL_NAME=NL#312
EXIT_COUNTRY=NL
EXIT_IP=192.0.2.99
MINTED_AT=2026-08-01T10:00:00+00:00
"""

HEALTH = """\
STATUS=healthy
FAIL_STREAK=0
LATENCY_MEDIAN_MS=23
THROUGHPUT_MBPS=148
COMPOSITE_SCORE=81
SCORE_UPDATED_AT=1754300000
"""


def test_parse_kv():
    d = ui_logic.parse_kv(SLOT_STATE)
    assert d["LOGICAL_NAME"] == "NL#312"
    assert ui_logic.parse_kv("# comment\n\nA=1\n")["A"] == "1"


def test_slot_summary_healthy():
    s = ui_logic.slot_summary(
        "proton-1", ui_logic.parse_kv(SLOT_STATE), ui_logic.parse_kv(HEALTH),
        next_rotation=1754400000, rotating=False, now=1754300010,
    )
    assert s["logical"] == "NL#312" and s["exit_ip"] == "192.0.2.99"
    assert s["health"]["score"] == "81" and not s["health"]["stale"]
    assert s["next_rotation"] == 1754400000


def test_slot_summary_degrades():
    s = ui_logic.slot_summary("proton-9", {}, {}, next_rotation=None,
                              rotating=False, now=0)
    assert s["status"] == "down" and s["next_rotation"] is None
    stale = ui_logic.slot_summary(
        "proton-1", ui_logic.parse_kv(SLOT_STATE), ui_logic.parse_kv(HEALTH),
        next_rotation=None, rotating=True, now=1754300000 + 999,
    )
    assert stale["health"]["stale"] and stale["rotating"]


def test_slot_summary_malformed_score_updated_at():
    health = ui_logic.parse_kv(HEALTH)
    health["SCORE_UPDATED_AT"] = "garbage"
    s = ui_logic.slot_summary(
        "proton-1", ui_logic.parse_kv(SLOT_STATE), health,
        next_rotation=None, rotating=False, now=1754300000,
    )
    assert s["health"]["stale"] is True


def test_lockout():
    lo = ui_logic.Lockout(limit=5, window_s=60)
    for _ in range(4):
        lo.record_failure("192.0.2.1", now=100.0)
    assert not lo.locked("192.0.2.1", now=100.0)
    lo.record_failure("192.0.2.1", now=100.0)
    assert lo.locked("192.0.2.1", now=100.0)
    assert not lo.locked("192.0.2.1", now=161.0)   # lockout expires
    assert not lo.locked("192.0.2.2", now=100.0)   # per-source
    lo.clear("192.0.2.1")
    assert not lo.locked("192.0.2.1", now=100.0)


def test_lockout_global_ceiling_bounds_distributed_guessing():
    # The per-source limit alone counts nothing an attacker can't choose: on a
    # /24 they get limit*254 attempts. The global ceiling is the real bound.
    lo = ui_logic.Lockout(limit=5, window_s=60, global_limit=20)
    for i in range(20):
        src = f"172.16.1.{i}"          # a fresh source every time
        assert not lo.locked(src, now=100.0), i
        lo.record_failure(src, now=100.0)
    # Every individual source is still under its own limit (1 failure each)...
    assert len(lo._fails["172.16.1.0"]) == 1
    # ...but the global ceiling has been reached, so a brand-new source is locked.
    assert lo.locked("172.16.1.200", now=100.0)
    # It drains with the window rather than latching.
    assert not lo.locked("172.16.1.200", now=161.0)


def test_lockout_success_does_not_clear_the_global_counter():
    # A valid login from one address says nothing about a distributed attack.
    lo = ui_logic.Lockout(limit=5, window_s=60, global_limit=3)
    for i in range(3):
        lo.record_failure(f"10.0.0.{i}", now=100.0)
    lo.clear("10.0.0.1")
    assert lo.locked("10.0.0.99", now=100.0)


def test_lockout_prunes_so_spoofed_sources_cannot_exhaust_memory():
    lo = ui_logic.Lockout(limit=5, window_s=60, global_limit=10**9, max_sources=50)
    for i in range(500):
        lo.record_failure("10.1.%d.%d" % (i // 256, i % 256), now=100.0)
    assert len(lo._fails) <= 50, len(lo._fails)
    # aged entries disappear entirely rather than accumulating
    lo.locked("10.1.0.0", now=100.0 + 61)
    assert len(lo._fails) == 0 and lo._global == []


def test_lockout_per_source_still_applies():
    # The global ceiling must not have replaced the per-source one.
    lo = ui_logic.Lockout(limit=3, window_s=60, global_limit=10**9)
    for _ in range(3):
        lo.record_failure("10.0.0.7", now=100.0)
    assert lo.locked("10.0.0.7", now=100.0)
    assert not lo.locked("10.0.0.8", now=100.0)


def test_lockout_thread_safety():
    # ThreadingHTTPServer runs one thread per request, so record_failure and
    # locked() race each other across concurrent login attempts. limit is set
    # far above the total so lockout kicking in never masks a dropped record.
    lo = ui_logic.Lockout(limit=10**9, window_s=3600)
    n_threads, n_each = 20, 200

    def hammer():
        for _ in range(n_each):
            lo.record_failure("192.0.2.1", now=100.0)
            lo.locked("192.0.2.1", now=100.0)  # also mutates _fails[src]

    threads = [threading.Thread(target=hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(lo._fails["192.0.2.1"]) == n_threads * n_each


def test_builtin_checks_shape():
    assert len(ui_logic.BUILTIN_CHECKS) >= 5
    for c in ui_logic.BUILTIN_CHECKS:
        assert c["url"].startswith("http") and c["tier"] in ("mandatory", "advisory")
    json.dumps(ui_logic.BUILTIN_CHECKS)


def test_validate_checks_ok():
    ok, reason, clean = ui_logic.validate_checks(
        {"checks": [{"url": "https://www.example.com/", "tier": "mandatory"},
                    {"url": "http://example.org/path?q=1&x=2", "tier": "advisory"}]})
    assert ok and reason == "" and len(clean) == 2
    assert clean[0] == {"url": "https://www.example.com/", "tier": "mandatory"}


def test_validate_checks_rejects_scheme_and_tier():
    for b in ([{"url": "ftp://x/", "tier": "advisory"}],
              [{"url": "file:///etc/passwd", "tier": "advisory"}],
              [{"url": "https://x/", "tier": "boss"}]):
        ok, reason, _ = ui_logic.validate_checks({"checks": b})
        assert not ok and reason, b


def test_validate_checks_rejects_injection_chars():
    # semicolon WITHOUT a space must still fail (regex, not incidental space);
    # a TRAILING newline must fail too (fullmatch, not $-anchored match)
    for u in ("https://x/;rm-rf", "https://x/`id`", "https://x/$(id)",
              "https://x/ a", "https://x/\nB", "https://x/\n", "-https://x/"):
        ok, reason, _ = ui_logic.validate_checks({"checks": [{"url": u, "tier": "advisory"}]})
        assert not ok and reason, u


def test_validate_checks_rejects_shape_and_limits():
    for b in ({"checks": "nope"}, {"nope": 1},
              {"checks": [{"url": "https://" + "a" * 250 + "/", "tier": "advisory"}]},
              {"checks": [{"url": f"https://x{i}/", "tier": "advisory"} for i in range(16)]}):
        ok, reason, _ = ui_logic.validate_checks(b)
        assert not ok and reason, b


def test_validate_checks_body_optional_and_roundtrips():
    ok, reason, clean = ui_logic.validate_checks({"checks": [
        {"url": "https://a.example/", "tier": "mandatory",
         "body": '"playabilityStatus":{"status":"OK"'},
        {"url": "https://b.example/", "tier": "advisory"},
        {"url": "https://c.example/", "tier": "advisory", "body": ""},
    ]})
    assert ok and reason == ""
    assert clean[0]["body"] == '"playabilityStatus":{"status":"OK"'
    # absent or empty body must not materialise a key — the probe treats a
    # present-but-empty assertion the same as absent, but the file stays clean
    assert "body" not in clean[1] and "body" not in clean[2]


def test_validate_checks_body_rejects_tsv_breakers():
    # checks.json is handed to reputation-probe.sh as tier\turl\tbody; a tab or
    # newline in the body would shift the columns and could smuggle a second row.
    for bad in ("has\ttab", "has\nnewline", "has\rcr", "a\tb\tc"):
        ok, reason, _ = ui_logic.validate_checks(
            {"checks": [{"url": "https://x/", "tier": "advisory", "body": bad}]})
        assert not ok and reason, repr(bad)


def test_validate_checks_body_limits_and_charset():
    ok, _, _ = ui_logic.validate_checks({"checks": [
        {"url": "https://x/", "tier": "advisory", "body": "a" * ui_logic.MAX_CHECK_BODY}]})
    assert ok
    for bad in ("a" * (ui_logic.MAX_CHECK_BODY + 1), "café", "nul\x00byte", "\x1b[31m"):
        ok, reason, _ = ui_logic.validate_checks(
            {"checks": [{"url": "https://x/", "tier": "advisory", "body": bad}]})
        assert not ok and reason, repr(bad)


def test_validate_checks_body_allows_leading_dash():
    # The body reaches grep as `-F -e <pattern>`, so a leading dash is a literal
    # pattern, not an option. It must not be rejected the way a URL is.
    ok, _, clean = ui_logic.validate_checks(
        {"checks": [{"url": "https://x/", "tier": "advisory", "body": "-not-an-option"}]})
    assert ok and clean[0]["body"] == "-not-an-option"


def test_builtin_youtube_asserts_playability():
    # A status-only YouTube check passes on exits that cannot play video.
    yt = [c for c in ui_logic.BUILTIN_CHECKS if "youtube" in c["url"]]
    assert len(yt) == 1
    assert "watch?v=" in yt[0]["url"] and yt[0]["tier"] == "mandatory"
    assert yt[0]["body"] == '"playabilityStatus":{"status":"OK"'


def test_parse_checks():
    assert ui_logic.parse_checks('{"checks":[{"url":"https://x/","tier":"advisory"}]}') == \
        [{"url": "https://x/", "tier": "advisory"}]
    assert ui_logic.parse_checks("") == []
    assert ui_logic.parse_checks("garbage{") == []
    assert ui_logic.parse_checks('{"checks":[{"url":"https://x/"},{"bad":1}]}') == []


def test_netshield_knob():
    for good in ("0", "1", "2"):
        assert ui_logic.validate_knob("PROTEUS_NETSHIELD_LEVEL", good)[0], good
    for bad in ("3", "-1", "2.0", "abc", ""):
        assert not ui_logic.validate_knob("PROTEUS_NETSHIELD_LEVEL", bad)[0], bad
    assert ui_logic.KNOBS["PROTEUS_NETSHIELD_LEVEL"].default == "2"


def test_client_isolation_knob():
    for good in ("open", "isolated"):
        assert ui_logic.validate_knob("PROTEUS_CLIENT_ISOLATION", good)[0], good
    # wrong case, partial, empty, injection, and near-misses all reject
    for bad in ("OPEN", "isolate", "on", "", "0", "open ", "open;isolated", "isolated\n"):
        assert not ui_logic.validate_knob("PROTEUS_CLIENT_ISOLATION", bad)[0], bad
    k = ui_logic.KNOBS["PROTEUS_CLIENT_ISOLATION"]
    assert k.default == "open" and k.group == "network"
    assert k.choices == ("open", "isolated")
    assert k.kick == "proteus-client-isolation.service"


def test_client_isolation_failsafe_knob():
    for good in ("open", "closed"):
        assert ui_logic.validate_knob("PROTEUS_CLIENT_ISOLATION_FAILSAFE", good)[0], good
    # "isolated" is a valid value for the OTHER isolation knob — it must not be
    # accepted here, or a mixed-up write would silently pick the wrong branch.
    for bad in ("isolated", "OPEN", "shut", "", "0", "closed\n", "open closed"):
        assert not ui_logic.validate_knob("PROTEUS_CLIENT_ISOLATION_FAILSAFE", bad)[0], bad
    k = ui_logic.KNOBS["PROTEUS_CLIENT_ISOLATION_FAILSAFE"]
    assert k.default == "open"          # user asked for fail-open as the default
    assert k.group == "network"
    assert k.kick == "proteus-client-isolation.service"


def test_dns_latency_threshold_retuned_for_in_tunnel_resolver():
    # 300ms was sized for a ~220ms Quad9 TCP path; against an ~12ms in-tunnel
    # resolver it can never fire, silently disabling DNS-tunnel health rotation.
    k = ui_logic.KNOBS["PROTEUS_DNS_LATENCY_THRESHOLD_MS"]
    assert k.default == "150"
    assert k.lo <= 150 <= k.hi
    assert ui_logic.validate_knob("PROTEUS_DNS_LATENCY_THRESHOLD_MS", "150")[0]


def test_netshield_help_no_longer_claims_posture_only():
    # The old help said NetShield was bypassed by proteus's own resolver. After
    # the switch to Proton's in-tunnel DNS that is false and would mislead.
    h = ui_logic.KNOBS["PROTEUS_NETSHIELD_LEVEL"].help.lower()
    assert "posture only" not in h and "bypass" not in h


def test_choices_knob_schema_json_safe():
    # choices tuples must survive asdict()->json for /api/status; after the JSON
    # round-trip (what the frontend actually receives) they're arrays.
    wire = {s["key"]: s for s in json.loads(json.dumps(ui_logic.knob_schema()))}
    assert wire["PROTEUS_CLIENT_ISOLATION"]["choices"] == ["open", "isolated"]
    # non-choice knobs still carry an (empty) choices field, not a crash
    assert wire["PROTEUS_STREAMING_MIN_MBPS"]["choices"] == []


# --- Cloudflare canaries -------------------------------------------------------
import ledger


def test_validate_canaries_accepts_https_list():
    ok, reason, clean = ui_logic.validate_canaries(
        {"canaries": [{"url": "https://a.invalid/"}, {"url": "https://b.invalid/x?y=1"}]})
    assert ok, reason
    assert clean == [{"url": "https://a.invalid/"}, {"url": "https://b.invalid/x?y=1"}]


def test_validate_canaries_rejects_bad_entries():
    bad = [
        {"canaries": []},
        {"canaries": [{"url": "http://a.invalid/"}]},
        {"canaries": [{"url": "https://a.invalid/ x"}]},
        {"canaries": [{"url": "https://a.invalid/"}] * 2},
        {"canaries": [{"url": f"https://h{i}.invalid/"} for i in range(9)]},
        {"canaries": "https://a.invalid/"},
        {"canaries": [{"url": "https://a.invalid/;rm"}]},
        {"canaries": [{"url": "-https://a.invalid/"}]},
        {"canaries": [{"url": "https://" + "a" * 200 + ".invalid/"}]},
        {"canaries": [{"url": ["https://a.invalid/"]}]},          # url not a string
        {"canaries": [{"url": "https://\u0440\u0430ypal.com/"}]},  # Cyrillic homoglyph host
        # userinfo: reads as discord.com, is fetched from evil.invalid
        {"canaries": [{"url": "https://discord.com@evil.invalid/"}]},
    ]
    for obj in bad:
        ok, reason, _ = ui_logic.validate_canaries(obj)
        assert not ok, obj
        assert reason


def test_parse_canaries_falls_back_to_defaults():
    assert ui_logic.parse_canaries("") == ledger.DEFAULT_CANARIES
    assert ui_logic.parse_canaries("nope") == ledger.DEFAULT_CANARIES
    assert ui_logic.parse_canaries('{"canaries":[{"url":"https://a.invalid/"}]}') == ["https://a.invalid/"]


def test_builtin_checks_list_canaries_at_the_cf_tier():
    for tier in ("mandatory", "advisory"):
        out = ui_logic.builtin_checks(tier, ["https://a.invalid/"])
        assert out[:len(ui_logic.BUILTIN_CHECKS)] == ui_logic.BUILTIN_CHECKS
        assert out[-1] == {"url": "https://a.invalid/", "tier": tier, "canary": True}


def test_cf_knobs_registered_and_validated():
    for key, good, bad in [
        ("PROTEUS_CF_TIER", "advisory", "maybe"),
        ("PROTEUS_LIVECHECK", "off", "yes"),
        ("PROTEUS_LIVECHECK_FAILS", "3", "0"),
        ("PROTEUS_LIVECHECK_ROT_COOLDOWN", "3600", "10"),
        ("PROTEUS_CF_QUARANTINE_MIN_EXITS", "8", "1"),
        ("PROTEUS_MINT_EXPLORE", "0.5", "1.5"),
        ("PROTEUS_MINT_POOL_TARGET", "20", "0"),
        ("PROTEUS_MINT_REUSE_MIN_S", "604800", "9999999"),
    ]:
        assert ui_logic.validate_knob(key, good) == (True, ""), key
        assert not ui_logic.validate_knob(key, bad)[0], key


def test_cf_tier_knob_is_the_require_cf_ok_switch():
    k = ui_logic.KNOBS["PROTEUS_CF_TIER"]
    assert (k.label, k.default, k.choices) == ("Require cf ok", "mandatory", ("mandatory", "advisory"))
    assert k.group == "gates" and k.kick == "proteus-dispatcher.service"
    keys = [x for x in ui_logic.KNOBS if ui_logic.KNOBS[x].group == "gates"]
    cf = [x for x in keys if "CF" in x or "LIVECHECK" in x]
    assert cf[0] == "PROTEUS_CF_TIER"                      # first CF knob in Quality gates
    assert "\u2014" not in k.help and "advisory" in k.help and "mandatory" in k.help


def test_cf_tier_helper_one_rule():
    # Same rule as checklib.sh (${PROTEUS_CF_TIER:-mandatory}): unset or empty is mandatory.
    for value, want in [(None, "mandatory"), ("", "mandatory"), ("mandatory", "mandatory"),
                        ("advisory", "advisory"), ("bogus", "advisory")]:
        assert ui_logic.cf_tier(value) == want, value


def test_ledger_view_advisory_scores_the_standard_like_the_report(tmp_path):
    canaries = tmp_path / "canaries.json"
    canaries.write_text(json.dumps({"canaries": [{"url": "https://a.invalid/"}]}))
    led = tmp_path / "exit-ledger.jsonl"
    now = 1_800_000_000
    # Thirteen distinct exits pass the verdict; twelve are challenged on the canary and
    # one is clean (so the canary is not quarantined). Thirteen gate records in 24 h make
    # the ledger deep enough to judge attainability.
    led.write_text("".join(
        json.dumps({"ts": now - 10, "source": "gate", "exit_ip": f"10.219.3.{i}", "verdict": "pass",
                    "canaries": {"a.invalid": "clean" if i == 13 else "challenge"}}) + "\n"
        for i in range(1, 14)))
    args = (str(led), str(canaries), now, 2, 20, 8)
    strict = ui_logic.ledger_view(*args)
    assert strict["standard"]["size"] == 1 and strict["standard"]["attainable"] is False
    assert strict["standard"]["passing_exits_24h"] == 1 and strict["pool"]["known_good"] == 1
    assert ui_logic.ledger_view(*args, "mandatory") == strict
    for tier in ("advisory", "bogus"):
        adv = ui_logic.ledger_view(*args, tier)
        assert adv["standard"]["size"] == 0 and adv["standard"]["attainable"] is True, tier
        assert adv["standard"]["passing_exits_24h"] == 13 and adv["pool"]["known_good"] == 13, tier
        # Canary stats and quarantine still use the full basket.
        assert [c["host"] for c in adv["canaries"]] == ["a.invalid"]
        assert adv["canaries"] == strict["canaries"]
        assert adv["pool"]["target"] == 20


def test_removed_cf_knobs_are_gone():
    for key in ("PROTEUS_CF_FALLBACK", "PROTEUS_CF_STEPDOWN_RETRY_S"):
        assert key not in ui_logic.KNOBS, key
        assert ui_logic.validate_knob(key, "x")[0] is False


def test_slot_summary_cf_field():
    base = dict(state={"LOGICAL_NAME": "US-XX#1"}, health={}, next_rotation=None, rotating=False, now=0.0)
    s = ui_logic.slot_summary("proton-1", **base)
    assert s["cf"] == {"clean": None, "failing": [], "at": None}
    s = ui_logic.slot_summary("proton-1", cf={"CF_CLEAN": "no", "AT": "17", "FAILING": "a.invalid,b.invalid"}, **base)
    assert s["cf"] == {"clean": False, "failing": ["a.invalid", "b.invalid"], "at": 17}
    s = ui_logic.slot_summary("proton-1", cf={"CF_CLEAN": "yes", "AT": "x", "FAILING": ""}, **base)
    assert s["cf"] == {"clean": True, "failing": [], "at": None}


# exit_ip below is an RFC 1918 stand-in, not a real address; only its
# presence/shape matters to this test.
def test_ledger_view_survives_a_corrupt_ledger(tmp_path):
    canaries = tmp_path / "canaries.json"
    canaries.write_text(json.dumps({"canaries": [{"url": "https://a.invalid/"}]}))
    led = tmp_path / "exit-ledger.jsonl"
    # Valid JSON, wrong shape: canaries must be an object and exit_ip a string.
    # Either one makes ledger.status raise; /api/status must still answer.
    for bad in ('{"ts":1,"source":"gate","exit_ip":"10.219.3.4","canaries":"boom"}',
                '{"ts":1,"source":"promote","exit_ip":42}'):
        led.write_text(bad + "\n")
        assert ui_logic.ledger_view(str(led), str(canaries), 1, 2, 20, 8) == {
            "standard": {}, "canaries": [], "pool": {}}
    # A well-formed ledger still returns the real rollup.
    led.write_text('{"ts":1,"source":"gate","exit_ip":"10.219.3.4",'
                   '"canaries":{"a.invalid":"clean"}}\n')
    out = ui_logic.ledger_view(str(led), str(canaries), 1, 2, 20, 8)
    assert out["pool"]["known_good"] == 1
    assert [c["host"] for c in out["canaries"]] == ["a.invalid"]
    # Missing files degrade to an empty rollup, not an exception.
    missing = ui_logic.ledger_view(str(tmp_path / "nope"), str(tmp_path / "nope"), 1, 2, 20, 8)
    assert missing["pool"]["known_good"] == 0


# --- trusted egress ----------------------------------------------------------
def test_trusted_summary_shapes_the_status_block(tmp_path) -> None:
    """The UI shows the list, whether the tunnel exists, how long since the peer
    was heard from, and how many pins fall inside a trusted range."""
    health = tmp_path / "health"
    health.mkdir()
    (health / ".udm-tunnel").write_text("HANDSHAKE_AGE_S=42\n")
    pins = [{"ip": "192.168.7.9", "slot": "proton-1"},
            {"ip": "172.16.1.50", "slot": "proton-2"}]
    out = ui_logic.trusted_summary(["192.168.7.0/24"], up=True,
                                   health_dir=str(health), pins=pins)
    assert out == {"cidrs": ["192.168.7.0/24"], "tunnel_up": True,
                   "handshake_age_s": 42, "pinned": 1}


def test_trusted_summary_degrades_rather_than_raising(tmp_path) -> None:
    out = ui_logic.trusted_summary([], up=False, health_dir=str(tmp_path / "nope"), pins=None)
    assert out == {"cidrs": [], "tunnel_up": False, "handshake_age_s": None, "pinned": 0}
    bad = tmp_path / "health"
    bad.mkdir()
    (bad / ".udm-tunnel").write_text("HANDSHAKE_AGE_S=not-a-number\n")
    out = ui_logic.trusted_summary(["192.168.7.0/24"], up=True, health_dir=str(bad),
                                   pins=[{"ip": "junk"}, {"nope": 1}])
    assert out["handshake_age_s"] is None and out["pinned"] == 0
    # An interface with no handshake yet writes the key with an empty value, and
    # a malformed range or a non-list pin block must not reach the caller either.
    (bad / ".udm-tunnel").write_text("HANDSHAKE_AGE_S=\n")
    out = ui_logic.trusted_summary(["not-a-cidr"], up=True, health_dir=str(bad), pins="junk")
    assert out == {"cidrs": ["not-a-cidr"], "tunnel_up": True,
                   "handshake_age_s": None, "pinned": 0}


def test_builtin_checks_match_reputation_probe_script():
    """ui_logic.BUILTIN_CHECKS is a read-only mirror of reputation-probe.sh's
    probe list ("keep in sync" says the comment; this is what keeps it).
    Parse the probe() calls out of the script and compare url, tier and body."""
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "etc/proteus/bin/reputation-probe.sh").read_text()
    found = set()
    for m in re.finditer(r'(mandatory|advisory)_results\+=\( "\$\(probe\s+\S+\s+"([^"]+)"', src):
        tier, url = m.group(1), m.group(2)
        segment = src[m.end(): src.index(')" )', m.end())]
        quoted = re.findall(r"'([^']*)'", segment)       # [expected-code, body?]
        body = quoted[1] if len(quoted) > 1 else None
        found.add((url, tier, body))
    assert len(found) >= 5, found
    expected = {(c["url"], c["tier"], c.get("body")) for c in ui_logic.BUILTIN_CHECKS}
    assert found == expected, {"script_only": found - expected, "ui_only": expected - found}
