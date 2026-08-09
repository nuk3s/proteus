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
