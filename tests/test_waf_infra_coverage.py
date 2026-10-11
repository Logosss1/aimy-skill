"""Offline coverage tests for the WAF bypass engine and the raw HTTP client.

All network, socket and subprocess activity is mocked. Targeted modules:
tools.waf_bypass (strategy tables, encoders, fingerprinting, bypass tests)
tools.http_client (raw socket client, wake-up challenge, response wrapper).

Some tests intentionally document current (defective) behaviour with a
"documented" suffix so the assertion is explicit about the gap.
"""

import socket as socket_mod
import types
from unittest import mock

from tools import http_client as hc
from tools import waf_bypass as wb


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None, url="http://t/"):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.content = text.encode("utf-8", errors="replace")


class FakeSession:
    def __init__(self, get_handler=None, post_handler=None):
        self.calls = []
        self.get_handler = get_handler
        self.post_handler = post_handler
        self.verify = True

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if callable(self.get_handler):
            return self.get_handler(url, kwargs)
        return MockResponse()

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if callable(self.post_handler):
            return self.post_handler(url, kwargs)
        return MockResponse()


def ok_handler(_url, _kwargs):
    return MockResponse(200, "ok")


# ---------------------------------------------------------------------------
# waf_bypass: fingerprinting
# ---------------------------------------------------------------------------


class TestFingerprintWaf:
    def test_exact_header_match_detects_cloudflare(self):
        sess = FakeSession(lambda u, k: MockResponse(200, "ok", {"CF-Ray": "abc"}))
        out = wb.fingerprint_waf("http://t/p", sess)
        assert out["detected"] is True
        assert out["name"] == "cloudflare"
        assert any("cf-ray" in e.lower() for e in out["evidence"])
        assert out["all_matches"]

    def test_wildcard_header_prefix_matches_akamai(self):
        sess = FakeSession(lambda u, k: MockResponse(200, "ok", {"X-Akamai-Config": "v"}))
        out = wb.fingerprint_waf("http://t/p", sess)
        assert out["detected"] is True
        assert out["name"] == "akamai"

    def test_body_evidence_tags_probe_source(self):
        sess = FakeSession(lambda u, k: MockResponse(200, "Attention Required! | Cloudflare"))
        out = wb.fingerprint_waf("http://t/p", sess)
        assert out["detected"] is True
        assert out["name"] == "cloudflare"
        sources = {m.get("source") for m in out["all_matches"]}
        assert sources == {"passive", "sqli_probe", "xss_probe"}

    def test_status_only_block_never_sets_detected_documented(self):
        sess = FakeSession(lambda u, k: MockResponse(403, "nope"))
        out = wb.fingerprint_waf("http://t/p", sess)
        assert out["detected"] is False
        assert out["name"] is None
        assert any("status_block" in m for m in out["all_matches"])

    def test_probe_urls_corrupt_existing_query_documented(self):
        sess = FakeSession(ok_handler)
        wb.fingerprint_waf("http://t/p?token=abc", sess)
        urls = [c[1] for c in sess.calls]
        assert urls[0] == "http://t/p?token=abc"
        assert urls[1].startswith("http://t/p?token=abc?")
        assert urls[1].count("?") == 2

    def test_probe_exceptions_swallowed_as_not_detected(self):
        def boom(_u, _k):
            raise ConnectionError("connection reset")

        out = wb.fingerprint_waf("http://t/p", FakeSession(boom))
        assert out["detected"] is False and out["name"] is None

    def test_f5_substring_false_positive_documented(self):
        sess = FakeSession(lambda u, k: MockResponse(200, "revision code: f5c0"))
        out = wb.fingerprint_waf("http://t/p", sess)
        assert out["detected"] is True
        assert out["name"] == "f5_bigip"

    def test_x_request_id_body_false_positive_documented(self):
        sess = FakeSession(lambda u, k: MockResponse(200, '{"error": "missing x-request-id"}'))
        out = wb.fingerprint_waf("http://t/p", sess)
        assert out["detected"] is True
        assert out["name"] == "chaitin_waf"

    def test_default_session_created_when_none(self, monkeypatch):
        created = []

        def factory():
            s = FakeSession(ok_handler)
            created.append(s)
            return s

        monkeypatch.setattr(wb.requests, "Session", factory)
        out = wb.fingerprint_waf("http://t/p", None, 3)
        assert created and out["detected"] is False


class TestGenerateBypasses:
    def test_known_type(self):
        assert "' OR '1'='1" in wb.generate_bypasses("sqli")

    def test_unknown_type_empty(self):
        assert wb.generate_bypasses("nope") == []


class TestCheck:
    def test_sprays_payloads_and_forwarded_header(self):
        sess = FakeSession(ok_handler)
        out = wb.check("http://t/p", "id", sess, 5)
        assert set(out["bypasses"]) == set(wb.BYPASS_PAYLOADS)
        for vtype, tested in out["bypasses"].items():
            assert len(tested) == len(wb.BYPASS_PAYLOADS[vtype]) + 5
            assert any(t["payload"].startswith("hdr:") for t in tested)
        header_calls = [
            c for c in sess.calls if c[2].get("headers", {}).get("X-Forwarded-For") == "127.0.0.1"
        ]
        assert len(header_calls) == 5 * len(wb.BYPASS_PAYLOADS)

    def test_without_param_skips_spraying(self):
        out = wb.check("http://t/p", None, FakeSession(ok_handler), 5)
        assert out["bypasses"] == {}
        assert out["vulnerable"] is False

    def test_payload_exceptions_do_not_abort(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] % 2 == 0:
                raise ConnectionError("flaky")
            return MockResponse(200, "ok")

        out = wb.check("http://t/p", "id", FakeSession(handler), 5)
        assert out["bypasses"]

    def test_waf_detected_marks_vulnerable(self):
        sess = FakeSession(
            lambda u, k: MockResponse(403, "Attention Required! Cloudflare", {"cf-ray": "1"})
        )
        out = wb.check("http://t/p", None, sess, 5)
        assert out["vulnerable"] is True
        assert out["type"] == "waf_detected"

    def test_default_session_created_when_none(self, monkeypatch):
        monkeypatch.setattr(wb.requests, "Session", lambda: FakeSession(ok_handler))
        out = wb.check("http://t/p", None, None, 3)
        assert out["vulnerable"] is False


# ---------------------------------------------------------------------------
# waf_bypass: block classification
# ---------------------------------------------------------------------------


class TestBlockClassification:
    def test_classify_block_none(self):
        assert wb.classify_block(None) == ""

    def test_cloudflare_text_signature(self):
        assert wb.classify_block(MockResponse(403, "Sorry, you have been blocked")) == "cloudflare"

    def test_aws_requestid_header_false_positive_documented(self):
        resp = MockResponse(200, "healthy payload", {"x-amzn-requestid": "1234"})
        assert wb.classify_block(resp) == "aws_waf"
        assert wb.is_blocked(resp) is True

    def test_is_blocked_hardcoded_statuses(self):
        for status in (403, 429, 406):
            assert wb.is_blocked(MockResponse(status)) is True
        assert wb.is_blocked(MockResponse(500)) is False
        assert wb.is_blocked(None) is False

    def test_threshold_parameter_honored(self):
        # 修复: threshold 现在生效 (旧逻辑被忽略)
        assert wb.is_blocked(MockResponse(500, "custom"), threshold=500) is True
        assert wb.is_blocked(MockResponse(404, "custom"), threshold=404) is True
        assert wb.is_blocked(MockResponse(500, "custom")) is False


# ---------------------------------------------------------------------------
# waf_bypass: block detection heuristics and adaptive escalation
# ---------------------------------------------------------------------------


class TestDetectBlock:
    def test_status_codes_block(self):
        for status in (403, 406, 429, 503):
            assert wb._detect_block(MockResponse(status)) is True

    def test_short_200_body_with_marker_blocks(self):
        assert wb._detect_block(MockResponse(200, "Access Denied")) is True

    def test_short_200_security_word_false_positive_documented(self):
        assert wb._detect_block(MockResponse(200, "Security Check Passed")) is True

    def test_long_200_body_ignores_markers(self):
        assert wb._detect_block(MockResponse(200, "blocked " * 40)) is False

    def test_plain_200_not_blocked(self):
        assert wb._detect_block(MockResponse(200, "hello world")) is False


class TestAdaptiveBypass:
    def test_first_strategy_returns_payload(self):
        sess = FakeSession(lambda u, k: MockResponse(200, "Z" * 150))
        out = wb.adaptive_bypass("http://t/p", "id", "' OR 1=1", sess)
        assert out["success"] is True
        assert out["strategy_index"] == 0
        assert out["payload"] == "' OR 1=1"

    def test_blocked_strategies_escalate(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] == 1:
                return MockResponse(200, "A" * 200)
            if state["n"] <= 3:
                return MockResponse(403, "blocked")
            return MockResponse(200, "B" * 300)

        out = wb.adaptive_bypass("http://t/p", "id", "' OR 1=1", FakeSession(handler))
        assert out["success"] is True
        assert out["strategy_index"] == 2

    def test_all_strategies_blocked(self):
        sess = FakeSession(lambda u, k: MockResponse(403, "blocked"))
        out = wb.adaptive_bypass("http://t/p", "id", "'", sess)
        assert out["success"] is False
        assert out["strategies_tried"] == 22

    def test_baseline_failure_still_tests_strategies(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] == 1:
                raise TimeoutError("baseline")
            return MockResponse(200, "Y" * 120)

        out = wb.adaptive_bypass("http://t/p", "id", "'", FakeSession(handler))
        assert out["success"] is True
        assert out["strategy_index"] == 0

    def test_request_exceptions_try_every_strategy(self):
        def handler(_u, _k):
            raise RuntimeError("boom")

        sess = FakeSession(handler)
        out = wb.adaptive_bypass("http://t/p", "id", "'", sess)
        assert out["success"] is False
        assert len(sess.calls) == 23


# ---------------------------------------------------------------------------
# waf_bypass: encoder outputs and strategy tables
# ---------------------------------------------------------------------------


class TestEncoderOutputs:
    def test_url_and_double_url_encode(self):
        assert wb.BypassEncoder.url_encode("a b'") == "a%20b%27"
        assert wb.BypassEncoder.double_url_encode("a b").startswith("a%2520b")

    def test_hex_and_null_bytes(self):
        assert wb.BypassEncoder.hex_encode("a'") == "%61%27"
        assert wb.BypassEncoder.null_bytes("ab") == "a%00b"

    def test_crlf_and_tab_injection(self):
        assert wb.BypassEncoder.tab_injection("a b") == "a%09b"
        assert wb.BypassEncoder.newline_injection("a b") == "a%0ab"
        assert wb.BypassEncoder.crlf_injection("a b") == "a%0d%0ab"

    def test_scientific_alternative(self):
        out = wb.BypassEncoder.scientific_alternative("1=1 and 1=2")
        assert out == "(select 1)=(select 1) and (select 1)=(select 2)"

    def test_versioned_comment(self):
        assert (
            wb.BypassEncoder.versioned_comment("UNION SELECT") == "/*!50000UNION*/ /*!50000SELECT*/"
        )

    def test_unmatched_encoder_chain_prefix_is_noop(self):
        def bad(_s):
            raise ValueError("fail")

        assert wb.apply_encoder_chain("keep", [bad]) == "keep"


class TestStrategyTableConsistency:
    HTTP_TIER = {"hpp", "hpp_duplicate", "chunked", "content_type_xml", "method_override"}

    def test_priority_names_resolve_to_encoder_or_http_tier(self):
        for name, strat in wb.WAF_BYPASS_STRATEGIES.items():
            if name is None:
                continue
            unresolved = [
                p
                for p in strat["priority"]
                if p not in wb.SQLI_BYPASS_ENCODERS and p not in self.HTTP_TIER
            ]
            assert unresolved == [], name

    def test_chain_indices_within_bounds(self):
        for name, strat in wb.WAF_BYPASS_STRATEGIES.items():
            for ci in strat.get("chain", []):
                assert 0 <= ci < len(wb.ENCODER_CHAINS), name

    def test_imperva_priority_mostly_not_in_sqli_pipeline_documented(self):
        out = wb.generate_sqli_payloads("' OR 1=1", "imperva")
        encoders = {p["encoder"] for p in out}
        assert "hex_encode" in encoders and "null_bytes" in encoders
        assert "chunked" not in encoders
        assert "content_type_xml" not in encoders
        assert "url_encode" not in encoders

    def test_cloudflare_hpp_priority_silently_dropped_documented(self):
        out = wb.generate_sqli_payloads("'", "cloudflare")
        assert "hpp" not in {p["encoder"] for p in out}
        assert "hpp" in wb.WAF_BYPASS_STRATEGIES["cloudflare"]["priority"]

    def test_unknown_waf_falls_back_to_default(self, monkeypatch):
        monkeypatch.setattr(wb.random, "choice", lambda seq: seq[0])
        monkeypatch.setattr(wb.random, "random", lambda: 0.9)
        unknown = wb.generate_sqli_payloads("' OR 1=1", "not_a_waf")
        default = wb.generate_sqli_payloads("' OR 1=1", None)
        assert [p["technique"] for p in unknown] == [p["technique"] for p in default]
        assert len(unknown) > 5

    def test_max_payloads_truncates(self):
        out = wb.generate_sqli_payloads("' OR 1=1", None, max_payloads=3)
        assert len(out) == 3
        assert out[0]["technique"] == "raw"

    def test_encoder_failure_logged_and_skipped(self, monkeypatch):
        def boom(_s):
            raise RuntimeError("encoder broken")

        monkeypatch.setitem(wb.SQLI_BYPASS_ENCODERS, "url_encode", boom)
        out = wb.generate_sqli_payloads("'", None)
        assert out[0]["technique"] == "raw"
        assert all(p["technique"] != "sqli_url_encode" for p in out)

    def test_chain_failure_logged_and_skipped(self, monkeypatch):
        def boom(_payload, _chain):
            raise RuntimeError("chain broken")

        monkeypatch.setattr(wb, "apply_encoder_chain", boom)
        out = wb.generate_sqli_payloads("'", None)
        assert out[0]["technique"] == "raw"
        assert all(not p["technique"].startswith("sqli_chain_") for p in out)


class TestHTTPBypassHelpers:
    def test_hpp_duplicate_keeps_both_values(self):
        out = wb.HTTPBypass.hpp_duplicate({"id": "1", "b": "2"}, "id", "'")
        assert out == "id=1&id='&b=2"

    def test_content_type_helpers(self):
        headers, body = wb.HTTPBypass.content_type_xml("P")
        assert headers["Content-Type"].startswith("application/xml")
        assert "<param>P</param>" in body
        headers2, body2 = wb.HTTPBypass.content_type_json("P")
        assert headers2 == {"Content-Type": "application/json"}
        assert body2 == '{"param":"P"}'

    def test_redundant_url_encode(self):
        assert wb.BypassEncoder.redundant_url_encode("' \" ") == "%2527%2520%2522%2520"

    def test_http_bypass_techniques_table(self):
        params = {"a": "1"}
        assert "id=x" in wb.HTTP_BYPASS_TECHNIQUES["hpp"](params, "id", "x")
        dup = wb.HTTP_BYPASS_TECHNIQUES["hpp_duplicate"](params, "a", "x")
        assert dup.count("a=") == 2
        headers, _body = wb.HTTP_BYPASS_TECHNIQUES["content_type_xml"](params, "id", "x")
        assert headers["Content-Type"].startswith("application/xml")
        _headers2, body2 = wb.HTTP_BYPASS_TECHNIQUES["content_type_json"](params, "id", "x")
        assert body2 == '{"param":"id=x"}'
        headers3, body3 = wb.HTTP_BYPASS_TECHNIQUES["chunked"](params, "id", "x")
        assert headers3["Transfer-Encoding"] == "chunked" and body3 == "id=x"
        headers4, body4 = wb.HTTP_BYPASS_TECHNIQUES["method_override"](params, "id", "x")
        assert headers4["X-HTTP-Method-Override"] == "POST" and body4 == "id=x"


# ---------------------------------------------------------------------------
# waf_bypass: SQLi / XSS verdict logic
# ---------------------------------------------------------------------------


class TestIndicatesInjection:
    def test_status_500(self):
        assert wb._indicates_injection(MockResponse(500, ""), None) is True

    def test_error_signatures(self):
        texts = [
            "SQL syntax near 'x' MySQL",
            "Warning: mysql_connect() failed",
            "MySQLSyntaxErrorException",
            "Unclosed quotation mark after the character string",
            "Microsoft OLE DB Provider for SQL Server",
            "PostgreSQL ERROR: syntax",
            "ORA-01756: quoted string",
            "SQLite Exception: near",
            "Division by zero",
        ]
        for text in texts:
            assert wb._indicates_injection(MockResponse(200, text), None) is True, text

    def test_length_diff_requires_same_status(self):
        baseline = MockResponse(200, "x" * 100)
        assert wb._indicates_injection(MockResponse(200, "x" * 200), baseline) is True
        assert wb._indicates_injection(MockResponse(404, "x" * 200), baseline) is False
        assert wb._indicates_injection(MockResponse(200, "x" * 110), baseline) is False


class TestSqliBypass:
    def test_500_response_marks_vulnerable_and_stops_at_three(self):
        sess = FakeSession(lambda u, k: MockResponse(500, "error"))
        out = wb.test_sqli_bypass("http://t/p", "id", sess, "cloudflare", 5)
        assert out["vulnerable"] is True
        assert len(out["bypasses"]) == 3
        assert out["bypasses"][0]["technique"] == "raw"
        assert out["best_payload"]
        assert len(sess.calls) == 4

    def test_error_signature_in_200_response(self):
        sess = FakeSession(lambda u, k: MockResponse(200, "SQL syntax near 'x' MySQL"))
        out = wb.test_sqli_bypass("http://t/p", "id", sess, None, 5)
        assert out["vulnerable"] is True

    def test_length_diff_in_200_response(self):
        def handler(url, _k):
            if url.endswith("id=1"):
                return MockResponse(200, "short")
            return MockResponse(200, "X" * 100)

        out = wb.test_sqli_bypass("http://t/p", "id", FakeSession(handler), None, 5)
        assert out["vulnerable"] is True
        assert out["bypasses"][0]["technique"] == "raw"

    def test_baseline_failure_does_not_abort(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] == 1:
                raise ConnectionError("baseline down")
            return MockResponse(200, "normal")

        out = wb.test_sqli_bypass("http://t/p", "id", FakeSession(handler), None, 5)
        assert out["vulnerable"] is False

    def test_payload_request_exception_skipped_then_detected(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] == 1:
                return MockResponse(200, "base")
            if state["n"] == 2:
                raise ConnectionError("transient")
            return MockResponse(200, "SQL syntax MySQL")

        out = wb.test_sqli_bypass("http://t/p", "id", FakeSession(handler), None, 5)
        assert out["vulnerable"] is True


class TestXssBypass:
    def test_reflection_detected_and_capped_at_three(self):
        sess = FakeSession(lambda u, k: MockResponse(200, u))
        out = wb.test_xss_bypass("http://t/p", "q", sess, 5)
        assert out["vulnerable"] is True
        assert len(out["bypasses"]) == 3
        assert out["bypasses"][0]["payload"] == "<script>alert(1)</script>"
        assert len(sess.calls) == 3

    def test_no_reflection_tries_every_payload(self):
        sess = FakeSession(lambda u, k: MockResponse(200, "safe page"))
        out = wb.test_xss_bypass("http://t/p", "q", sess, 5)
        assert out["vulnerable"] is False
        assert len(sess.calls) == len(wb.XSS_BYPASS_PAYLOADS)

    def test_request_exceptions_ignored(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] <= 2:
                raise ConnectionError("flaky")
            return MockResponse(200, "safe page")

        sess = FakeSession(handler)
        out = wb.test_xss_bypass("http://t/p", "q", sess, 5)
        assert out["vulnerable"] is False
        assert len(sess.calls) == len(wb.XSS_BYPASS_PAYLOADS)


class TestHttpBypass:
    def test_hpp_runs_for_cloudflare_priority(self):
        sess = FakeSession(lambda u, k: MockResponse(500, "err"))
        out = wb.test_http_bypass("http://t/p?a=1", "id", sess, "cloudflare", 5)
        assert out["vulnerable"] is True
        assert out["bypasses"][0]["technique"] == "hpp"
        assert "a=1&id=" in sess.calls[0][1]

    def test_hpp_without_existing_query(self):
        sess = FakeSession(lambda u, k: MockResponse(500, "err"))
        out = wb.test_http_bypass("http://t/p", "id", sess, "cloudflare", 5)
        assert out["vulnerable"] is True
        assert sess.calls[0][1].startswith("http://t/p?id=")

    def test_chunked_runs_for_imperva_priority(self):
        sess = FakeSession(post_handler=lambda u, k: MockResponse(500, "err"))
        out = wb.test_http_bypass("http://t/p", "id", sess, "imperva", 5)
        assert out["vulnerable"] is True
        assert out["bypasses"][0]["technique"] == "chunked"
        post_call = [c for c in sess.calls if c[0] == "POST"][0]
        assert post_call[2]["headers"]["Transfer-Encoding"] == "chunked"
        assert post_call[2]["data"].endswith("0\r\n\r\n")

    def test_method_override_loop_hits(self):
        def handler(_u, kwargs):
            if kwargs.get("headers", {}).get("X-HTTP-Method-Override") == "POST":
                return MockResponse(500, "err")
            return MockResponse(200, "ok")

        sess = FakeSession(handler)
        out = wb.test_http_bypass("http://t/p", "id", sess, "chaitin_waf", 5)
        assert out["vulnerable"] is True
        assert out["bypasses"][0]["technique"] == "method_override_POST"
        assert out["bypasses"][0]["payload"] == "' OR '1'='1"

    def test_request_exceptions_swallowed(self):
        def handler(_u, _k):
            raise ConnectionError("down")

        out = wb.test_http_bypass("http://t/p", "id", FakeSession(handler), None, 5)
        assert out["vulnerable"] is False

    def test_chunked_post_exception_swallowed(self):
        def post_handler(_u, _k):
            raise ConnectionError("post down")

        sess = FakeSession(ok_handler, post_handler)
        out = wb.test_http_bypass("http://t/p", "id", sess, None, 5)
        assert out["vulnerable"] is False
        assert any(c[0] == "POST" for c in sess.calls)


class TestWafStrength:
    def test_counts_blocks_passes_and_errors(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] <= 3:
                return MockResponse(200, "ok")
            if state["n"] == 4:
                return MockResponse(403, "")
            if state["n"] == 5:
                return MockResponse(200, "blocked by waf")
            if state["n"] == 6:
                return MockResponse(429, "")
            return MockResponse(200, "fine")

        out = wb.test_waf_strength("http://t/p", FakeSession(handler), 5)
        assert out["blocked_count"] == 3
        assert out["bypass_count"] == 1
        assert out["summary"]["block_rate"] == "3/4"
        assert out["waf"]["detected"] is False

    def test_request_errors_counted_as_blocked(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] <= 3:
                return MockResponse(200, "ok")
            raise ConnectionResetError("reset")

        out = wb.test_waf_strength("http://t/p", FakeSession(handler), 5)
        assert out["blocked_count"] == 4
        assert out["bypass_count"] == 0
        assert out["summary"]["block_rate"] == "4/4"


class TestHeavyCheck:
    def test_param_none_skips_sqli_and_xss(self):
        out = wb.heavy_check("http://t/p", None, FakeSession(ok_handler), 5)
        assert out["sqli_bypass"] is None
        assert out["xss_bypass"] is None
        assert out["http_bypass"] is not None
        assert out["vulnerable"] is False

    def test_sqli_finding_recorded(self):
        state = {"n": 0}

        def handler(_u, _k):
            state["n"] += 1
            if state["n"] <= 4:
                return MockResponse(200, "ok")
            if state["n"] <= 7:
                return MockResponse(500, "err")
            return MockResponse(200, "ok")

        out = wb.heavy_check("http://t/p", "id", FakeSession(handler), 5)
        assert out["vulnerable"] is True
        types_seen = {f["type"] for f in out["findings"]}
        assert types_seen == {"sqli_waf_bypass"}

    def test_default_session_created_when_none(self, monkeypatch):
        monkeypatch.setattr(wb.requests, "Session", lambda: FakeSession(ok_handler))
        out = wb.heavy_check("http://t/p", None, None, 3)
        assert out["vulnerable"] is False

    def test_all_finding_types_aggregated(self, monkeypatch):
        monkeypatch.setattr(
            wb,
            "fingerprint_waf",
            lambda url, sess, timeout: {"detected": True, "name": "cloudflare"},
        )
        monkeypatch.setattr(
            wb,
            "test_sqli_bypass",
            lambda *a, **k: {"vulnerable": True, "bypasses": [{"payload": "x"}]},
        )
        monkeypatch.setattr(
            wb,
            "test_xss_bypass",
            lambda *a, **k: {"vulnerable": True, "bypasses": [{"payload": "y"}]},
        )
        monkeypatch.setattr(
            wb,
            "test_http_bypass",
            lambda *a, **k: {"vulnerable": True, "bypasses": [{"technique": "hpp"}]},
        )
        out = wb.heavy_check("http://t/p", "id", FakeSession(ok_handler), 5)
        assert {f["type"] for f in out["findings"]} == {
            "sqli_waf_bypass",
            "xss_waf_bypass",
            "http_waf_bypass",
        }


# ---------------------------------------------------------------------------
# http_client: SSL context and challenge solving
# ---------------------------------------------------------------------------


class TestBuildSslContext:
    def test_verify_toggle_and_tls_floor(self, monkeypatch):
        monkeypatch.setattr(hc.settings, "verify_ssl", False)
        ctx = hc._build_ssl_context()
        assert ctx.verify_mode == hc.ssl.CERT_NONE
        assert ctx.check_hostname is False
        assert ctx.minimum_version == hc.ssl.TLSVersion.TLSv1_2
        assert ctx.maximum_version == hc.ssl.TLSVersion.TLSv1_2
        monkeypatch.setattr(hc.settings, "verify_ssl", True)
        ctx2 = hc._build_ssl_context()
        assert ctx2.verify_mode != hc.ssl.CERT_NONE


class TestGetAesJs:
    def test_fetches_and_caches(self, monkeypatch):
        calls = []

        def fake_request(_self, method, url, **kwargs):
            calls.append((method, url))
            return (200, {}, "J" * 1200)

        monkeypatch.setattr(hc._RawHttpClient, "request", fake_request)
        monkeypatch.setattr(hc, "_AES_JS_CACHE", None)
        body = hc._get_aes_js("https://t/some/page")
        assert body == "J" * 1200
        assert calls == [("GET", "https://t/aes.js")]
        assert hc._get_aes_js("https://t/some/page") == "J" * 1200
        assert len(calls) == 1

    def test_short_body_not_cached(self, monkeypatch):
        monkeypatch.setattr(hc._RawHttpClient, "request", lambda *a, **k: (200, {}, "tiny"))
        monkeypatch.setattr(hc, "_AES_JS_CACHE", None)
        assert hc._get_aes_js("https://t/") is None
        assert hc._AES_JS_CACHE is None

    def test_failure_returns_none(self, monkeypatch):
        def boom(*_a, **_k):
            raise OSError("no route")

        monkeypatch.setattr(hc._RawHttpClient, "request", boom)
        monkeypatch.setattr(hc, "_AES_JS_CACHE", None)
        assert hc._get_aes_js("https://t/") is None


CHALLENGE_HTML = 'toNumbers("aa")' + "pad" * 20 + 'toNumbers("bb")' + "pad" * 5 + 'toNumbers("cc")'

JS_OUTPUT_OK = types.SimpleNamespace(stdout="ab" * 16 + "\n", stderr="", returncode=0)


class TestSolveChallenge:
    def test_no_pattern_skips_node(self, monkeypatch):
        calls = []
        monkeypatch.setattr(hc.subprocess, "run", lambda *a, **k: calls.append(a))
        assert hc._solve_challenge("no challenge here", "http://t/") is None
        assert calls == []

    def test_without_aes_js_returns_none(self, monkeypatch):
        monkeypatch.setattr(hc, "_get_aes_js", lambda base: None)
        assert hc._solve_challenge(CHALLENGE_HTML, "http://t/") is None

    def test_valid_cookie_returned(self, monkeypatch):
        monkeypatch.setattr(hc, "_get_aes_js", lambda base: "var slowAES = {};")
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            return JS_OUTPUT_OK

        monkeypatch.setattr(hc.subprocess, "run", fake_run)
        assert hc._solve_challenge(CHALLENGE_HTML, "http://t/") == "ab" * 16
        assert seen["cmd"][0] == "node" and seen["cmd"][1] == "-e"
        assert "slowAES" in seen["cmd"][2] and 'toNumbers("bb")' in seen["cmd"][2]

    def test_invalid_output_returns_none(self, monkeypatch):
        monkeypatch.setattr(hc, "_get_aes_js", lambda base: "js")
        bad = types.SimpleNamespace(stdout="zz" * 16, stderr="", returncode=0)
        monkeypatch.setattr(hc.subprocess, "run", lambda *a, **k: bad)
        assert hc._solve_challenge(CHALLENGE_HTML, "http://t/") is None

    def test_node_failure_returns_none(self, monkeypatch):
        monkeypatch.setattr(hc, "_get_aes_js", lambda base: "js")

        def boom(*_a, **_k):
            raise FileNotFoundError("node not installed")

        monkeypatch.setattr(hc.subprocess, "run", boom)
        assert hc._solve_challenge(CHALLENGE_HTML, "http://t/") is None


# ---------------------------------------------------------------------------
# http_client: raw socket client
# ---------------------------------------------------------------------------


class FakeSock:
    def __init__(self, chunks=None, exc=None):
        self.chunks = list(chunks or [])
        self.exc = exc or socket_mod.timeout("timed out")
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, _n):
        if self.chunks:
            return self.chunks.pop(0)
        raise self.exc

    def close(self):
        self.closed = True


def _install_socket(monkeypatch, sock, addr_holder=None):
    def fake_create_connection(addr, timeout=None):
        if addr_holder is not None:
            addr_holder.append((addr, timeout))
        return sock

    monkeypatch.setattr(hc.socket, "create_connection", fake_create_connection)


class TestRawHttpClient:
    def test_parses_response_and_builds_request(self, monkeypatch):
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-UPPER: v\r\n\r\nhello"
        sock = FakeSock([response])
        _install_socket(monkeypatch, sock)
        client = hc._RawHttpClient(timeout=2)
        status, headers, body = client.request(
            "POST", "http://t/p?a=1", headers={"A": "b"}, body="x=1", cookie="c"
        )
        assert (status, headers["content-type"], headers["x-upper"], body) == (
            200,
            "text/html",
            "v",
            "hello",
        )
        req = sock.sent.decode()
        assert req.startswith("POST /p?a=1 HTTP/1.1\r\n")
        assert "Host: t\r\n" in req
        assert "A: b\r\n" in req
        assert "Content-Length: 3\r\n" in req
        assert "Cookie: __test=c\r\n" in req
        assert req.endswith("x=1")
        assert sock.closed is True

    def test_https_wraps_socket_with_hostname(self, monkeypatch):
        sock = FakeSock([b"HTTP/1.1 204 No Content\r\n\r\n"])
        addrs = []
        _install_socket(monkeypatch, sock, addrs)
        client = hc._RawHttpClient(timeout=1)
        wrapped = []

        class FakeCtx:
            def wrap_socket(self, s, server_hostname=None):
                wrapped.append(server_hostname)
                return s

        client._ctx = FakeCtx()
        status, _headers, body = client.request("GET", "https://t/")
        assert status == 204 and body == ""
        assert addrs == [(("t", 443), 1)]
        assert wrapped == ["t"]

    def test_chunked_body_not_deframed_documented(self, monkeypatch):
        response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        _install_socket(monkeypatch, FakeSock([response]))
        client = hc._RawHttpClient(timeout=1)
        _status, headers, body = client.request("GET", "http://t/")
        assert headers["transfer-encoding"] == "chunked"
        assert body == "5\r\nhello\r\n0\r\n\r\n"

    def test_recv_error_returns_partial(self, monkeypatch):
        _install_socket(monkeypatch, FakeSock([], exc=RuntimeError("reset")))
        client = hc._RawHttpClient(timeout=1)
        assert client.request("GET", "http://t/") == (0, {}, "")

    def test_missing_header_terminator(self, monkeypatch):
        _install_socket(monkeypatch, FakeSock([b"garbage"]))
        client = hc._RawHttpClient(timeout=1)
        assert client.request("GET", "http://t/") == (0, {}, "garbage")

    def test_malformed_status_line(self, monkeypatch):
        _install_socket(monkeypatch, FakeSock([b"HTTP/1.1\r\nX: 1\r\n\r\nbody"]))
        client = hc._RawHttpClient(timeout=1)
        status, headers, body = client.request("GET", "http://t/")
        assert status == 0 and headers["x"] == "1" and body == "body"

    def test_empty_recv_terminates_read(self, monkeypatch):
        sock = FakeSock([b"HTTP/1.1 200 OK\r\n\r\nbody", b""])
        _install_socket(monkeypatch, sock)
        client = hc._RawHttpClient(timeout=1)
        assert client.request("GET", "http://t/") == (200, {}, "body")


# ---------------------------------------------------------------------------
# http_client: HttpClient wrapper behaviour
# ---------------------------------------------------------------------------


class RecordedRaw:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, cookie=None):
        self.calls.append(
            {"method": method, "url": url, "headers": headers, "body": body, "cookie": cookie}
        )
        return self.responses.pop(0)


class TestHttpClient:
    def test_request_wraps_raw_result(self):
        client = hc.HttpClient(timeout=3)
        client._raw = RecordedRaw([(200, {"content-type": "text/html"}, "body")])
        resp = client.get("http://t/p")
        assert isinstance(resp, hc.FakeResponse)
        assert resp.status_code == 200 and resp.text == "body" and resp.ok is True
        assert client._raw.calls[0]["method"] == "GET"

    def test_convenience_methods_dispatch(self):
        client = hc.HttpClient()
        client._raw = RecordedRaw([(200, {}, "x")] * 4)
        client.get("http://t/")
        client.post("http://t/")
        client.put("http://t/")
        client.delete("http://t/")
        assert [c["method"] for c in client._raw.calls] == ["GET", "POST", "PUT", "DELETE"]

    def test_challenge_solved_then_retried_with_cookie(self, monkeypatch):
        body = "x" * 100 + "slowAES toNumbers"
        client = hc.HttpClient()
        raw = RecordedRaw([(200, {"content-type": "text/html"}, body), (200, {}, "done")])
        client._raw = raw
        monkeypatch.setattr(hc, "_solve_challenge", lambda html, url: "ab" * 16)
        resp = client.get("http://t/p")
        assert resp.text == "done"
        assert len(raw.calls) == 2
        assert raw.calls[0]["cookie"] is None
        assert raw.calls[1]["cookie"] == "ab" * 16
        assert client._cookie == "ab" * 16

    def test_solve_challenge_not_called_when_already_solved(self, monkeypatch):
        calls = []
        monkeypatch.setattr(hc, "_solve_challenge", lambda html, url: calls.append(1))
        client = hc.HttpClient()
        client._challenge_solved = True
        assert client._auto_solve("slowAES toNumbers", "http://t/") is None
        assert calls == []

    def test_auto_solve_ignores_bodies_without_markers(self):
        client = hc.HttpClient()
        assert client._auto_solve("plain page", "http://t/") is None

    def test_auto_solve_failure_leaves_state_unsolved(self, monkeypatch):
        monkeypatch.setattr(hc, "_solve_challenge", lambda html, url: None)
        client = hc.HttpClient()
        assert client._auto_solve("slowAES toNumbers", "http://t/") is None
        assert client._challenge_solved is False
        assert client._cookie is None

    def test_auto_solve_marker_after_2000_bytes(self, monkeypatch):
        # 修复: 挑战标记窗口与全文正则一致, 2000 字符后的标记也会求解
        called = []
        monkeypatch.setattr(hc, "_solve_challenge", lambda html, url: called.append(html))
        client = hc.HttpClient()
        late_marker = "x" * 2100 + "slowAES toNumbers"
        assert client._auto_solve(late_marker, "http://t/") is None
        assert called == [late_marker]

    def test_extra_kwargs_forwarded(self):
        # 修复: params/json/cookies 不再静默丢弃
        client = hc.HttpClient()
        raw = mock.Mock()
        raw.request.return_value = (200, {}, "ok")
        client._raw = raw
        client.post(
            "http://t/p",
            headers={"H": "1"},
            data="x",
            cookies={"s": "1"},
            json={"a": 1},
            params={"q": "1"},
            timeout=1,
            verify=False,
            allow_redirects=False,
        )
        args, forwarded = client._raw.request.call_args
        assert set(forwarded) == {"headers", "body", "cookie"}
        assert forwarded["headers"]["H"] == "1"
        assert forwarded["headers"]["Content-Type"] == "application/json"
        assert forwarded["body"] == '{"a": 1}'
        assert forwarded["cookie"] == "s=1"
        assert "?q=1" in args[1]

    def test_injected_session_used(self):
        # 修复: 注入的 Session 现在真正用于请求 (旧逻辑被丢弃)
        class RecordingSession:
            def __init__(self):
                self.calls = []

            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return MockResponse(200, "session body")

        sess = RecordingSession()
        client = hc.HttpClient(sess=sess)
        client._raw = RecordedRaw([(200, {}, "raw body")])
        resp = client.get("http://t/p")
        assert resp.text == "session body"
        assert len(sess.calls) == 1

    def test_ensure_session_lazy(self):
        client = hc.HttpClient()
        assert not hasattr(client, "_raw")
        client._ensure_session()
        assert isinstance(client._raw, hc._RawHttpClient)

    def test_resolve_url(self):
        client = hc.HttpClient()
        assert client.resolve_url("http://t", "/a") == "http://t/a"
        assert client.resolve_url("http://t/", "a") == "http://t/a"


class TestFakeResponse:
    def test_ok_boundaries_and_content(self):
        r = hc.FakeResponse(204, {}, "", "http://t/")
        assert r.ok is True and r.content == b"" and "204" in repr(r)
        r2 = hc.FakeResponse(404, {}, "x", "http://t/")
        assert r2.ok is False and r2.content == b"x"

    def test_non_utf8_safe_content(self):
        r = hc.FakeResponse(200, {}, "\udcff", "http://t/")
        assert isinstance(r.content, bytes)


class TestBuildUrl:
    def test_overwrites_existing_param(self):
        url = hc.build_url("http://t/p?id=1&keep=2", "id", "3")
        assert "id=3" in url and "keep=2" in url

    def test_preserves_fragment(self):
        url = hc.build_url("http://t/p?a=1#frag", "b", "2")
        assert url.endswith("#frag")
        assert "a=1" in url and "b=2" in url

    def test_spaces_and_quotes_encoded(self):
        url = hc.build_url("http://t/", "q", "hello world&x")
        assert "hello+world%26x" in url
