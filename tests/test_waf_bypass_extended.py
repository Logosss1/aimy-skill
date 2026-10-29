from tools.waf_bypass import (
    BYPASS_PAYLOADS,
    BypassEncoder,
    HTTPBypass,
    apply_encoder_chain,
    classify_block,
    generate_bypasses,
    is_blocked,
)


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class TestClassifyBlock:
    def test_none_response(self):
        assert classify_block(None) == ""

    def test_cloudflare_body(self):
        resp = MockResponse(403, "Attention Required! Cloudflare")
        assert classify_block(resp) == "cloudflare"

    def test_mod_security_body(self):
        resp = MockResponse(403, "Mod Security Web Application Firewall")
        result = classify_block(resp)
        assert result in ("mod_security", "generic", "akamai")

    def test_no_waf_detected(self):
        resp = MockResponse(200, "normal page content")
        assert classify_block(resp) == ""

    def test_akamai_body(self):
        resp = MockResponse(403, "access denied akamai")
        assert classify_block(resp) == "akamai"

    def test_aws_waf_body(self):
        resp = MockResponse(403, "Request blocked by AWSWAF")
        assert classify_block(resp) == "aws_waf"

    def test_cloudflare_header(self):
        resp = MockResponse(200, "cf-ray: 12345", {"cf-ray": "12345"})
        assert classify_block(resp) == "cloudflare"


class TestIsBlocked:
    def test_none_response(self):
        assert is_blocked(None) is False

    def test_status_403(self):
        assert is_blocked(MockResponse(403)) is True

    def test_status_429(self):
        assert is_blocked(MockResponse(429)) is True

    def test_status_406(self):
        assert is_blocked(MockResponse(406)) is True

    def test_status_200_not_blocked(self):
        assert is_blocked(MockResponse(200)) is False

    def test_waf_signature_blocked(self):
        resp = MockResponse(200, "Attention Required! Cloudflare")
        assert is_blocked(resp) is True

    def test_status_500_not_blocked(self):
        assert is_blocked(MockResponse(500)) is False

    def test_custom_threshold(self):
        resp = MockResponse(404, "Not Found")
        # 修复: threshold 现在生效, 404 >= 404 视为拦截
        result = is_blocked(resp, threshold=404)
        assert result is True
        assert is_blocked(resp) is False


class TestGenerateBypasses:
    def test_sqli_bypasses(self):
        payloads = generate_bypasses("sqli")
        assert len(payloads) > 0
        assert "' OR '1'='1" in payloads

    def test_xss_bypasses(self):
        payloads = generate_bypasses("xss")
        assert len(payloads) > 0
        assert "<script>alert(1)</script>" in payloads

    def test_unknown_vuln_type(self):
        payloads = generate_bypasses("unknown_type")
        assert payloads == []

    def test_lfi_bypasses(self):
        payloads = generate_bypasses("lfi")
        assert len(payloads) > 0
        assert any("etc/passwd" in p for p in payloads)

    def test_ssti_bypasses(self):
        payloads = generate_bypasses("ssti")
        assert len(payloads) > 0

    def test_nosqli_bypasses(self):
        payloads = generate_bypasses("nosqli")
        assert len(payloads) > 0


class TestBypassEncoder:
    def test_url_encode(self):
        result = BypassEncoder.url_encode("hello world")
        assert result == "hello%20world"

    def test_double_url_encode(self):
        result = BypassEncoder.double_url_encode("hello world")
        assert "hello" in result
        assert result != "hello%20world"

    def test_unicode_url_encode(self):
        result = BypassEncoder.unicode_url_encode("' OR '1'='1")
        assert "%u" in result

    def test_overlong_utf8_encode(self):
        result = BypassEncoder.overlong_utf8_encode("<script>")
        assert "%C0" in result

    def test_ibm037_encode(self):
        result = BypassEncoder.ibm037_encode("'test\"")
        assert "%X7F" in result

    def test_hex_encode(self):
        result = BypassEncoder.hex_encode("a")
        assert "%61" in result

    def test_null_bytes(self):
        result = BypassEncoder.null_bytes("abc")
        assert "%00" in result
        assert result == "a%00b%00c"

    def test_case_random(self):
        import random

        random.seed(42)
        result = BypassEncoder.case_random("OR 1=1")
        assert "OR" in result or "or" in result

    def test_scientific_notation(self):
        result = BypassEncoder.scientific_notation("1=1")
        assert "1.0=1.0" in result

    def test_negative_sign(self):
        result = BypassEncoder.negative_sign("1=1")
        assert "-(-1)" in result

    def test_negative_sign_2(self):
        result = BypassEncoder.negative_sign("1=2")
        assert "-(-2)" in result


class TestApplyEncoderChain:
    def test_single_encoder(self):
        chain = [BypassEncoder.url_encode]
        result = apply_encoder_chain("hello world", chain)
        assert result == "hello%20world"

    def test_multi_encoder(self):
        chain = [BypassEncoder.url_encode, BypassEncoder.hex_encode]
        result = apply_encoder_chain("hello world", chain)
        assert "%" in result

    def test_encoder_failure_continues(self):
        def bad_enc(s):
            raise ValueError("fail")

        result = apply_encoder_chain("test", [bad_enc, BypassEncoder.url_encode])
        assert result == "test"


class TestHTTPBypass:
    def test_hpp_single_param(self):
        params = {"a": "1", "b": "2"}
        result = HTTPBypass.hpp(params, "c", "3")
        assert "c=3" in result
        assert "a=1" in result

    def test_hpp_duplicate_key(self):
        params = {"id": "1", "b": "2"}
        result = HTTPBypass.hpp_duplicate(params, "id", "3")
        assert result.count("id=") == 2
        assert "id=3" in result

    def test_content_type_xml(self):
        headers, body = HTTPBypass.content_type_xml("payload")
        assert headers["Content-Type"] == "application/xml; charset=utf-8"
        assert "<param>payload</param>" in body

    def test_content_type_json(self):
        headers, body = HTTPBypass.content_type_json("payload")
        assert headers["Content-Type"] == "application/json"
        assert "payload" in body

    def test_chunked_encoding(self):
        headers = HTTPBypass.chunked_encoding("payload")
        assert "Transfer-Encoding" in headers
        assert headers["Transfer-Encoding"] == "chunked"

    def test_method_override(self):
        headers = HTTPBypass.method_override("DELETE")
        assert headers["X-HTTP-Method-Override"] == "DELETE"


class TestWAFConstants:
    def test_bypass_payloads_has_categories(self):
        assert "sqli" in BYPASS_PAYLOADS
        assert "xss" in BYPASS_PAYLOADS
        assert "lfi" in BYPASS_PAYLOADS
        assert "ssti" in BYPASS_PAYLOADS
        assert "nosqli" in BYPASS_PAYLOADS

    def test_sqli_payloads_not_empty(self):
        assert len(BYPASS_PAYLOADS["sqli"]) > 10

    def test_xss_payloads_not_empty(self):
        assert len(BYPASS_PAYLOADS["xss"]) > 10

    def test_lfi_payloads_not_empty(self):
        assert len(BYPASS_PAYLOADS["lfi"]) > 5
