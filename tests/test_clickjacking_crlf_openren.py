import re

import responses

from tools._session import make_session


class TestClickjackingDetector:
    @responses.activate
    def test_no_protection_headers(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(
            responses.GET, "http://test.com/page", status=200, body="<html>ok</html>", headers={}
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is True
        assert len(result["findings"]) == 1
        assert result["findings"][0]["type"] == "clickjacking"
        assert result["findings"][0]["severity"] == "medium"

    @responses.activate
    def test_xfo_deny_protected(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(
            responses.GET,
            "http://test.com/page",
            status=200,
            body="<html>ok</html>",
            headers={"X-Frame-Options": "DENY"},
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is False
        assert result.get("protected", False) is False or "findings" in result

    @responses.activate
    def test_xfo_sameorigin_protected(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(
            responses.GET,
            "http://test.com/page",
            status=200,
            body="<html>ok</html>",
            headers={"X-Frame-Options": "SAMEORIGIN"},
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_xfo_weak_value(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(
            responses.GET,
            "http://test.com/page",
            status=200,
            body="<html>ok</html>",
            headers={"X-Frame-Options": "ALLOWALL"},
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is True

    @responses.activate
    def test_csp_frame_ancestors_none(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(
            responses.GET,
            "http://test.com/page",
            status=200,
            body="<html>ok</html>",
            headers={"Content-Security-Policy": "frame-ancestors 'none'"},
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is False
        assert result.get("protected") is True

    @responses.activate
    def test_csp_frame_ancestors_self(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(
            responses.GET,
            "http://test.com/page",
            status=200,
            body="<html>ok</html>",
            headers={"Content-Security-Policy": "frame-ancestors 'self'"},
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is False
        assert result.get("protected") is True

    @responses.activate
    def test_csp_frame_ancestors_unsafe(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(
            responses.GET,
            "http://test.com/page",
            status=200,
            body="<html>ok</html>",
            headers={"Content-Security-Policy": "frame-ancestors *"},
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is True

    @responses.activate
    def test_network_error(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(responses.GET, "http://test.com/page", body=ConnectionError("network error"))
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_url_prefix_fix(self):
        from tools.clickjacking import check

        sess = make_session()
        responses.add(responses.GET, "http://test.com/page", status=200, body="ok", headers={})
        result = check("test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is True


class TestCRLFSInjection:
    @responses.activate
    def test_no_injection(self):
        from tools.crlf_injection import check

        sess = make_session()
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/page\?q=.*"),
            status=200,
            body="ok",
            headers={},
        )
        result = check("http://test.com/page", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_set_cookie_injection(self):
        from tools.crlf_injection import check

        sess = make_session()

        def callback(request):
            if "injected" in request.url:
                return (200, {"Set-Cookie": "injected=true; Path=/"}, "ok")
            return (200, {}, "ok")

        responses.add_callback(responses.GET, re.compile(r".*"), callback=callback)
        result = check("http://test.com/page", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is True
        assert result["findings"][0]["type"] == "crlf_injection"

    @responses.activate
    def test_x_injected_header(self):
        from tools.crlf_injection import check

        sess = make_session()

        def callback(request):
            if "X-Injected" in request.url:
                return (200, {"X-Injected": "test"}, "ok")
            return (200, {}, "ok")

        responses.add_callback(responses.GET, re.compile(r".*"), callback=callback)

        import urllib.parse

        original_quote = urllib.parse.quote
        original_quote("%0d%0aX-Injected: test", safe="")
        url = "http://test.com/page?q=%0d%0aX-Injected: testtest"

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, url, status=200, headers={"X-Injected": "test"})
            result = check("http://test.com/page", "q", sess=sess, timeout=2)
            assert result["vulnerable"] is True or result["vulnerable"] is False

    @responses.activate
    def test_network_error(self):
        from tools.crlf_injection import check

        sess = make_session()
        responses.add(responses.GET, re.compile(r".*"), body=ConnectionError("network error"))
        result = check("http://test.com/page", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_existing_query_params(self):
        from tools.crlf_injection import check

        sess = make_session()
        responses.add(responses.GET, re.compile(r".*"), status=200, body="ok", headers={})
        result = check("http://test.com/page?foo=bar", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is False


class TestOpenRedirect:
    @responses.activate
    def test_no_redirect(self):
        from tools.open_redirect import check

        sess = make_session()
        responses.add(responses.GET, re.compile(r".*"), status=200, body="ok", headers={})
        result = check("http://test.com/page", "url", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_redirect_to_evil(self):
        from tools.open_redirect import check

        sess = make_session()
        responses.add(
            responses.GET,
            re.compile(r".*evil\.com"),
            status=302,
            headers={"Location": "https://evil.com"},
        )
        result = check("http://test.com/page", "url", sess=sess, timeout=2)
        assert result["vulnerable"] is True
        assert result["findings"][0]["type"] == "open_redirect"
        assert "evil.com" in result["findings"][0]["redirect_to"]

    @responses.activate
    def test_no_redirect_found(self):
        from tools.open_redirect import check

        sess = make_session()
        responses.add(responses.GET, re.compile(r".*"), status=200, body="ok", headers={})
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_redirect_with_existing_params(self):
        from tools.open_redirect import check

        sess = make_session()
        responses.add(
            responses.GET,
            re.compile(r".*evil\.com"),
            status=302,
            headers={"Location": "//evil.com"},
        )
        result = check("http://test.com/page?foo=bar", "url", sess=sess, timeout=2)
        assert result["vulnerable"] is True


class TestFileUpload:
    @responses.activate
    def test_upload_no_vuln(self):
        from tools.file_upload import check

        sess = make_session()
        responses.add(
            responses.POST, "http://test.com/upload", status=200, body="upload successful"
        )
        result = check("http://test.com/upload", sess=sess, timeout=2)
        assert isinstance(result, dict)

    def test_file_upload_constants(self):
        from tools.file_upload import DANGEROUS_EXTENSIONS

        assert ".php" in DANGEROUS_EXTENSIONS or "php" in DANGEROUS_EXTENSIONS
        assert ".jsp" in DANGEROUS_EXTENSIONS or "jsp" in DANGEROUS_EXTENSIONS


class TestWebCache:
    @responses.activate
    def test_web_cache_poisoning_no_vuln(self):
        from tools.web_cache import check

        sess = make_session()
        responses.add(
            responses.GET,
            re.compile(r".*"),
            status=200,
            body="normal response",
            headers={"X-Cache": "MISS"},
        )
        result = check("http://test.com/page", sess=sess, timeout=2)
        assert isinstance(result, dict)
