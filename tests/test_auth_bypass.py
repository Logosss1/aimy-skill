import responses

from tools.auth_bypass import check


class TestAuthBypass:
    @responses.activate
    def test_path_bypass_found(self):
        responses.add(
            responses.GET, 'http://test.com/admin',
            body='login page', status=401,
        )
        responses.add(
            responses.GET, 'http://test.com/ADMIN',
            body='admin content', status=200,
        )
        responses.add(
            responses.GET, re.compile(r'http://test\.com/.*'),
            body='not found', status=404,
        )
        import requests
        sess = requests.Session()
        result = check('http://test.com/admin', sess)
        assert result['vulnerable'] is True

    @responses.activate
    def test_header_injection_bypass(self):
        responses.add(
            responses.GET, 'http://test.com/admin',
            body='admin content', status=200,
            match=[responses.matchers.header_matcher({'X-Forwarded-For': '127.0.0.1'})],
        )
        import requests
        sess = requests.Session()
        result = check('http://test.com/admin', sess)
        assert result is not None

    @responses.activate
    def test_no_bypass(self):
        responses.add(
            responses.GET, re.compile(r'http://test\.com/.*'),
            body='login page', status=401,
        )
        import requests
        sess = requests.Session()
        result = check('http://test.com/admin', sess)
        assert result['vulnerable'] is False


class FakeResp:
    def __init__(self, status, body, url=""):
        self.status_code = status
        self.text = body
        self.content = body.encode()
        self.url = url
        self.headers = {}


class FakeSession:
    """Minimal session stand-in driven by a url->FakeResp handler."""

    def __init__(self, handler):
        self._handler = handler
        self.verify = False
        self.cookies = []

    def get(self, url, **kwargs):
        return self._handler(url)

    def post(self, url, **kwargs):
        return self._handler(url)

    def request(self, method, url, **kwargs):
        return self._handler(url)


class TestAuthBypassCatchall:
    def test_catchall_server_no_false_bypasses(self):
        """catch-all 200 服务器: 所有路径同 body => 无假绕过."""
        sess = FakeSession(lambda url: FakeResp(200, "ok", url))
        result = check("http://test.com/admin", sess)
        assert result["path_bypasses"] == []
        assert result["admin_endpoints"] == []
        assert result["vulnerable"] is False

    def test_real_bypass_on_catchall_server(self):
        """catch-all 服务器上真实例外: /ADMIN 返回不同 body => 仍报绕过."""
        def handler(url):
            if url.rstrip("/").endswith("/ADMIN"):
                return FakeResp(200, "real admin dashboard controls", url)
            return FakeResp(200, "ok", url)

        sess = FakeSession(handler)
        result = check("http://test.com/admin", sess)
        assert any("ADMIN" in b["bypass"] for b in result["path_bypasses"])

    def test_normal_404_server_unaffected(self):
        """正常 404 服务器: catch-all 探测返回 404, 不影响原有逻辑."""
        def handler(url):
            if url.rstrip("/").endswith("/ADMIN"):
                return FakeResp(200, "admin content", url)
            return FakeResp(404, "nope", url)

        sess = FakeSession(handler)
        result = check("http://test.com/admin", sess)
        assert any("ADMIN" in b["bypass"] for b in result["path_bypasses"])


import re
