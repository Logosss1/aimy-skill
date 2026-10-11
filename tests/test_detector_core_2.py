"""Offline coverage tests for tools.response_analyzer and tools.active_prober.

All HTTP I/O uses fake sessions; no sockets or real requests. Docstrings tagged
``DEFECT`` pin detection-capability bugs (file:line + one-line judgment).
"""

import pytest

from tools import active_prober
from tools.response_analyzer import ResponseAnalyzer


class ProberResp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = text.encode("utf-8")


class ProberSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, timeout=None, verify=None):
        self.calls.append(url)
        return self.handler(url)


class FakeBannerSock:
    def __init__(self, data=b""):
        self.data = data
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def settimeout(self, timeout):
        pass

    def sendall(self, payload):
        self.sent.append(payload)

    def recv(self, n):
        return self.data


class TestAnalyzeJson:
    def test_dict_root_fields_sensitive_pagination_endpoints(self):
        analyzer = ResponseAnalyzer()
        body = ('{"id": 1, "password": "s", "profile": {"email": "a@b.co"}, '
                '"items": [{"url": "/i/1", "user_id": 5}], "total": 10, '
                '"next": "/p?x=2"}')
        result = analyzer.analyze("http://t/api/users/42", 200,
                                  {"Content-Type": "application/json"}, body)
        paths = {f.path for f in result.fields}
        assert paths == {"$.id", "$.password", "$.profile", "$.profile.email",
                         "$.items", "$.items[].url", "$.items[].user_id",
                         "$.total", "$.next"}
        assert set(result.sensitive_fields) == {"$.id", "$.password",
                                                "$.profile.email", "$.items[].user_id"}
        assert result.pagination == {"field": "total", "value": 10}
        assert result.endpoints_linked == ["/p?x=2", "/i/1"]
        assert result.is_json is True
        assert result.is_error is False
        assert result.error_type == ""
        assert result.inferred_resource == "users"
        assert analyzer._cache["http://t/api/users/42"] is result

    def test_list_root_uses_first_item(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/items", 200,
                                  {"Content-Type": "application/json"},
                                  '[{"a": 1}, {"a": 2}]')
        assert result.pagination == {"type": "list", "count": 2}
        assert [f.path for f in result.fields] == ["$.a"]

    def test_empty_list_root(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/items", 200,
                                  {"Content-Type": "application/json"}, "[]")
        assert result.pagination == {"type": "list", "count": 0}
        assert result.fields == []
        assert result.data_structure == ["unknown"]

    def test_scalar_root(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/v", 200,
                                  {"Content-Type": "application/json"}, '"hello"')
        assert len(result.fields) == 1
        assert result.fields[0].name == "root"
        assert result.fields[0].value_type == "str"
        assert result.pagination is None

    def test_invalid_json_body_is_silently_ignored(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/bad", 200,
                                  {"Content-Type": "application/json"}, "{oops")
        assert result.fields == []
        assert result.sensitive_fields == []
        assert result.data_structure == {}

    def test_content_type_with_charset(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/a", 200,
                                  {"Content-Type": "application/json; charset=utf-8"},
                                  '{"a": 1}')
        assert result.is_json is True

    def test_uppercase_json_content_type_is_analyzed(self):
        """Content-Type values are matched case-insensitively, so 'Application/JSON'
        (legal per RFC) still triggers JSON field analysis."""
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/a", 200,
                                  {"Content-Type": "Application/JSON"}, '{"a": 1}')
        assert result.is_json is True
        assert result.content_type == "Application/JSON"
        assert [f.path for f in result.fields] == ["$.a"]
        assert result.data_structure == {"a": "number"}

    def test_lowercase_header_key_is_recognized(self):
        """Header keys are matched case-insensitively, so a 'content-type' key is
        honored and body analysis runs."""
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/a", 200,
                                  {"content-type": "application/json"}, '{"a": 1}')
        assert result.content_type == "application/json"
        assert result.is_json is True
        assert [f.path for f in result.fields] == ["$.a"]

    def test_empty_body_skips_json_analysis(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/a", 200,
                                  {"Content-Type": "application/json"}, "")
        assert result.fields == []


class TestAnalyzeHtml:
    def test_extracts_inputs_and_data_attributes(self):
        analyzer = ResponseAnalyzer()
        body = ('<form><input name="user"><input name=\'q\'>'
                '<div data-role="admin" data-x=""></div></form>')
        result = analyzer.analyze("http://t/form", 200,
                                  {"Content-Type": "text/html"}, body)
        paths = [f.path for f in result.fields]
        assert paths == ["form.input.user", "form.input.q", "data.role", "data.x"]
        assert result.fields[0].value_type == "html_input"
        assert result.fields[0].is_nullable is True
        assert result.fields[2].value_type == "data_attr"
        assert result.fields[2].sample_value == "admin"
        assert result.is_html is True

    def test_message_word_on_success_page_is_not_error(self):
        """Only error/exception/failure/warning markers set is_error on HTML bodies;
        a benign 'message:' page stays a success response."""
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/welcome", 200,
                                  {"Content-Type": "text/html"},
                                  "<div>message: welcome to the site</div>")
        assert result.is_error is False
        assert result.error_type == ""
        failure = analyzer.analyze("http://t/fail", 200,
                                   {"Content-Type": "text/html"},
                                   "<div>error: upstream timeout</div>")
        assert failure.is_error is True

    def test_html_without_inputs_has_no_fields(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze("http://t/plain", 200,
                                  {"Content-Type": "text/html"}, "<p>hello</p>")
        assert result.fields == []


class TestClassifyError:
    @pytest.mark.parametrize("status,body,expected", [
        (401, "", "unauthorized"),
        (403, "", "forbidden"),
        (404, "", "not_found"),
        (405, "", "method_not_allowed"),
        (500, "anything", "internal_error"),
        (502, "", "bad_gateway"),
        (429, "", "rate_limited"),
        (400, "SQL syntax error near x", "sql_error"),
        (400, "Traceback (most recent call last)", "traceback"),
        (400, "JS exception thrown", "exception"),
        (400, "plain failure", "http_400"),
        (200, "", ""),
    ])
    def test_classification(self, status, body, expected):
        assert ResponseAnalyzer._classify_error(status, body) == expected

    def test_500_body_features_win_over_status_code(self):
        """Body features are inspected before the status map, so SQL/traceback pages
        surface as sql_error/traceback even on a 500; a bare 500 stays internal_error."""
        assert ResponseAnalyzer._classify_error(500, "SQL syntax error: mysql_fetch") == (
            "sql_error")
        assert ResponseAnalyzer._classify_error(
            500, "Traceback (most recent call last):") == "traceback"
        assert ResponseAnalyzer._classify_error(500, "boom") == "internal_error"


class TestTypeOfAndSample:
    @pytest.mark.parametrize("value,expected", [
        (None, "null"),
        (True, "boolean"),
        (1, "integer"),
        (1.5, "float"),
        ("2024-01-01", "date"),
        ("user@example.com", "email"),
        ("x" * 101, "text(long)"),
        ([1, 2], "list[2]"),
        ({"a": 1}, "object[1]"),
        ((1, 2), "tuple"),
    ])
    def test_type_of(self, value, expected):
        assert ResponseAnalyzer()._type_of(value) == expected

    def test_datetime_is_typed_before_plain_date(self):
        """The datetime regex is checked first, so timestamps keep their precision tag
        while plain dates are still typed 'date'."""
        analyzer = ResponseAnalyzer()
        assert analyzer._type_of("2024-01-01T10:00:00") == "datetime"
        assert analyzer._type_of("2024-01-01T10:00:00Z") == "datetime"
        assert analyzer._type_of("2024-01-01") == "date"

    def test_sample_truncates(self):
        analyzer = ResponseAnalyzer()
        assert analyzer._sample(None) == "null"
        assert analyzer._sample("x" * 100) == "x" * 80 + "..."
        assert analyzer._sample(123) == "123"


class TestInferStructure:
    def test_all_value_kinds(self):
        analyzer = ResponseAnalyzer()
        data = {"a": 1, "b": True, "c": 1.5, "d": "s", "e": [], "f": [{"g": 2}]}
        assert analyzer._infer_structure(data) == {
            "a": "number", "b": "boolean", "c": "number", "d": "string",
            "e": ["unknown"], "f": [{"g": "number"}],
        }


class TestExtractFields:
    def test_depth_is_capped(self):
        analyzer = ResponseAnalyzer()
        data = {"a": {}}
        node = data["a"]
        for _ in range(7):
            node["n"] = {}
            node = node["n"]
        fields = analyzer._extract_fields(data, "$")
        assert len(fields) == 6
        assert fields[-1].path == "$.a.n.n.n.n.n"

    def test_nullable_and_collection_flags(self):
        analyzer = ResponseAnalyzer()
        fields = analyzer._extract_fields({"x": None, "l": [1, 2], "s": (1, 2)}, "$")
        by_name = {f.name: f for f in fields}
        assert by_name["x"].is_nullable is True
        assert by_name["x"].value_type == "null"
        assert by_name["l"].is_collection is True
        assert by_name["l"].value_type == "list[2]"
        assert by_name["s"].is_collection is True

    def test_non_dict_root_returns_no_fields(self):
        assert ResponseAnalyzer()._extract_fields("scalar", "$") == []


class TestPaginationAndEndpoints:
    def test_pagination_prefers_page_over_total(self):
        analyzer = ResponseAnalyzer()
        assert analyzer._detect_pagination({"total": 1, "page": 2}) == {
            "field": "page", "value": 2}
        assert analyzer._detect_pagination({}) is None

    def test_extract_endpoints_top_level_and_items(self):
        analyzer = ResponseAnalyzer()
        data = {"url": "http://x/next", "items": [{"href": "/a"}, {"id": "3"}, "junk"]}
        assert analyzer._extract_endpoints(data, "http://x/") == ["http://x/next", "/a"]


class TestInferResource:
    @pytest.mark.parametrize("url,expected", [
        ("http://t/api/users/42", "users"),
        ("http://t/api/users", "users"),
        ("http://t/", ""),
        ("http://t/12345678", ""),
    ])
    def test_resource_inference(self, url, expected):
        assert ResponseAnalyzer._infer_resource(url) == expected

    def test_id_regex_char_class_malformed_defect(self):
        """DEFECT tools/response_analyzer.py:286: the class [\\d{8}\\-] matches literal
        braces/'8'/hyphen instead of 8-digit ids, so hyphenated values like '8-8' are
        treated as opaque ids and the real resource segment is used instead."""
        assert ResponseAnalyzer._infer_resource("http://t/by-id/8-8") == "by-id"
        assert ResponseAnalyzer._infer_resource("http://t/by-id/8") == "by-id"


class TestSelectAndExecuteProbe:
    def test_banner_only_techs_excluded_from_url_probes(self):
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        tasks = prober._select_probes_from_url("http://t.test")
        assert "nginx" in tasks
        assert "openssh" not in tasks
        assert "mysql" not in tasks
        assert "redis" not in tasks
        assert all(p.get("path") for probes in tasks.values() for p in probes)
        assert any(p.get("hash") for p in tasks["wordpress"])

    def test_header_probe_exact_version(self):
        def handler(url):
            return ProberResp(200, "", {"Server": "nginx/1.25.3"})

        prober = active_prober.ActiveProber(ProberSession(handler))
        result = prober._execute_probe("http://t.test", "nginx",
                                       active_prober.TECH_PROBES["nginx"][0])
        assert result.version == "1.25.3"
        assert result.confidence == 0.85
        assert result.method == "header"
        assert result.evidence == "Server: nginx/1.25.3"
        assert result.exact_match is True
        assert result.cve_hits == []

    def test_header_probe_presence_without_version(self):
        def handler(url):
            return ProberResp(200, "", {"X-Powered-By": "ASP.NET"})

        prober = active_prober.ActiveProber(ProberSession(handler))
        result = prober._execute_probe("http://t.test", "iis",
                                       active_prober.TECH_PROBES["iis"][1])
        assert result.version == "present"
        assert result.confidence == 0.60
        assert result.exact_match is False

    def test_body_probe_reads_body_regex_and_matches(self):
        """Body probes store their regex under 'body'; _execute_probe reads that key
        (no KeyError) and returns the captured version."""
        prober = active_prober.ActiveProber(
            ProberSession(lambda url: ProberResp(200, "Drupal 7.58, 2018-03-28")))
        probe = active_prober.TECH_PROBES["drupal"][0]
        assert "body" in probe and "regex" not in probe
        result = prober._execute_probe("http://t.test", "drupal", probe)
        assert result.version == "7.58"
        assert result.method == "body"
        assert result.evidence == "body match: Drupal 7.58,"
        assert result.confidence == 0.85
        assert result.exact_match is True
        assert result.cve_hits == []

    def test_body_probe_success_path_only_with_explicit_regex_key(self):
        """A body probe carrying an explicit 'body' regex yields the captured version;
        extra keys on the probe do not interfere with the match."""
        def handler(url):
            return ProberResp(200, "Drupal 7.58, 2018-03-28")

        prober = active_prober.ActiveProber(ProberSession(handler))
        probe = {"path": "/CHANGELOG.txt", "body": r"Drupal ([\d.]+),",
                 "regex": r"Drupal ([\d.]+),"}
        result = prober._execute_probe("http://t.test", "drupal", probe)
        assert result.version == "7.58"
        assert result.method == "body"
        assert result.evidence == "body match: Drupal 7.58,"

    def test_hash_match_path_reachable_only_when_stub_patched(self, monkeypatch):
        """_match_version_hash() is a stub, so hash_match never fires in production;
        patching it shows the surrounding code works once the stub is implemented."""
        prober = active_prober.ActiveProber(
            ProberSession(lambda url: ProberResp(200, "css-content")))
        monkeypatch.setattr(prober, "_match_version_hash", lambda tech, digest: "6.4.1")
        probe = [p for p in active_prober.TECH_PROBES["wordpress"] if p.get("hash")][0]
        result = prober._execute_probe("http://t.test", "wordpress", probe)
        assert result.version == "6.4.1"
        assert result.method == "hash_match"
        assert result.evidence.startswith("hash:")

    def test_error_page_is_not_fingerprinted(self):
        """probe responses with status >= 400 return zero confidence, so an error page
        echoing a banner string cannot fake a version hit."""
        def handler(url):
            return ProberResp(404, "not found", {"Server": "nginx/1.25.3"})

        prober = active_prober.ActiveProber(ProberSession(handler))
        result = prober._execute_probe("http://t.test", "nginx",
                                       active_prober.TECH_PROBES["nginx"][0])
        assert result.version is None
        assert result.confidence == 0.0
        assert result.method == ""
        assert result.exact_match is False
        for status in (400, 404, 500, 503):
            prober.sess = ProberSession(
                lambda url, status=status: ProberResp(
                    status, "not found", {"Server": "nginx/1.25.3"}))
            assert prober._execute_probe(
                "http://t.test", "nginx",
                active_prober.TECH_PROBES["nginx"][0]).confidence == 0.0

    def test_hash_probe_never_matches_defect(self):
        """DEFECT tools/active_prober.py:254-255: _match_version_hash() is a stub returning
        None, so every hash-based probe (e.g. WordPress colors.min.css) is dead code and
        that detection route can never fingerprint a version."""
        prober = active_prober.ActiveProber(
            ProberSession(lambda url: ProberResp(200, "css-content")))
        probe = [p for p in active_prober.TECH_PROBES["wordpress"] if p.get("hash")][0]
        assert prober._execute_probe("http://t.test", "wordpress", probe).confidence == 0.0
        assert prober._match_version_hash("wordpress", "deadbeef") is None

    def test_session_exception_returns_zero_confidence(self):
        def handler(url):
            raise RuntimeError("connection reset")

        prober = active_prober.ActiveProber(ProberSession(handler))
        result = prober._execute_probe("http://t.test", "nginx",
                                       active_prober.TECH_PROBES["nginx"][0])
        assert result.confidence == 0.0
        assert result.tech == "nginx"

    def test_probe_url_is_base_plus_path(self):
        session = ProberSession(lambda url: ProberResp(404, "x"))
        prober = active_prober.ActiveProber(session)
        prober._execute_probe("http://t.test/", "nginx",
                              active_prober.TECH_PROBES["nginx"][0])
        assert session.calls == ["http://t.test/"]


class TestProbeTarget:
    def test_body_and_header_probes_both_fingerprint(self):
        """Body-based detection works: the WordPress readme probe yields its version
        alongside the nginx header hit, with no swallowed KeyError."""
        session = ProberSession(lambda url: (
            ProberResp(200, "WordPress 5.8.1") if url.endswith("/readme.html")
            else ProberResp(200, "", {"Server": "nginx/1.25.3"})
            if url.rstrip("/").endswith("t.test") else ProberResp(404, "not found")))
        prober = active_prober.ActiveProber(session)
        results = prober.probe_target("http://t.test", [])
        assert set(results) == {"nginx", "wordpress"}
        assert results["wordpress"].version == "5.8.1"
        assert results["wordpress"].method == "body"
        assert results["wordpress"].confidence == 0.85
        assert results["wordpress"].cve_hits == ["CVE-2021-29447"]
        assert results["nginx"].confidence == 0.85
        assert "http://t.test/readme.html" in session.calls

    def test_later_higher_confidence_probe_replaces_present(self, monkeypatch):
        def handler(url):
            if url.endswith("/v"):
                return ProberResp(200, "", {"Server": "Widget/2.0"})
            return ProberResp(200, "", {"Server": "Widget"})

        prober = active_prober.ActiveProber(ProberSession(handler))
        probes = {
            "fake": [
                {"path": "/", "header": "server", "regex": r"Widget(?:/([\d.]+))?"},
                {"path": "/v", "header": "server", "regex": r"Widget/([\d.]+)"},
            ],
        }
        monkeypatch.setattr(prober, "_select_probes_from_url", lambda url: probes)
        results = prober.probe_target("http://t.test", [])
        assert results["fake"].version == "2.0"
        assert results["fake"].method == "header"
        assert results["fake"].confidence == 0.85

    def test_open_port_banner_dispatch_fingerprints_services(self, monkeypatch):
        """SSH/Redis/MySQL ports are dispatched to _probe_banner, which parses their
        banners and assigns the result per tech; 443 is not probed."""
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        monkeypatch.setattr(prober, "_select_probes_from_url", lambda url: {})
        socks = {
            22: FakeBannerSock(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"),
            6379: FakeBannerSock(b"$7\r\nNOAUTH Authentication required.\r\n"),
            3306: FakeBannerSock(b"\x0a5.7.44\x00123\x00mysql_native_password\x00"),
        }
        attempted = []

        def fake_create_connection(address, timeout=None):
            attempted.append(address)
            return socks[address[1]]

        monkeypatch.setattr(active_prober.socket, "create_connection",
                            fake_create_connection)
        results = prober.probe_target("http://t.test:8080/app", [
            {"port": 22, "service": "ssh"},
            {"port": 6379, "service": "redis"},
            {"port": 3306, "service": "mysql"},
            {"port": 443, "service": "https"},
        ])
        assert attempted == [("t.test", 22), ("t.test", 6379), ("t.test", 3306)]
        assert set(results) == {"openssh", "redis", "mysql"}
        assert results["openssh"].version == "8.9"
        assert results["openssh"].method == "banner"
        assert results["openssh"].confidence == 0.85
        assert results["openssh"].evidence.startswith("SSH-2.0-OpenSSH_8.9p1")
        assert results["redis"].version == "present"
        assert results["redis"].confidence == 0.60
        assert socks[6379].sent == [b"INFO\r\n"]
        assert results["mysql"].version == "present"
        assert results["mysql"].confidence == 0.60

    def test_banner_dispatch_assigns_results_only_when_stub_returns_value(self, monkeypatch):
        """probe_target stores whatever _probe_banner returns for each banner port."""
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        monkeypatch.setattr(prober, "_select_probes_from_url", lambda url: {})
        monkeypatch.setattr(prober, "_probe_banner", lambda host, port, tech: (
            active_prober.ProbeResult(tech=tech, version="8.9p1", confidence=0.85)))
        results = prober.probe_target("http://t.test", [
            {"port": 22, "service": "ssh"},
            {"port": 6379, "service": "redis"},
            {"port": 3306, "service": "mysql"},
        ])
        assert set(results) == {"openssh", "redis", "mysql"}
        assert results["openssh"].version == "8.9p1"

    def test_probe_banner_skips_non_banner_probes(self):
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        assert prober._probe_banner("127.0.0.1", 80, "nginx") is None

    def test_probe_banner_parses_ssh_and_redis_banners(self, monkeypatch):
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        ssh_sock = FakeBannerSock(b"SSH-2.0-OpenSSH_8.9p1 Debian-10+deb10u2\r\n")
        redis_sock = FakeBannerSock(b"$7\r\nNOAUTH Authentication required.\r\n")
        mysql_sock = FakeBannerSock(b"\x0a5.7.44\x00123\x00mysql_native_password\x00")
        socks = {22: ssh_sock, 6379: redis_sock, 3306: mysql_sock}

        def fake_create_connection(address, timeout=None):
            return socks[address[1]]

        monkeypatch.setattr(active_prober.socket, "create_connection",
                            fake_create_connection)
        ssh = prober._probe_banner("127.0.0.1", 22, "openssh")
        assert ssh.version == "8.9"
        assert ssh.confidence == 0.85
        assert ssh.method == "banner"
        assert ssh.evidence == "SSH-2.0-OpenSSH_8.9p1 Debian-10+deb10u2"
        assert ssh.exact_match is True
        redis = prober._probe_banner("127.0.0.1", 6379, "redis")
        assert redis.version == "present"
        assert redis.confidence == 0.60
        assert redis.method == "banner"
        assert redis_sock.sent == [b"INFO\r\n"]
        mysql = prober._probe_banner("127.0.0.1", 3306, "mysql")
        assert mysql.version == "present"
        assert mysql.confidence == 0.60

        def refused(address, timeout=None):
            raise OSError("connection refused")

        monkeypatch.setattr(active_prober.socket, "create_connection", refused)
        assert prober._probe_banner("127.0.0.1", 22, "openssh") is None

    def test_target_without_scheme_uses_raw_host(self, monkeypatch):
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        monkeypatch.setattr(prober, "_select_probes_from_url", lambda url: {})
        calls = []
        monkeypatch.setattr(prober, "_probe_banner",
                            lambda host, port, tech: calls.append((host, port, tech)))
        prober.probe_target("t.test", [{"port": 22, "service": "ssh"}])
        assert calls == [("t.test", 22, "openssh")]

    def test_unexpected_probe_exception_is_swallowed_defect(self):
        """DEFECT tools/active_prober.py:165-166: every probe exception is swallowed with
        'except Exception: pass', so a broken parser silently drops detection with no
        signal in the result."""

        class BadHeaders:
            def items(self):
                raise RuntimeError("malformed headers")

        resp = ProberResp(200, "x")
        resp.headers = BadHeaders()
        prober = active_prober.ActiveProber(ProberSession(lambda url: resp))
        assert prober.probe_target("http://t.test", []) == {}


class TestMatchCves:
    @pytest.mark.parametrize("tech,version,expected", [
        ("spring", "5.3.16", ["CVE-2022-22965"]),
        ("spring", "5.3.10", ["CVE-2022-22965", "CVE-2022-22963"]),
        ("tomcat", "9.0.31", []),
        ("jenkins", "2.500", []),
        ("unknown", "1.0", []),
        ("spring", "present", []),
        ("spring", "abc", []),
    ])
    def test_cve_matching(self, tech, version, expected):
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        assert prober._match_cves(tech, version) == expected

    def test_inclusive_upper_bound_flags_patched_releases_defect(self):
        """DEFECT tools/active_prober.py:287-296: range checks treat the upper bound as
        inclusive, so already-patched versions (Spring 5.3.17, Tomcat 9.0.30) still emit
        Spring4Shell/Ghostcat CVEs (false-positive vuln report)."""
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        assert prober._match_cves("spring", "5.3.17") == ["CVE-2022-22965"]
        assert prober._match_cves("tomcat", "9.0.30") == ["CVE-2020-1938"]
        assert prober._match_cves("jenkins", "2.440") == ["CVE-2024-23897"]


class TestVerInRange:
    @pytest.mark.parametrize("version,low,high,expected", [
        ("5.3.16", "5.3.0", "5.3.15", False),
        ("5.3.10", "5.3.0", "5.3.15", True),
        ("5.3.20", "5.3.0", None, True),
        ("5.3.0", "5.3.0", None, True),
        ("2.9.9", "3.0", None, False),
        ("9.0.0", "9.0.0", "9.0.30", True),
        ("9.0.31", "9.0.0", "9.0.30", False),
        ("5.4", "5.3.0", "5.3.15", False),
        ("5.3", None, "5.3.17", True),
        ("1.2.3.4", "1.2.3", "1.2.4", True),
        ("1.2.3", "x.y", None, True),
        ("1.2.3", None, "x", True),
        ("bad", "1.0", None, False),
        (None, "1.0", None, False),
    ])
    def test_range_matrix(self, version, low, high, expected):
        prober = active_prober.ActiveProber(ProberSession(lambda url: ProberResp()))
        assert prober._ver_in_range(version, low, high) is expected


class TestProbeResultDefaults:
    def test_defaults(self):
        result = active_prober.ProbeResult(tech="nginx")
        assert result.version is None
        assert result.confidence == 0.0
        assert result.method == ""
        assert result.evidence == ""
        assert result.cve_hits == []
        assert result.exact_match is False
