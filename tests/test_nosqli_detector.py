import re
from urllib.parse import unquote_plus

import responses

from tools.nosqli_detector import check


def _url_of(request) -> str:
    return unquote_plus(request.url)


class TestNoSQLIDetector:
    @responses.activate
    def test_boolean_blind_true_false_differential(self):
        """真布尔盲注: TRUE / FALSE 条件产生不同且稳定的响应."""

        def cb(request):
            u = _url_of(request)
            if "'1'=='1'" in u:
                return (200, {}, "admin row leaked " + "x" * 100)
            if "'1'=='2'" in u:
                return (200, {}, "no rows")
            return (200, {}, "normal response")

        responses.add_callback(responses.GET, re.compile(r"http://test\.com/login.*"),
                               callback=cb)
        result = check("http://test.com/login", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "boolean"

    @responses.activate
    def test_sql_error_page_is_not_nosqli(self):
        """回归: 所有特殊字符 payload 返回同一个 SQL 错误页 => 不是 NoSQLi.

        这正是 /sqli_error 端点上出现过的误报: 长度差恒定, 真/假条件无差异.
        """

        def cb(request):
            u = _url_of(request)
            if u.endswith("id=1"):
                return (200, {}, "normal response")
            # 任何带引号的 payload 都触发同一个错误页 (恒定长度)
            return (200, {}, "SQL syntax error near ''' " + "e" * 42)

        responses.add_callback(responses.GET, re.compile(r"http://test\.com/login.*"),
                               callback=cb)
        result = check("http://test.com/login", "id")
        assert result["vulnerable"] is False

    @responses.activate
    def test_nosql_specific_error_string_is_detected(self):
        """NoSQL 专属错误串 (MongoError) 仍是强信号."""

        def cb(request):
            u = _url_of(request)
            if "'" in u:
                return (500, {}, "MongoError: bad query")
            return (200, {}, "normal response")

        responses.add_callback(responses.GET, re.compile(r"http://test\.com/login.*"),
                               callback=cb)
        result = check("http://test.com/login", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "error"

    @responses.activate
    def test_no_nosqli(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/login\?.*"),
            body="normal response",
            status=200,
        )
        result = check("http://test.com/login", "id")
        assert result["vulnerable"] is False

    @responses.activate
    def test_unstable_boolean_response_not_confirmed(self):
        """真/假响应不稳定 (每次不同) => 不确认, 避免误报."""
        counter = {"n": 0}

        def cb(request):
            counter["n"] += 1
            u = _url_of(request)
            if u.endswith("id=1"):
                return (200, {}, "normal response")
            return (200, {}, "varies-%d" % counter["n"])

        responses.add_callback(responses.GET, re.compile(r"http://test\.com/login.*"),
                               callback=cb)
        result = check("http://test.com/login", "id")
        assert result["vulnerable"] is False

class TestOperatorDifferential:
    def test_confirm_operator_blind_two_families(self, monkeypatch):
        from tools import nosqli_detector as nd

        def fake_sig(sess, url, param, payload, timeout):
            if "$ne" in payload or "$gt" in payload:
                return (200, 135)
            return (200, 1)

        monkeypatch.setattr(nd, "_resp_sig", fake_sig)
        ok, ev = nd._confirm_operator_blind(None, "http://t/x", "id", 5)
        assert ok is True
        assert len(ev) == 2

    def test_confirm_operator_blind_rejects_generic_diff(self, monkeypatch):
        from tools import nosqli_detector as nd

        def fake_sig(sess, url, param, payload, timeout):
            return (200, 500)

        monkeypatch.setattr(nd, "_resp_sig", fake_sig)
        ok, ev = nd._confirm_operator_blind(None, "http://t/x", "id", 5)
        assert ok is False
        assert ev == []

    def test_confirm_operator_blind_requires_baseline_control(self, monkeypatch):
        from tools import nosqli_detector as nd

        def fake_sig(sess, url, param, payload, timeout):
            if payload == "1":
                return (200, 1)
            if "$ne" in payload or "$gt" in payload:
                return (200, 135)
            return (403, 0)

        monkeypatch.setattr(nd, "_resp_sig", fake_sig)
        ok, ev = nd._confirm_operator_blind(None, "http://t/x", "id", 5)
        assert ok is False

    @responses.activate
    def test_operator_injection_via_get(self):
        def cb(request):
            u = _url_of(request)
            if "$ne" in u or "$gt" in u:
                return (200, {}, "x" * 135)
            return (200, {}, "x")

        responses.add_callback(responses.GET, re.compile(r"http://test\.com/api.*"),
                               callback=cb)
        result = check("http://test.com/api", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "operator"
