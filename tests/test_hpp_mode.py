import responses

from tools import hpp
from tools.mode import _is_low_value, enrich_result, filter_vulnerabilities, show_banner
from tools.settings import settings


class TestHPPDetector:
    @responses.activate
    def test_hpp_not_polluted(self):
        from tools._session import make_session

        sess = make_session()
        responses.add(
            responses.GET, "http://test.com/page?q=1", status=200, body="same response content"
        )
        responses.add(
            responses.GET, "http://test.com/page?q=1&q=2", status=200, body="same response content"
        )
        result = hpp.check("http://test.com/page", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is False
        assert result["findings"] == []

    @responses.activate
    def test_hpp_polluted(self):
        from tools._session import make_session

        sess = make_session()
        responses.add(responses.GET, "http://test.com/page?q=1", status=200, body="response with 1")
        responses.add(
            responses.GET, "http://test.com/page?q=1&q=2", status=200, body="response with 2"
        )
        result = hpp.check("http://test.com/page", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is True
        assert result["parameter_pollution"] is True
        assert len(result["findings"]) == 1
        assert result["findings"][0]["type"] == "hpp"

    @responses.activate
    def test_hpp_url_prefix_fix(self):
        from tools._session import make_session

        sess = make_session()
        responses.add(responses.GET, "http://test.com/page?q=1", status=200, body="same")
        responses.add(responses.GET, "http://test.com/page?q=1&q=2", status=200, body="same")
        result = hpp.check("test.com/page", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_hpp_default_session(self):
        responses.add(responses.GET, "http://test.com/page?q=1", status=200, body="same")
        responses.add(responses.GET, "http://test.com/page?q=1&q=2", status=200, body="same")
        result = hpp.check("http://test.com/page", "q", timeout=2)
        assert result["vulnerable"] is False

    @responses.activate
    def test_hpp_network_error(self):
        from tools._session import make_session

        sess = make_session()
        responses.add(responses.GET, "http://test.com/page?q=1", body=ConnectionError("failed"))
        result = hpp.check("http://test.com/page", "q", sess=sess, timeout=2)
        assert result["vulnerable"] is False

    def test_hpp_finding_details(self):
        result = {
            "vulnerable": True,
            "findings": [
                {
                    "type": "hpp",
                    "severity": "low",
                    "confidence": 0.8,
                    "single_response_length": 200,
                    "polluted_response_length": 250,
                }
            ],
        }
        assert result["findings"][0]["confidence"] == 0.8


class TestModeSelector:
    def setup_method(self):
        self._original_mode = settings.mode

    def teardown_method(self):
        settings.mode = self._original_mode

    def test_show_banner_rookie(self):
        settings.mode = "rookie"
        import io
        import sys

        old_stderr = sys.stderr
        sys.stderr = captured = io.StringIO()
        try:
            show_banner()
        finally:
            sys.stderr = old_stderr
        output = captured.getvalue()
        assert "Rookie" in output or "菜鸟" in output

    def test_show_banner_veteran(self):
        settings.mode = "veteran"
        import io
        import sys

        old_stderr = sys.stderr
        sys.stderr = captured = io.StringIO()
        try:
            show_banner()
        finally:
            sys.stderr = old_stderr
        output = captured.getvalue()
        assert "Veteran" in output or "老鸟" in output

    def test_show_banner_default(self):
        settings.mode = "unknown_mode"
        import io
        import sys

        old_stderr = sys.stderr
        sys.stderr = captured = io.StringIO()
        try:
            show_banner()
        finally:
            sys.stderr = old_stderr
        output = captured.getvalue()
        assert "Rookie" in output or "菜鸟" in output

    def test_is_low_value_reflected_xss(self):
        assert _is_low_value({"type": "reflected_xss"}) is True

    def test_is_low_value_open_redirect(self):
        assert _is_low_value({"type": "open_redirect"}) is True

    def test_is_low_value_info_disclosure(self):
        assert _is_low_value({"severity": "info_disclosure"}) is True

    def test_is_low_value_high_risk(self):
        result = {"type": "sqli", "risk": "critical"}
        assert _is_low_value(result) is False

    def test_is_low_value_not_dict(self):
        assert _is_low_value("string_result") is False

    def test_is_low_value_no_signal(self):
        assert _is_low_value({}) is False

    def test_is_low_value_risk_field(self):
        assert _is_low_value({"risk": "low"}) is True
        assert _is_low_value({"risk": "info"}) is True

    def test_is_low_value_lowercase_type(self):
        assert _is_low_value({"type": "REFLECTED_XSS"}) is True

    def test_filter_veteran_removes_low_value(self):
        settings.mode = "veteran"
        results = [
            {"type": "sqli", "risk": "critical"},
            {"type": "reflected_xss"},
            {"type": "open_redirect"},
        ]
        filtered = filter_vulnerabilities(results)
        assert len(filtered) == 1
        assert filtered[0]["type"] == "sqli"

    def test_filter_rookie_keeps_all(self):
        settings.mode = "rookie"
        results = [
            {"type": "sqli", "risk": "critical"},
            {"type": "reflected_xss"},
        ]
        filtered = filter_vulnerabilities(results)
        assert len(filtered) == 2

    def test_filter_non_list_passthrough(self):
        settings.mode = "veteran"
        result = {"type": "sqli"}
        assert filter_vulnerabilities(result) == result

    def test_enrich_result_rookie_sql_injection(self):
        settings.mode = "rookie"
        result = {"type": "sql_injection", "vulnerable": True}
        enriched = enrich_result(result)
        assert "_explanation" in enriched
        assert "SQL" in enriched["_explanation"]

    def test_enrich_result_rookie_xss(self):
        settings.mode = "rookie"
        result = {"type": "xss_reflected", "vulnerable": True}
        enriched = enrich_result(result)
        assert "_explanation" in enriched

    def test_enrich_result_veteran(self):
        settings.mode = "veteran"
        result = {"type": "sql_injection", "vulnerable": True}
        enriched = enrich_result(result)
        assert "_explanation" not in enriched

    def test_enrich_result_unknown_type(self):
        settings.mode = "rookie"
        result = {"type": "unknown_vuln", "vulnerable": True}
        enriched = enrich_result(result)
        assert "_explanation" not in enriched

    def test_enrich_result_non_dict(self):
        settings.mode = "rookie"
        result = "string result"
        assert enrich_result(result) == "string result"

    def test_enrich_result_non_dict_type(self):
        settings.mode = "rookie"
        result = ["list", "of", "strings"]
        assert enrich_result(result) == ["list", "of", "strings"]
