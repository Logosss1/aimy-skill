"""Tests for engine/contract.py - AI-Agent check() return shape validation."""
import unittest

from engine.contract import (
    CheckResult,
    check_return_shape,
    is_vulnerable,
)


class TestCheckResult:
    def test_default_is_safe(self):
        cr = CheckResult()
        assert cr.vulnerable is False
        assert cr.evidence == []
        assert cr.findings == []

    def test_from_dict_minimal(self):
        cr = CheckResult.from_dict({"vulnerable": True})
        assert cr.vulnerable is True
        assert cr.extras == {}

    def test_from_dict_preserves_unknown_keys_in_extras(self):
        cr = CheckResult.from_dict({
            "vulnerable": True,
            "type": "xss",
            "my_custom_field": [1, 2, 3],
        })
        assert cr.type == "xss"
        assert cr.extras == {"my_custom_field": [1, 2, 3]}

    def test_to_dict_strips_empty(self):
        cr = CheckResult(vulnerable=False)
        out = cr.to_dict()
        assert out == {"vulnerable": False}
        assert "evidence" not in out

    def test_to_dict_keeps_vulnerable_even_if_false(self):
        cr = CheckResult(vulnerable=False)
        assert cr.to_dict().get("vulnerable") is False

    def test_to_dict_merges_extras(self):
        cr = CheckResult(vulnerable=True, type="sqli",
                         extras={"dbms_hint": "mysql"})
        out = cr.to_dict()
        assert out["dbms_hint"] == "mysql"
        assert out["type"] == "sqli"

    def test_roundtrip(self):
        original = {"vulnerable": True, "type": "xss",
                    "evidence": ["<script>"], "score": 0.95}
        cr = CheckResult.from_dict(original)
        out = cr.to_dict()
        assert out["vulnerable"] is True
        assert out["type"] == "xss"
        assert out["evidence"] == ["<script>"]
        assert out["score"] == 0.95

    def test_validate_clean(self):
        cr = CheckResult(vulnerable=True, confidence="high",
                         confidence_score=0.9)
        assert cr.validate() == []

    def test_validate_warns_bad_confidence(self):
        cr = CheckResult(vulnerable=True, confidence="maybe")
        warnings = cr.validate()
        assert any("confidence" in w for w in warnings)

    def test_validate_warns_bad_score(self):
        cr = CheckResult(vulnerable=True, confidence_score=1.5)
        warnings = cr.validate()
        assert any("confidence_score" in w for w in warnings)

    def test_validate_warns_both_evidence_and_findings(self):
        cr = CheckResult(vulnerable=True,
                         evidence=["a"], findings=[{"x": 1}])
        warnings = cr.validate()
        assert any("evidence" in w and "findings" in w for w in warnings)


class TestCheckReturnShape:
    def test_none_returns_warning(self):
        warnings = check_return_shape(None)
        assert any("None" in w for w in warnings)

    def test_non_dict_returns_warning(self):
        warnings = check_return_shape("not a dict")
        assert any("Dict" in w for w in warnings)

    def test_clean_dict_no_warnings(self):
        warnings = check_return_shape({"vulnerable": True, "type": "xss"})
        assert warnings == []

    def test_strict_requires_vulnerable(self):
        warnings = check_return_shape({"type": "xss"}, strict=True)
        assert any("vulnerable" in w for w in warnings)


class TestIsVulnerable:
    def test_bool_true(self):
        assert is_vulnerable({"vulnerable": True}) is True

    def test_bool_false(self):
        assert is_vulnerable({"vulnerable": False}) is False

    def test_legacy_int_count(self):
        """兼容 unauth_scan 旧行为: int 计数 > 0 视为 vulnerable."""
        assert is_vulnerable({"vulnerable": 3}) is True
        assert is_vulnerable({"vulnerable": 0}) is False

    def test_missing_field(self):
        assert is_vulnerable({}) is False
        assert is_vulnerable(None) is False

    def test_garbage_value(self):
        assert is_vulnerable({"vulnerable": "yes"}) is False


class TestRealDetectorShapes:
    """真实 detector 的返回 shape 至少要通过契约."""

    def test_sql_injection_shape(self):
        from tools.sql_injection import check
        result = check("http://x.test/page", "id", timeout=2)
        warnings = check_return_shape(result)
        assert result["vulnerable"] is False
        assert warnings == []

    def test_leak_scanner_shape(self):
        from tools.leak_scanner import check
        result = check("http://x.test/", timeout=2)
        assert "vulnerable" in result
        assert isinstance(result["vulnerable"], bool)
        warnings = check_return_shape(result)
        assert warnings == []

    def test_weakpass_shape(self):
        from tools.weakpass import check
        result = check("http://x.test/login", max_attempts=0, timeout=2)
        assert "vulnerable" in result
        assert isinstance(result["vulnerable"], bool)

    def test_waf_bypass_shape(self):
        from tools.waf_bypass import check
        result = check("http://x.test/", timeout=2)
        assert "vulnerable" in result
        assert isinstance(result["vulnerable"], bool)


if __name__ == "__main__":
    unittest.main()
