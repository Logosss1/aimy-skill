"""Tests for tools.orchestrator_engine.test_runner extracted helpers."""
from unittest import mock

from tools.orchestrator_engine import test_runner


class TestRunDetector:
    def test_unknown_vtype_returns_none(self):
        result = test_runner.run_detector(
            "nonexistent_detector", "http://x.test/", "id",
            sess=None, waf_name="", oob={}, effective_timeout=5.0,
        )
        assert result is None

    def test_wraps_vtype_into_result(self):
        with mock.patch(
            "tools.orchestrator_engine.test_runner._run_detector_by_name",
            return_value={"vulnerable": True},
        ):
            result = test_runner.run_detector(
                "xsscheck", "http://x.test/", "q",
                sess=None, waf_name="", oob={}, effective_timeout=5.0,
            )
        assert result is not None
        assert result["_vtype"] == "xsscheck"
        assert result["vulnerable"] is True

    def test_returns_none_on_exception(self):
        with mock.patch(
            "tools.orchestrator_engine.test_runner._run_detector_by_name",
            side_effect=RuntimeError("boom"),
        ):
            result = test_runner.run_detector(
                "xsscheck", "http://x.test/", "q",
                sess=None, waf_name="", oob={}, effective_timeout=5.0,
            )
        assert result is None

    def test_returns_none_on_non_dict_result(self):
        with mock.patch(
            "tools.orchestrator_engine.test_runner._run_detector_by_name",
            return_value="not a dict",
        ):
            result = test_runner.run_detector(
                "xsscheck", "http://x.test/", "q",
                sess=None, waf_name="", oob={}, effective_timeout=5.0,
            )
        assert result is None


class TestCrossVerify:
    def _make_oracle(self, verified=True, confidence=0.9):
        oracle = mock.Mock()
        oracle.verify.return_value = {"verified": verified, "confidence_score": confidence}
        return oracle

    def test_no_vuln_no_cross(self):
        oracle = self._make_oracle()
        first = {"vulnerable": False}
        with mock.patch(
            "tools.orchestrator_engine.test_runner._run_detector_by_name",
            return_value={"vulnerable": False},
        ):
            out = test_runner.cross_verify(
                "xsscheck", "http://x.test/", "q", "", {}, first,
                oracle=oracle, sess=None, timeout=5.0,
            )
        assert out["cross_verified"] == []
        assert out["confirmed"] is False
        assert out["cross_count"] == 0

    def test_vuln_confirmed(self):
        oracle = self._make_oracle(verified=True)
        first = {"vulnerable": True, "result": {"payload": "<script>"}}
        with mock.patch(
            "tools.orchestrator_engine.test_runner._run_detector_by_name",
            return_value={"vulnerable": True, "error": None},
        ):
            out = test_runner.cross_verify(
                "xsscheck", "http://x.test/", "q", "", {}, first,
                oracle=oracle, sess=None, timeout=5.0,
            )
        assert "xsscheck" in out["cross_verified"]
        assert out["confirmed"] is True
        assert out["cross_count"] == 1

    def test_oracle_unverified(self):
        oracle = self._make_oracle(verified=False)
        first = {"vulnerable": True, "result": {"payload": "<script>"}}
        with mock.patch(
            "tools.orchestrator_engine.test_runner._run_detector_by_name",
            return_value={"vulnerable": True},
        ):
            out = test_runner.cross_verify(
                "xsscheck", "http://x.test/", "q", "", {}, first,
                oracle=oracle, sess=None, timeout=5.0,
            )
        assert out["confirmed"] is False

    def test_error_in_r2_no_cross(self):
        oracle = self._make_oracle()
        first = {"vulnerable": True, "result": {"payload": "<script>"}}
        with mock.patch(
            "tools.orchestrator_engine.test_runner._run_detector_by_name",
            return_value={"error": "network timeout"},
        ):
            out = test_runner.cross_verify(
                "xsscheck", "http://x.test/", "q", "", {}, first,
                oracle=oracle, sess=None, timeout=5.0,
            )
        assert out["cross_verified"] == []
        assert out["confirmed"] is False


if __name__ == "__main__":
    import unittest
    unittest.main()
