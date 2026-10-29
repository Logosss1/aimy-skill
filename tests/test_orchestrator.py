import time
from unittest.mock import MagicMock, patch

import pytest

from tools.false_positive_filter import FalsePositiveFilter


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.elapsed = 0.1


def _sess():
    """Offline session double used by integration-style orchestrator tests."""
    s = MagicMock()
    s.get.return_value = MockResponse(200, "hello body")
    s.post.return_value = MockResponse(200, "hello body")
    s.request.return_value = MockResponse(200, "hello body")
    return s


class TestTestSinglePoint:
    """Test the _test_single_point method with confidence and FPF integration."""

    @pytest.fixture(autouse=True)
    def _cleanup_detectors(self):
        from tools.orchestrator import ALL_DETECTORS

        saved = ALL_DETECTORS.copy()
        yield
        ALL_DETECTORS.clear()
        ALL_DETECTORS.update(saved)

    def _make_orchestrator(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test")
        o._lock = __import__("threading").Lock()
        o.state["filtered_findings"] = []
        o._backtrack_findings = []
        o._chain_cache = {}
        o.profiler = MagicMock()
        return o

    def _register_test_detector(self, o, name="test_vuln", mock_det=None):
        """Register a mock detector function in ALL_DETECTORS."""
        from tools.orchestrator import ALL_DETECTORS

        if mock_det is None:

            def mock_det(url, param, sess, timeout, waf, oob):
                return self._detector()

        ALL_DETECTORS[name] = mock_det

    def _detector(self, vulnerable=True, confidence=0.8, votes=None, evidence=None):
        return {
            "vulnerable": vulnerable,
            "type": "test_vuln",
            "confidence_score": confidence,
            "confidence_votes": votes or [],
            "evidence": evidence or ["test evidence", "test evidence 2"],
        }

    def test_confidence_merging_detector_higher(self):
        """Native detector confidence is higher than oracle, so final = native."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.85)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.4,
                "confidence_votes": [],
                "evidence": ["oracle evidence", "oracle evidence 2"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 1
        assert result[0]["confidence_score"] == 0.85
        assert result[0]["detector_confidence"] == 0.85

    def test_confidence_merging_oracle_higher(self):
        """Oracle confidence is higher than native, so final = oracle."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.4)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.9,
                "confidence_votes": ["oob_callback:0.95"],
                "evidence": ["OOB callback", "OOB evidence"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 1
        assert result[0]["confidence_score"] == 0.9
        assert result[0]["detector_confidence"] == 0.4

    def test_false_positive_low_confidence_skipped(self):
        """Low confidence findings are filtered and stored in state."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.1,
                "confidence_votes": [],
                "evidence": ["weak signal"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0
        assert len(o.state["filtered_findings"]) == 1
        assert o.state["filtered_findings"][0]["filtered"] is True
        assert "low_confidence" in o.state["filtered_findings"][0].get("filter_reason", "")

    def test_high_confidence_passes_filter(self):
        """High confidence findings pass through FPF."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.85)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.85,
                "confidence_votes": ["bool_multi_confirmed:0.75"],
                "evidence": ["sqli: error", "time_delay: 3.2s"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 1
        assert result[0]["filtered"] is False
        assert len(o.state["filtered_findings"]) == 0

    def test_non_vulnerable_skipped(self):
        """Detector returning vulnerable=False generates no finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(vulnerable=False)

        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0

    def test_oracle_not_verified_skipped(self):
        """Oracle returning verified=False skips the finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": False,
                "confidence_score": 0.0,
                "confidence_votes": [],
                "evidence": [],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0

    def test_evidence_passed_through(self):
        """Evidence from detector reaches the finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(evidence=["sqli: error based", "sqli: time based"])

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.8,
                "confidence_votes": ["bool_diff:0.5"],
                "evidence": ["sqli: error based", "sqli: time based"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result[0]["evidence"]) >= 2

    def test_confidence_votes_passed_through(self):
        """Confidence votes from detector or oracle reach the finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(votes=["output_indicator:0.70"])

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.7,
                "confidence_votes": ["output_indicator:0.70"],
                "evidence": ["evidence 1", "evidence 2"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result[0]["confidence_votes"]) > 0

    def test_error_page_finding_filtered(self):
        """Finding with error page content gets filtered."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.8,
                "confidence_votes": [],
                "evidence": ["test"],
                "response_text": "<title>404 Not Found</title><h1>Error 404</h1>",
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0
        assert len(o.state["filtered_findings"]) == 1

    def test_backtrack_chain_skipped_for_filtered(self):
        """Chain backtracking is not called for filtered findings."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.1,
                "confidence_votes": [],
                "evidence": [],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value={"success": True})

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        o._maybe_backtrack_chain.assert_not_called()

    def test_backtrack_chain_called_for_unfiltered(self):
        """Chain backtracking is called for unfiltered high-confidence findings."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.85)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.85,
                "confidence_votes": ["bool_diff:0.5"],
                "evidence": ["sqli: error", "sqli: evidence 2"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "id"},
            ["test_vuln"],
        )

        o._maybe_backtrack_chain.assert_called_once()

    def test_timestamp_in_finding(self):
        """Finding includes a timestamp field."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)

        self._register_test_detector(o, "test_vuln", mock_det)
        before = time.time()

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.8,
                "confidence_votes": [],
                "evidence": ["test 1", "test 2"],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert before <= result[0]["timestamp"] <= time.time() + 1

    def test_vulnerable_field_overridden_by_fpf(self):
        """FPF sets vulnerable=False on filtered finding."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.1,
                "confidence_votes": [],
                "evidence": [],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0
        assert o.state["filtered_findings"][0]["vulnerable"] is False

    def test_cross_verify_called_when_vulnerable(self):
        """_cross_verify is invoked when detector finds vulnerable."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)

        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)
        cross_mock = MagicMock(side_effect=lambda *a, **k: a[5])
        o._cross_verify = cross_mock
        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.8,
                "confidence_votes": [],
                "evidence": [],
            }
        )
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        cross_mock.assert_called_once()

    def test_cross_verify_not_called_when_not_vulnerable(self):
        """_cross_verify is skipped when detector returns not vulnerable."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(vulnerable=False)

        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock()

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        o._cross_verify.assert_not_called()

    def test_detector_exception_handled(self):
        """Exception in detector is caught and logged, does not crash."""
        o = self._make_orchestrator()

        def mock_det(*args, **kwargs):
            raise ValueError("detector crash")

        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock()
        o.oracle = MagicMock()

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0

    def test_unknown_detector_skipped(self):
        """Unknown detector type in active_detectors is skipped."""
        o = self._make_orchestrator()
        o._budget_ok = MagicMock(return_value=True)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["nonexistent_detector"],
        )

        assert len(result) == 0

    def test_thread_lock_prevents_race(self):
        """Threading lock is acquired for shared state modifications."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.1,
                "confidence_votes": [],
                "evidence": [],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert o._lock.locked() is False

    def test_multiple_detectors_run(self):
        """Multiple detectors in active list each get called."""
        o = self._make_orchestrator()
        call_count = []

        def mock_det1(url, param, sess, timeout, waf, oob):
            call_count.append(1)
            return self._detector(vulnerable=False)

        def mock_det2(url, param, sess, timeout, waf, oob):
            call_count.append(1)
            return self._detector(vulnerable=False)

        def mock_det3(url, param, sess, timeout, waf, oob):
            call_count.append(1)
            return self._detector(vulnerable=False)

        self._register_test_detector(o, "test_vuln", mock_det1)
        self._register_test_detector(o, "test_vuln2", mock_det2)
        self._register_test_detector(o, "test_vuln3", mock_det3)

        o._budget_ok = MagicMock(return_value=True)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln", "test_vuln2", "test_vuln3"],
        )

        assert len(call_count) == 3

    def test_lock_initialized_in_init(self):
        """_lock is initialized in Orchestrator.__init__."""
        o = self._make_orchestrator()
        assert hasattr(o, "_lock")
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)

        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(
            return_value={
                "verified": True,
                "confidence_score": 0.1,
                "confidence_votes": [],
                "evidence": [],
            }
        )
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(o.state["filtered_findings"]) == 1

    def test_budget_exhausted_skips(self):
        """When budget is exhausted, no tests run."""
        o = self._make_orchestrator()
        o._budget_ok = MagicMock(return_value=False)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0


class TestOrchestratorIntegration:
    """Integration-level tests for the Orchestrator."""

    @patch("tools.orchestrator.fingerprint_target", return_value={})
    @patch("tools.orchestrator.enum_subdomains", return_value={})
    @patch("tools.orchestrator.fingerprint_tech", return_value={})
    @patch("tools.orchestrator.scan_ports", return_value={})
    @patch("tools.orchestrator.check_git_leak", return_value={})
    @patch("tools.orchestrator.fuzz_directories", return_value={"interesting": []})
    def test_phase_recon_runs(self, *mocks):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", sess=_sess(), time_budget=600)
        result = o.phase_recon()
        assert "target" in result
        assert result["target"] == "http://target.test"

    @patch("tools.orchestrator.crawler.crawl", return_value={"endpoints": {}, "parameters": []})
    @patch("tools.orchestrator.ALL_DETECTORS", {})
    def test_phase_detect_no_points(self, *mocks):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", sess=_sess(), time_budget=600)
        crawl_result = o.phase_crawl()
        o.state["phases"]["crawl"] = crawl_result
        o.state["phases"]["param_mine"] = {}
        # Run _select_detectors with empty state
        o.last_hypotheses = []

        with patch.object(o, "_run_kali_recon"):
            result = o.phase_detect()

        assert isinstance(result, dict)

    @patch("tools.orchestrator.build_attack_plan")
    def test_phase_attack_plan_empty(self, mock_plan):
        mock_plan.return_value = {"phases": [], "risk_score": 0}
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        o.state["phases"]["recon"] = {
            "technologies": {},
            "open_ports": {},
            "git_leak": {},
            "directories": {},
        }
        result = o.phase_attack_plan()
        assert "phases" in result

    def test_select_detectors_default_order(self):
        from tools.orchestrator import ALL_DETECTORS, DETECTOR_RISK_ORDER, Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        o.last_hypotheses = []
        result = o._select_detectors()
        assert len(result) == len(ALL_DETECTORS)
        assert DETECTOR_RISK_ORDER[result[0]] == min(DETECTOR_RISK_ORDER.values())

    @patch("tools.orchestrator.fingerprint_target", return_value={})
    @patch("tools.orchestrator.fingerprint_tech", return_value={})
    @patch("tools.orchestrator.scan_ports", return_value={})
    @patch("tools.orchestrator.check_git_leak", return_value={})
    @patch("tools.orchestrator.enum_subdomains", return_value={})
    @patch("tools.orchestrator.fuzz_directories", return_value={"interesting": []})
    def test_recon_stores_state(self, *mocks):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", sess=_sess(), time_budget=600)
        o.phase_recon()
        assert "recon" in o.state["phases"]

    def test_build_test_points_with_crawl_data(self):
        """Build test points from crawl data with one endpoint + param."""
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        o.state["phases"]["recon"] = {
            "technologies": {"technologies": [{"id": "php"}]},
            "open_ports": {},
            "git_leak": {},
            "directories": {},
        }
        o.state["phases"]["crawl"] = {
            "endpoints": {
                "/page.php": {
                    "url": "http://target.test/page.php",
                    "methods": ["GET"],
                    "params": ["id"],
                }
            },
            "parameters": ["id"],
            "js_api_endpoints": [],
        }
        o.state["phases"]["param_mine"] = {}
        points = o._build_test_points()
        assert len(points) > 0
        assert any("id" in p.get("param", "") for p in points)

    def test_budget_tracking(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        o._start_time = time.time() - 100
        remaining = o._budget_remaining()
        assert 495 < remaining <= 600

    def test_fingerprint_waf_cached_hit(self):
        """WAF cached in context_memory: 不再调 fingerprint_waf."""
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        o.context_memory.set("waf", "cloudflare", "test", 0.9)
        with patch("tools.orchestrator.waf_bypass.fingerprint_waf") as m:
            info = o._fingerprint_waf_cached()
        m.assert_not_called()
        assert info["name"] == "cloudflare"

    def test_fingerprint_waf_cached_miss(self):
        """WAF 未缓存: 调 fingerprint_waf 并写入 context_memory."""
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        # 清掉可能残留的缓存
        o.context_memory.delete("waf") if hasattr(o.context_memory, "delete") else None
        with patch(
            "tools.orchestrator.waf_bypass.fingerprint_waf", return_value={"name": "akamai"}
        ):
            info = o._fingerprint_waf_cached()
        assert info["name"] == "akamai"
        assert o.context_memory.get("waf") == "akamai"

    def test_phase_detect_bayes_no_findings_is_noop(self):
        """无 backtrack findings 时 Bayes 不做事."""
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        o._backtrack_findings = []
        # 不应抛异常也不应修改 last_hypotheses
        before = o.last_hypotheses
        o._phase_detect_bayes(active=[])
        assert o.last_hypotheses == before

    def test_phase_detect_semantic_empty_findings(self):
        """空 findings 不应崩."""
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        fake_sess = type(
            "S", (), {"get": staticmethod(lambda *a, **k: (_ for _ in ()).throw(Exception("no")))}
        )()
        o.sess = fake_sess
        o._phase_detect_semantic({})  # 不应抛

    def test_phase_detect_second_order_skips_low_confidence(self):
        """confidence_score < 0.5 的 finding 不做二阶验证."""
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", time_budget=600)
        findings = {
            "sqli|http://x/?id=1|id": {
                "type": "sqli",
                "url": "http://x/",
                "param": "id",
                "vulnerable": True,
                "confidence_score": 0.3,
            },
        }
        with patch.object(o.verifier, "verify") as m:
            o._phase_detect_second_order(findings)
        m.assert_not_called()


class TestSeedPointsFromEndpoints:
    """--endpoints 文件: 让 agent 喂入外部发现的端点/参数."""

    def test_url_with_param_line(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator(
            "http://target.test",
            endpoints=[
                "http://target.test/page id",
                "http://target.test/api/user uid",
            ],
        )
        pts = o._seed_points_from_endpoints(set())
        got = {(p["url"], p["param"]) for p in pts}
        assert ("http://target.test/page", "id") in got
        assert ("http://target.test/api/user", "uid") in got
        assert all(p["from_endpoints"] for p in pts)

    def test_url_with_query_line(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator(
            "http://target.test",
            endpoints=[
                "http://target.test/search?q=1&page=2",
            ],
        )
        pts = o._seed_points_from_endpoints(set())
        params = {p["param"] for p in pts}
        assert params == {"q", "page"}

    def test_comments_and_blank_lines_skipped(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator(
            "http://target.test",
            endpoints=[
                "",
                "   ",
                "# comment",
                "http://target.test/a id",
            ],
        )
        pts = o._seed_points_from_endpoints(set())
        assert len(pts) == 1
        assert pts[0]["param"] == "id"

    def test_skip_params_excluded(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator(
            "http://target.test",
            endpoints=[
                "http://target.test/page submit",
                "http://target.test/page id",
            ],
        )
        pts = o._seed_points_from_endpoints(set())
        params = {p["param"] for p in pts}
        assert "submit" not in params
        assert "id" in params

    def test_non_http_line_ignored(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", endpoints=["not-a-url id"])
        assert o._seed_points_from_endpoints(set()) == []

    def test_dedup_against_seen(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", endpoints=["http://target.test/a id"])
        seen = {"http://target.test/a|id|GET"}
        assert o._seed_points_from_endpoints(seen) == []

    def test_build_test_points_includes_endpoints(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test", endpoints=["http://target.test/x?q=1"])
        o.state["phases"]["crawl"] = {}
        o.state["phases"]["param_mine"] = {}
        o.state["phases"]["recon"] = {}
        o.last_hypotheses = []
        pts = o._build_test_points()
        assert any(p.get("from_endpoints") and p["param"] == "q" for p in pts)

    def test_no_endpoints_is_empty(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test")
        assert o.seed_endpoints == []
        assert o._seed_points_from_endpoints(set()) == []

    def test_endpoints_combined_with_target_query(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test/page?id=1", endpoints=["http://target.test/other?x=9"])
        o.state["phases"]["crawl"] = {}
        o.state["phases"]["param_mine"] = {}
        o.state["phases"]["recon"] = {}
        o.last_hypotheses = []
        pts = o._build_test_points()
        params = {p["param"] for p in pts}
        assert "id" in params  # from target URL
        assert "x" in params  # from endpoints file


class TestSeedPointsFromTarget:
    """种子 URL 自带的 query 参数必须成为测试点 (auto 最自然的用法)."""

    def test_seed_url_params_are_testable(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test/page?id=1&q=foo")
        seen = set()
        pts = o._seed_points_from_target(seen)
        params = {p["param"] for p in pts}
        assert params == {"id", "q"}
        assert all(p["url"] == "http://target.test/page" for p in pts)
        assert all(p["from_seed"] for p in pts)

    def test_base_target_strips_query(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test/page?id=1")
        assert o.target == "http://target.test/page?id=1"
        assert o.base_target == "http://target.test/page"

    def test_no_query_yields_no_seed_points(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test/page")
        assert o._seed_points_from_target(set()) == []

    def test_skip_params_excluded_from_seed(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test/page?submit=1&id=2")
        pts = o._seed_points_from_target(set())
        params = {p["param"] for p in pts}
        assert "submit" not in params
        assert "id" in params

    def test_seed_respects_seen_dedup(self):
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test/page?id=1")
        seen = {"http://target.test/page|id|GET"}
        assert o._seed_points_from_target(seen) == []

    def test_build_test_points_includes_seed(self):
        """_build_test_points 在无 crawl/dirfuzz 时也应产出种子点."""
        from tools.orchestrator import Orchestrator

        o = Orchestrator("http://target.test/page?id=1")
        o.state["phases"]["crawl"] = {}
        o.state["phases"]["param_mine"] = {}
        o.state["phases"]["recon"] = {}
        o.last_hypotheses = []
        points = o._build_test_points()
        assert any(p.get("from_seed") and p["param"] == "id" for p in points)


class TestReportHelpers:
    """Pure-function tests for the extracted report helpers."""

    def test_report_group_by_type_and_url(self):
        from tools.orchestrator import Orchestrator

        findings = {
            "k1": {"type": "sqli", "url": "http://x/a", "param": "id"},
            "k2": {"type": "sqli", "url": "http://x/b", "param": "id"},
            "k3": {"type": "xss", "url": "http://x/a", "param": "q"},
        }
        by_type, by_url = Orchestrator._report_group(findings)
        assert set(by_type.keys()) == {"sqli", "xss"}
        assert len(by_type["sqli"]) == 2
        assert by_url["http://x/a"] == ["sqli", "xss"]

    def test_report_summary_empty(self):
        from tools.orchestrator import Orchestrator

        summary = Orchestrator._report_summary({}, {}, {}, {}, {})
        assert summary["vulnerabilities"] == 0
        assert summary["critical"] is False
        assert summary["exploit_ready_details"] == []

    def test_report_summary_critical_via_exploit_ready(self):
        from tools.orchestrator import Orchestrator

        exploits = {"sqli|http://x|id": {"exploit_ready": True}}
        summary = Orchestrator._report_summary(
            findings={"k": {"type": "sqli", "url": "http://x/", "param": "id"}},
            by_type={"sqli": []},
            by_url={"http://x/": []},
            exploits=exploits,
            auth_data={},
        )
        assert summary["critical"] is True
        assert summary["exploit_ready_details"] == ["sqli|http://x|id"]

    def test_report_summary_critical_via_rce_flag(self):
        from tools.orchestrator import Orchestrator

        findings = {
            "k": {
                "type": "sqli",
                "url": "http://x/",
                "param": "id",
                "result": {"rce_available": True},
            },
        }
        summary = Orchestrator._report_summary(
            findings=findings,
            by_type={"sqli": []},
            by_url={"http://x/": []},
            exploits={},
            auth_data={},
        )
        assert summary["critical"] is True

    def test_report_summary_param_hits_format(self):
        from tools.orchestrator import Orchestrator

        findings = {
            "k": {"type": "sqli", "url": "http://x/", "param": "id"},
        }
        summary = Orchestrator._report_summary(
            findings=findings,
            by_type={},
            by_url={},
            exploits={},
            auth_data={},
        )
        assert summary["param_hits"] == ["http://x/?id [sqli]"]

    def test_report_recon_basic(self):
        from tools.orchestrator import Orchestrator

        recon = {
            "technologies": {"technologies": [{"name": "PHP"}, {"name": "Nginx"}]},
            "open_ports": {"open_ports": [{"port": 80}, {"port": 443}]},
            "git_leak": {"git_exposed": True, "sensitive_finds": [{}, {}]},
            "directories": {"interesting": ["/admin"]},
        }
        detection = {"test_points": 42}
        crawl_summary = {"pages_crawled": 10, "endpoints_found": 5, "is_spa": True}
        mine_data = {"host1": {"all_params": ["a", "b"]}, "host2": {"all_params": ["c"]}}
        waf_info = {"name": "cloudflare"}

        r = Orchestrator._report_recon(recon, detection, crawl_summary, mine_data, waf_info)
        assert r["technologies"] == ["PHP", "Nginx"]
        assert r["open_ports"] == [80, 443]
        assert r["git_exposed"] is True
        assert r["git_sensitive"] == 2
        assert r["directories"] == 1
        assert r["pages_crawled"] == 10
        assert r["params_mined"] == 3
        assert r["test_points"] == 42
        assert r["is_spa"] is True
        assert r["waf"] == "cloudflare"


class TestFalsePositiveFilter:
    """Verify FPF integration with orchestrator findings."""

    def test_fpf_filters_low_confidence(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.1,
            "evidence": ["weak test"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "low_confidence" in result["filter_reason"]

    def test_fpf_passes_high_confidence(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error", "time_delay: 3.2s"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is False

    def test_fpf_filters_insufficient_evidence(self):
        fpf = FalsePositiveFilter()
        fpf.set_threshold(min_evidence=3)
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "insufficient_evidence" in result["filter_reason"]

    def test_fpf_filters_error_page(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error"],
            "response_text": "<title>404 Not Found</title>",
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "error_page" in result["filter_reason"]

    def test_fpf_filter_sets_vulnerable_false(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.1,
            "evidence": ["test"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["vulnerable"] is False

    def test_fpf_not_vulnerable_not_filtered(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": False,
            "confidence_score": 0.0,
            "evidence": [],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is False

    def test_fpf_batch_filter(self):
        fpf = FalsePositiveFilter()
        results = [
            {
                "vulnerable": True,
                "confidence_score": 0.1,
                "evidence": ["test"],
                "timestamp": time.time(),
            },
            {
                "vulnerable": True,
                "confidence_score": 0.85,
                "evidence": ["a", "b"],
                "timestamp": time.time(),
            },
            {
                "vulnerable": True,
                "confidence_score": 0.9,
                "evidence": ["a", "b", "c"],
                "timestamp": time.time(),
            },
        ]
        out = fpf.filter(results)
        assert len(out) == 2

    def test_stale_data_filtered(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error"],
            "timestamp": time.time() - 7200,
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "stale_data" in result["filter_reason"]


class TestBenchmarkHelpers:
    """Test helper utilities used by orchestrator."""

    def test_skip_params_defined(self):
        from tools.orchestrator import SKIP_PARAMS

        assert "submit" in SKIP_PARAMS
        assert "button" in SKIP_PARAMS

    def test_detector_risk_order_has_all(self):
        from tools.orchestrator import ALL_DETECTORS, DETECTOR_RISK_ORDER

        for d in ALL_DETECTORS:
            assert d in DETECTOR_RISK_ORDER, "%s missing from DETECTOR_RISK_ORDER" % d

    def test_all_detectors_lambdas_are_callable(self):
        """Every entry in ALL_DETECTORS is a callable function."""
        from tools.orchestrator import ALL_DETECTORS

        for name, fn in ALL_DETECTORS.items():
            assert callable(fn), "%s entry is not callable" % name
