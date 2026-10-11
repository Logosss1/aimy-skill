"""High-coverage tests for tools/orchestrator.py (fully mocked, offline, fast).

Only adds tests; does not modify source. All HTTP traffic goes through a
MagicMock session. Heavy collaborators (reasoner, oracle, chains, C2, Kali)
are patched per-test so nothing touches the network or the real filesystem.
"""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tools.orchestrator import (
    _PIVOT_HANDLERS,
    SIGNATURE_PLACEHOLDER,
    Orchestrator,
)


def _resp(status=200, text="hello body", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers if headers is not None else {"content-type": "text/html"}
    return r


def _sess():
    s = MagicMock()
    s.get.return_value = _resp()
    return s


def _orch(target="http://target.test", **kw):
    o = Orchestrator(target, sess=_sess(), **kw)
    o.oob_server = MagicMock()
    o.context_memory = MagicMock()
    o.vuln_ctx = MagicMock()
    o.oracle = MagicMock()
    o.profiler = MagicMock()
    return o


class _Hyp:
    """Lightweight hypothesis stub with explicit attributes."""

    def __init__(self, priority=0, confidence=0.8, vuln_type="sqli",
                 evidence=None, suggested_chain="", detail=None):
        self.priority = priority
        self.confidence = confidence
        self.vuln_type = vuln_type
        self.evidence = evidence if evidence is not None else ["ev-1"]
        self.suggested_chain = suggested_chain
        self.detail = detail if detail is not None else {}

    def to_dict(self):
        return {"vuln_type": self.vuln_type, "priority": self.priority}


class TestInitVariants:
    def test_turbo_adjusts_limits_and_budget(self):
        o = _orch(turbo=True)
        assert o.threads == 60
        assert o.max_pages == 100
        assert o.max_depth == 4
        assert o.time_budget == 180.0

    def test_high_value_budget(self):
        o = _orch(high_value=True)
        assert o.time_budget == 300.0

    def test_default_budget(self):
        o = _orch()
        assert o.time_budget == 600.0

    def test_sess_none_builds_session(self):
        with patch("tools.orchestrator.build_session", return_value=MagicMock()) as m:
            o = Orchestrator("http://target.test")
        m.assert_called_once()
        assert o.sess is m.return_value

    def test_opsec_wraps_session(self):
        wrapped = MagicMock()
        with patch("tools.opsec_session.opsec_session", return_value=wrapped) as m:
            o = Orchestrator("http://target.test", sess=_sess(), opsec=True)
        m.assert_called_once()
        assert o.sess is wrapped


class TestSeedPoints:
    def test_seed_from_url_query(self):
        o = _orch("http://target.test/page?id=1&q=foo")
        seen = set()
        pts = o._seed_points_from_target(seen)
        assert {p["param"] for p in pts} == {"id", "q"}
        assert all(p["url"] == "http://target.test/page" for p in pts)
        assert all(p.get("from_seed") for p in pts)
        assert "http://target.test/page|id|GET" in seen

    def test_seed_skips_skip_params_and_blank_query(self):
        o = _orch("http://target.test/page?submit=1&id=")
        params = {p["param"] for p in o._seed_points_from_target(set())}
        assert "submit" not in params
        assert "id" in params

    def test_seed_no_query(self):
        o = _orch("http://target.test/page")
        assert o._seed_points_from_target(set()) == []

    def test_endpoints_url_with_param(self):
        o = _orch(endpoints=["http://t.test/page?a=1 id", "notaurl id"])
        seen = set()
        pts = o._seed_points_from_endpoints(seen)
        assert pts[0]["url"] == "http://t.test/page"
        assert pts[0]["param"] == "id"
        assert pts[0]["from_endpoints"] is True
        assert o._seed_points_from_endpoints(seen) == []

    def test_endpoints_query_line_and_dedup(self):
        o = _orch(endpoints=["http://t.test/s?q=1", "# comment", "", "http://t.test/s?q=2"])
        seen = set()
        pts = o._seed_points_from_endpoints(seen)
        assert len(pts) == 1
        assert pts[0]["param"] == "q"
        assert o._seed_points_from_endpoints(seen) == []

    def test_endpoints_skip_param(self):
        o = _orch(endpoints=["http://t.test/s submit"])
        assert o._seed_points_from_endpoints(set()) == []


class TestBuildTestPoints:
    def test_full_assembly(self):
        o = _orch("http://target.test?id=1")
        o.state["phases"]["crawl"] = {
            "endpoints": {
                "/a": {"url": "http://target.test/a", "params": ["id", "submit"]},
            },
            "parameters": ["q"],
            "js_api_endpoints": ["/api/one", "http://other.test/api/two"],
        }
        o.state["phases"]["param_mine"] = {
            "/m": {
                "all_params": ["p1"],
                "get_params": [
                    {"param": "g1", "status": 200},
                    {"param": "g404", "status": 404},
                    {"param": "g0", "status": 0},
                    {"param": "g400", "status": 400},
                    {"param": "submit", "status": 200},
                    {"param": 5, "status": 200},
                    "notadict",
                ],
                "post_params": [
                    {"param": "p_ok", "status": 200},
                    {"param": "p_bad", "status": 404},
                    {"param": "submit", "status": 200},
                ],
            },
            "/strkey": "not-a-dict",
        }
        o.state["phases"]["recon"] = {
            "directories": {"interesting": [{"path": "/admin"}]},
            "technologies": {"technologies": [{"id": "php"}]},
        }
        o.attack_plan = {"phases": [
            {"phase": "tech_specific", "priority_modules": ["/wp-admin"]},
            {"phase": "other", "priority_modules": ["/nope"]},
        ]}
        o.last_hypotheses = []
        o.reasoner = MagicMock()
        o.reasoner.score_endpoint.return_value = 0.5
        group = SimpleNamespace(vuln_type="sqli", confidence=0.9, payloads=[1, 2, 3])
        with patch("tools.orchestrator.AdaptiveFuzzer") as af:
            af.return_value.all_groups.return_value = [group]
            pts = o._build_test_points()

        keys = {(p["url"], p["param"], p.get("method", "GET")) for p in pts}
        assert ("http://target.test", "id", "GET") in keys
        assert ("http://target.test/a", "id", "GET") in keys
        assert ("http://target.test/a", "submit", "GET") not in keys
        assert ("http://target.test/m", "g1", "GET") in keys
        assert ("http://target.test/m", "g404", "GET") not in keys
        assert ("http://target.test/m", "p_ok", "POST") in keys
        assert ("http://target.test/m", "submit", "POST") not in keys
        assert ("http://target.test/admin", SIGNATURE_PLACEHOLDER, "GET") in keys
        assert ("http://target.test/api/one", "page", "GET") in keys
        assert ("http://other.test/api/two", SIGNATURE_PLACEHOLDER, "GET") in keys
        assert ("http://target.test/wp-admin", SIGNATURE_PLACEHOLDER, "GET") in keys
        assert ("http://target.test/nope", SIGNATURE_PLACEHOLDER, "GET") not in keys
        assert all("_payload_groups" in p for p in pts)
        post_point = [p for p in pts if p.get("method") == "POST"][0]
        assert post_point["post_data"] == {"p_ok": "1"}

    def test_enrichment_dedups_identical_points(self):
        o = _orch()
        duplicate = {"url": "http://target.test/x", "param": "id", "method": "GET"}
        o._seed_points_from_target = MagicMock(return_value=[dict(duplicate), dict(duplicate)])
        o._seed_points_from_endpoints = MagicMock(return_value=[])
        o.state["phases"]["crawl"] = {}
        o.state["phases"]["param_mine"] = {}
        o.state["phases"]["recon"] = {"technologies": {"technologies": [{"id": "php"}]}}
        o.reasoner = MagicMock()
        o.reasoner.score_endpoint.return_value = 0.1
        with patch("tools.orchestrator.AdaptiveFuzzer") as af:
            af.return_value.all_groups.return_value = []
            pts = o._build_test_points()
        assert len(pts) == 1

    def test_turbo_limit(self):
        o = _orch(turbo=True)
        o.state["phases"]["crawl"] = {}
        o.state["phases"]["param_mine"] = {}
        o.state["phases"]["recon"] = {}
        o._seed_points_from_target = MagicMock(return_value=[])
        o._seed_points_from_endpoints = MagicMock(return_value=[])
        assert o._build_test_points() == []


class TestBudget:
    def test_budget_remaining_and_ok(self):
        o = _orch(time_budget=100.0)
        o._start_time = time.time() - 10
        assert 88 < o._budget_remaining() <= 90.5
        assert o._budget_ok(5) is True
        assert o._budget_ok(200) is False

    def test_filter_by_budget_plenty(self):
        o = _orch(time_budget=100.0)
        pts = list(range(100))
        o._start_time = time.time() - 10
        assert o._filter_by_budget(pts) is pts

    def test_filter_by_budget_low(self):
        o = _orch(time_budget=100.0)
        pts = list(range(100))
        o._start_time = time.time() - 90
        assert len(o._filter_by_budget(pts)) == 30

    def test_filter_by_budget_middle(self):
        o = _orch(time_budget=100.0)
        pts = list(range(100))
        o._start_time = time.time() - 50
        assert 40 <= len(o._filter_by_budget(pts)) <= 50


class TestSelectDetectors:
    def test_hypotheses_path_fills_registry(self):
        from tools.orchestrator import ALL_DETECTOR_NAMES
        o = _orch()
        o.last_hypotheses = [_Hyp()]
        o.reasoner = MagicMock()
        o.reasoner.suggest_detectors.return_value = ["cmdi"]
        res = o._select_detectors()
        assert set(res) == set(ALL_DETECTOR_NAMES)

    def test_plan_recommended_mapping(self):
        o = _orch()
        o.last_hypotheses = [_Hyp()]
        o.reasoner = MagicMock()
        o.reasoner.suggest_detectors.return_value = []
        o.attack_plan = {"recommended_detectors": ["sql_injection", "nope", "cmdi"]}
        res = o._select_detectors()
        assert "sqlcheck" in res
        assert "sql_injection" not in res
        assert "cmdi" in res
        assert "nope" not in res

    def test_default_all_sorted_by_risk(self):
        from tools.orchestrator import ALL_DETECTOR_NAMES, DETECTOR_RISK_ORDER
        o = _orch()
        o.last_hypotheses = []
        res = o._select_detectors()
        assert set(res) == set(ALL_DETECTOR_NAMES)
        assert DETECTOR_RISK_ORDER[res[0]] == min(DETECTOR_RISK_ORDER.values())

    def test_filter_high_value(self):
        from tools.orchestrator import HIGH_VALUE_DETECTORS, LOW_VALUE_DETECTORS
        o = _orch()
        o.high_value = False
        low = sorted(LOW_VALUE_DETECTORS)[0]
        assert o._filter_high_value([low]) == [low]
        o.high_value = True
        high = sorted(HIGH_VALUE_DETECTORS)[0]
        assert o._filter_high_value([low, high]) == [high]


class TestPhaseRecon:
    def test_recon_full_results(self):
        o = _orch()
        with patch("tools.orchestrator.fingerprint_tech",
                   return_value={"technologies": [{"name": "nginx"}]}), \
             patch("tools.orchestrator.fingerprint_target", return_value={
                 "critical_versions": [{"product": "nginx", "version": "1.0",
                                        "cves": ["CVE-1", "CVE-2"]}],
                 "total_versions": 3}), \
             patch("tools.orchestrator.scan_ports", return_value={
                 "open_count": 2,
                 "open_ports": [{"port": 80, "service": "http", "state": "open"}]}), \
             patch("tools.orchestrator.check_git_leak", return_value={
                 "git_exposed": True, "sensitive_finds": [{}, {}]}), \
             patch("tools.orchestrator.enum_subdomains", return_value={
                 "resolved": ["a.t"], "http_reachable": ["a.t"]}), \
             patch("tools.orchestrator.fuzz_directories", return_value={
                 "interesting": [{"path": "/admin", "status": 200, "size": 12}]}), \
             patch("tools.recon.subdomain.COMMON_SUBDOMAINS", ["www"]):
            recon = o.phase_recon()
        assert recon["technologies"]["technologies"][0]["name"] == "nginx"
        assert recon["git_leak"]["git_exposed"] is True
        assert o.state["phases"]["recon"] is recon
        o.vuln_ctx.update.assert_any_call(has_debug_mode=True)

    def test_recon_empty_and_exceptions(self):
        o = _orch()
        o.sess.get.side_effect = RuntimeError("no http")
        with patch("tools.orchestrator.fingerprint_tech", return_value={}), \
             patch("tools.orchestrator.fingerprint_target", side_effect=RuntimeError("x")), \
             patch("tools.orchestrator.scan_ports", return_value={}), \
             patch("tools.orchestrator.check_git_leak", return_value={}), \
             patch("tools.orchestrator.enum_subdomains", side_effect=RuntimeError("x")), \
             patch("tools.orchestrator.fuzz_directories", return_value={"interesting": []}):
            recon = o.phase_recon()
        assert recon["subdomains"] == {}
        o.vuln_ctx.update.assert_not_called()

    def test_recon_versions_without_critical_and_no_subdomains(self):
        o = _orch()
        o.sess.get.side_effect = RuntimeError("no http")
        with patch("tools.orchestrator.fingerprint_tech", return_value={}), \
             patch("tools.orchestrator.fingerprint_target",
                   return_value={"total_versions": 2, "critical_versions": []}), \
             patch("tools.orchestrator.scan_ports", return_value={}), \
             patch("tools.orchestrator.check_git_leak", return_value={}), \
             patch("tools.orchestrator.enum_subdomains",
                   return_value={"resolved": [], "http_reachable": []}), \
             patch("tools.orchestrator.fuzz_directories", return_value={"interesting": []}):
            recon = o.phase_recon()
        assert recon["version_info"]["total_versions"] == 2


class TestPhaseAttackPlan:
    def test_plan_with_phases(self):
        o = _orch()
        plan = {"phases": [
            {"phase": "tech", "risk": "high", "tech": "Spring"},
            {"phase": "port", "risk": "med", "port": 8080, "module": "api"},
            {"phase": "det", "risk": "low", "detectors": ["cmdi", "ssrf"]},
        ], "risk_score": 7}
        o.state["phases"]["recon"] = {
            "technologies": {"technologies": []}, "open_ports": {"open_ports": []},
            "git_leak": {}, "directories": {"interesting": []},
        }
        with patch("tools.orchestrator.build_attack_plan", return_value=plan):
            got = o.phase_attack_plan()
        assert got["risk_score"] == 7
        assert o.attack_plan is plan
        assert o.state["phases"]["attack_plan"] is plan

    def test_plan_empty(self):
        o = _orch()
        o.state["phases"]["recon"] = {}
        with patch("tools.orchestrator.build_attack_plan",
                   return_value={"phases": [], "risk_score": 0}):
            got = o.phase_attack_plan()
        assert got["phases"] == []


class TestPhaseReason:
    def test_reason_full(self):
        o = _orch()
        o.reasoner = MagicMock()
        h = _Hyp(detail={"cve_ids": ["CVE-2021-1", "CVE-2021-2"]},
                 suggested_chain="sqli->rce")
        o.reasoner.analyze.return_value = [h]
        o.reasoner.correlate_hypotheses.return_value = [h]
        tree = MagicMock()
        tree.nodes = [1, 2, 3]
        tree.best_paths.return_value = [
            {"confidence": 0.9, "path_string": "n1 -> n2", "chain": "c1"}]
        tree.summary.return_value = {"nodes": 3}
        o.reasoner.build_attack_tree.return_value = tree
        graph = MagicMock()
        graph.summary.return_value = {
            "total_nodes": 5, "total_edges": 4, "goals": ["g1", "g2"],
            "best_paths": [{"confidence": 0.6, "path_string": "x"}],
        }
        o.state["phases"]["recon"] = {"technologies": {"technologies": []}}
        o.state["phases"]["crawl"] = {"endpoints": {}, "summary": {}}
        with patch("tools.orchestrator.build_attack_graph", return_value=graph):
            result = o.phase_reason()
        assert result == [h.to_dict()]
        assert o.attack_graph is graph
        assert o.state["phases"]["reason"]["count"] == 1
        assert o.attack_tree is tree

    def test_reason_no_hypotheses(self):
        o = _orch()
        o.reasoner = MagicMock()
        o.reasoner.analyze.return_value = []
        o.reasoner.correlate_hypotheses.return_value = []
        tree = MagicMock()
        tree.nodes = []
        tree.best_paths.return_value = []
        tree.summary.return_value = {"nodes": 0}
        o.reasoner.build_attack_tree.return_value = tree
        graph = MagicMock()
        graph.summary.return_value = {
            "total_nodes": 0, "total_edges": 0, "goals": [], "best_paths": []}
        with patch("tools.orchestrator.build_attack_graph", return_value=graph):
            result = o.phase_reason()
        assert result == []
        assert o.state["phases"]["reason"]["count"] == 0


class TestCrawlMineAuth:
    def test_phase_crawl(self):
        o = _orch()
        with patch("tools.orchestrator.crawler.crawl",
                   return_value={"endpoints": {}, "parameters": []}) as m:
            r = o.phase_crawl()
        m.assert_called_once()
        assert o.state["phases"]["crawl"] is r

    def test_phase_mine_default_endpoints(self):
        o = _orch()
        o.state["phases"]["crawl"] = {}
        with patch("tools.orchestrator.param_miner.mine",
                   return_value={"/": {"all_params": ["q"]}}) as m:
            res = o.phase_mine()
        assert res == {"/": {"all_params": ["q"]}}
        endpoints_arg = m.call_args[0][1]
        assert "/" in endpoints_arg

    def test_phase_mine_with_crawl_result(self):
        o = _orch()
        with patch("tools.orchestrator.param_miner.mine",
                   return_value={}) as m:
            o.phase_mine(crawl_result={"endpoints": {"/x": {}}})
        assert m.call_args[0][1] == {"/x": {}}
        assert o.state["phases"]["param_mine"] == {}

    def test_phase_auth_bypass(self):
        o = _orch()
        with patch("tools.orchestrator.auth_bypass.check",
                   return_value={"total_bypasses": 1}):
            r = o.phase_auth_bypass()
        assert r["total_bypasses"] == 1
        assert o.state["phases"]["auth_bypass"] is r


class TestBacktrack:
    def test_maybe_backtrack_runs_chain(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=True)
        fn = MagicMock(return_value={"success": True,
                                     "credentials_extracted": ["a:b"],
                                     "rce_available": True, "rce_method": "m"})
        with patch("tools.orchestrator_engine.chains.by_vtype",
                   return_value={"sqli": ("sqli_to_rce", fn)}):
            r = o._maybe_backtrack_chain({"type": "SQLi", "url": "u", "param": "id"})
        assert r["success"] is True
        assert o._chain_cache["sqli|u|id"] is r
        fn.assert_called_once_with("u", "id")

    def test_maybe_backtrack_cached(self):
        o = _orch()
        o._chain_cache["sqli|u|id"] = {"success": False}
        assert o._maybe_backtrack_chain(
            {"type": "sqli", "url": "u", "param": "id"}) is None

    def test_maybe_backtrack_no_chain_for_type(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=True)
        with patch("tools.orchestrator_engine.chains.by_vtype", return_value={}):
            assert o._maybe_backtrack_chain(
                {"type": "nope", "url": "u", "param": "p"}) is None

    def test_maybe_backtrack_budget_exhausted(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=False)
        fn = MagicMock()
        with patch("tools.orchestrator_engine.chains.by_vtype",
                   return_value={"sqli": ("sqli_to_rce", fn)}):
            assert o._maybe_backtrack_chain(
                {"type": "sqli", "url": "u", "param": "p"}) is None
        fn.assert_not_called()

    def test_maybe_backtrack_exception(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=True)
        fn = MagicMock(side_effect=RuntimeError("boom"))
        with patch("tools.orchestrator_engine.chains.by_vtype",
                   return_value={"sqli": ("sqli_to_rce", fn)}):
            assert o._maybe_backtrack_chain(
                {"type": "sqli", "url": "u", "param": "p"}) is None

    def test_loop_closure_noop(self):
        o = _orch()
        o._backtrack_loop_closure(None, {})
        o._backtrack_loop_closure({"success": False}, {})
        assert "recovered_credentials" not in o.state

    def test_loop_closure_credentials_rce_and_sqli(self):
        o = _orch()
        finding = {"type": "sqli", "url": "u", "param": "id"}
        chain_result = {"success": True,
                        "credentials_extracted": ["admin:pw", "user@host"],
                        "rce_available": True, "rce_method": "outfile"}
        o._backtrack_loop_closure(chain_result, finding)
        assert o.state["recovered_credentials"] == ["admin:pw", "user@host"]
        assert o.state["exploits"][0]["type"] == "rce"
        assert o.state["admin_creds"] == ["admin:pw", "user@host"]
        o2 = _orch()
        o2._backtrack_loop_closure({"success": True}, {"type": "xss"})
        assert o2.state["exploits"] == []

    def test_cross_verify_delegates(self):
        o = _orch()
        with patch("tools.orchestrator.test_runner.cross_verify",
                   return_value={"confirmed": True}) as m:
            r = o._cross_verify("sqli", "u", "p", "cf", {}, {"v": 1},
                                post_data={"p": "1"}, method="POST")
        assert r["confirmed"] is True
        kwargs = m.call_args[1]
        assert kwargs["oracle"] is o.oracle
        assert kwargs["sess"] is o.sess
        assert kwargs["post_data"] == {"p": "1"}
        assert kwargs["method"] == "POST"

    def test_run_detector_delegates(self):
        o = _orch()
        with patch("tools.orchestrator.test_runner.run_detector",
                   return_value={"_vtype": "cmdi"}) as m:
            r = o._run_detector("cmdi", "u", "p", "waf", {}, 5.0,
                                post_data=None, method="POST")
        assert r["_vtype"] == "cmdi"
        assert m.call_args[1]["method"] == "POST"


class TestTestSinglePointExtra:
    def _fpf_patch(self, filtered=False):
        inst = MagicMock()
        inst.filter_single.side_effect = lambda f: dict(f, filtered=filtered,
                                                        vulnerable=not filtered)
        return patch("tools.false_positive_filter.FalsePositiveFilter",
                     return_value=inst)

    def test_skip_verify_marks_verified(self):
        o = _orch()
        o.skip_verify = True
        o._budget_ok = MagicMock(return_value=True)
        o._run_detector = MagicMock(return_value={
            "_vtype": "cmdi", "vulnerable": True, "confidence_score": 0.6,
            "os_type": "linux", "result": {"os_type": "linux"}, "evidence": ["e"],
        })
        o._maybe_backtrack_chain = MagicMock(return_value=None)
        with patch("tools.orchestrator.suggest_additional_tests",
                   return_value=["try"]):
            res = o._test_single_point({"url": "u", "param": "p"}, ["cmdi"])
        assert len(res) == 1
        assert res[0]["result"]["verified"] is True
        o.oracle.verify.assert_not_called()
        assert res[0]["suggested_next_steps"] == ["try"]
        o.vuln_ctx.update.assert_any_call(os_type="linux")

    def test_fast_mode_disables_low_value(self):
        from tools.orchestrator import LOW_VALUE_DETECTORS
        o = _orch()
        o.skip_verify = True
        o._fast_mode = True
        o._budget_ok = MagicMock(return_value=True)
        o._run_detector = MagicMock(return_value={
            "_vtype": "ssrf", "vulnerable": True, "confidence_score": 0.6,
            "cloud": "aws", "result": {"cloud": "aws"}, "evidence": ["e"],
        })
        o._maybe_backtrack_chain = MagicMock(return_value=None)
        res = o._test_single_point({"url": "u", "param": "p"}, ["ssrf"])
        assert len(res) == 1
        assert LOW_VALUE_DETECTORS <= o._detectors_disabled
        o.vuln_ctx.update.assert_any_call(cloud_provider="aws")

    def test_sqli_full_post_processing(self):
        o = _orch()
        o.skip_verify = False
        o._budget_ok = MagicMock(return_value=True)
        o._run_detector = MagicMock(return_value={
            "_vtype": "sqli", "vulnerable": True, "confidence_score": 0.7,
            "result": {"payload": "'"}, "evidence": ["det"],
        })
        o.oracle.verify = MagicMock(return_value={
            "verified": True, "confidence_score": 0.9,
            "confidence_votes": ["v"], "evidence": ["o1", "o2"],
        })
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        o._maybe_backtrack_chain = MagicMock(return_value={
            "success": True, "credentials_extracted": ["root:pw"],
            "rce_available": True, "rce_method": "into outfile"})
        with self._fpf_patch(filtered=False), \
             patch("tools.orchestrator.robust_verify",
                   return_value={"vulnerable": True, "confidence": 0.95,
                                 "dbms": "mysql"}), \
             patch("tools.orchestrator.run_cross_validation",
                   return_value={"vulnerable": True, "cross_checks": {"a": 1},
                                 "confidence": 0.92, "rce_available": True}), \
             patch("tools.orchestrator.sqli_union_probe",
                   return_value={"vulnerable": True, "columns": 4,
                                 "usable_columns": [2, 3]}), \
             patch("tools.orchestrator.binary_search_sqli_blind",
                   return_value={"extracted": "db"}), \
             patch("tools.orchestrator.suggest_additional_tests",
                   return_value=["next"]):
            res = o._test_single_point({"url": "u", "param": "id"}, ["sqli"])
        assert len(res) == 1
        f = res[0]
        assert f["robust_verified"] is True
        assert f["dbms"] == "mysql"
        assert f["cross_validated"] is True
        assert f["rce_available"] is True
        assert f["sql_columns"] == 4
        assert f["blind_extracted"] == "db"
        assert f["suggested_next_steps"] == ["next"]
        assert f["_chain_result"]["success"] is True
        assert o.state["recovered_credentials"] == ["root:pw"]

    def test_fpf_filtered_finding_stored(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=True)
        o.state["filtered_findings"] = []
        o._run_detector = MagicMock(return_value={
            "_vtype": "xss", "vulnerable": True, "confidence_score": 0.4,
            "result": {}, "evidence": [],
        })
        o.oracle.verify = MagicMock(return_value={
            "verified": True, "confidence_score": 0.4,
            "confidence_votes": [], "evidence": [],
        })
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        with self._fpf_patch(filtered=True):
            res = o._test_single_point({"url": "u", "param": "p"}, ["xss"])
        assert res == []
        assert len(o.state["filtered_findings"]) == 1
        assert o.state["filtered_findings"][0]["filtered"] is True

    def test_oracle_not_verified_skips(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=True)
        o._run_detector = MagicMock(return_value={
            "_vtype": "xss", "vulnerable": True, "confidence_score": 0.8,
            "result": {}, "evidence": [],
        })
        o.oracle.verify = MagicMock(return_value={"verified": False,
                                                  "confidence_score": 0.0})
        o._cross_verify = MagicMock(side_effect=lambda *a, **k: a[5])
        res = o._test_single_point({"url": "u", "param": "p"}, ["xss"])
        assert res == []
        assert "filtered_findings" not in o.state

    def test_disabled_detector_returns_empty(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=True)
        o._detectors_disabled = {"xss"}
        assert o._test_single_point({"url": "u", "param": "p"}, ["xss"]) == []

    def test_time_sensitive_budget_skip(self):
        o = _orch()
        o._budget_ok = MagicMock(side_effect=lambda need=5.0: need < 5)
        assert o._test_single_point({"url": "u", "param": "p"}, ["sqli"]) == []

    def test_turbo_parallel_path(self):
        o = _orch(turbo=True)
        o._budget_ok = MagicMock(return_value=True)

        def _run(vtype, *a, **k):
            if vtype == "boom":
                raise RuntimeError("det crash")
            return {"_vtype": vtype, "vulnerable": False, "confidence_score": 0.0}

        o._run_detector = MagicMock(side_effect=_run)
        res = o._test_single_point(
            {"url": "u", "param": "p", "method": "POST", "post_data": {"p": "1"}},
            ["a1", "b2", "boom", "d4"],
        )
        assert res == []
        assert o._run_detector.call_count == 4

    def test_total_bypasses_counts_as_vulnerable(self):
        o = _orch()
        o.skip_verify = True
        o._budget_ok = MagicMock(return_value=True)
        o._run_detector = MagicMock(return_value={
            "_vtype": "auth-bypass", "vulnerable": False, "total_bypasses": 2,
            "confidence_score": 0.5, "evidence": [],
        })
        o._maybe_backtrack_chain = MagicMock(return_value=None)
        res = o._test_single_point({"url": "u", "param": "p"}, ["auth-bypass"])
        assert len(res) == 1

    def test_budget_break_in_result_loop(self):
        o = _orch()
        calls = {"n": 0}

        def budget(need=5.0):
            calls["n"] += 1
            return calls["n"] == 1

        o._budget_ok = budget
        o._run_detector = MagicMock(return_value={
            "_vtype": "xss", "vulnerable": True, "confidence_score": 0.9,
            "result": {}, "evidence": [],
        })
        assert o._test_single_point({"url": "u", "param": "p"}, ["xss"]) == []

    def test_entry_budget_exhausted(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=False)
        assert o._test_single_point({"url": "u", "param": "p"}, ["xss"]) == []

    def test_result_loop_budget_break(self):
        o = _orch()
        o._budget_ok = MagicMock(side_effect=[True, True, False])
        o._run_detector = MagicMock(return_value={
            "_vtype": "xss", "vulnerable": True, "confidence_score": 0.9,
        })
        assert o._test_single_point({"url": "u", "param": "p"}, ["xss"]) == []

    def test_turbo_parallel_budget_break(self):
        o = _orch(turbo=True)
        o._budget_ok = MagicMock(side_effect=[True, False])
        o._run_detector = MagicMock(return_value={
            "_vtype": "a1", "vulnerable": False, "confidence_score": 0.0,
        })
        assert o._test_single_point({"url": "u", "param": "p"},
                                    ["a1", "b2"]) == []

    def test_sqli_extraction_exceptions_swallowed(self):
        o = _orch()
        o.skip_verify = True
        o._budget_ok = MagicMock(return_value=True)
        o._run_detector = MagicMock(return_value={
            "_vtype": "sqli", "vulnerable": True, "confidence_score": 0.6,
            "evidence": [],
        })
        o._maybe_backtrack_chain = MagicMock(return_value=None)
        with patch("tools.orchestrator.sqli_union_probe",
                   side_effect=RuntimeError("u")), \
             patch("tools.orchestrator.binary_search_sqli_blind",
                   side_effect=RuntimeError("b")), \
             patch("tools.orchestrator.suggest_additional_tests", return_value=[]):
            res = o._test_single_point({"url": "u", "param": "id"}, ["sqli"])
        assert len(res) == 1
        assert "sql_columns" not in res[0]
        assert "blind_extracted" not in res[0]

    def test_suggest_next_steps_exception_swallowed(self):
        o = _orch()
        o.skip_verify = True
        o._budget_ok = MagicMock(return_value=True)
        o._run_detector = MagicMock(return_value={
            "_vtype": "lfi", "vulnerable": True, "confidence_score": 0.6,
            "evidence": [],
        })
        o._maybe_backtrack_chain = MagicMock(return_value=None)
        with patch("tools.orchestrator.suggest_additional_tests",
                   side_effect=RuntimeError("s")):
            res = o._test_single_point({"url": "u", "param": "p"}, ["lfi"])
        assert len(res) == 1
        assert "suggested_next_steps" not in res[0]


class TestUpdateContextMemory:
    def _tech(self, name):
        return {"name": name}

    def _run(self, o, vc, findings, ports=None, techs=None):
        o.vuln_ctx.get.return_value = vc
        recon = {
            "technologies": {"technologies": [self._tech(t) for t in (techs or [])]},
            "open_ports": {"open_ports": ports or []},
        }
        o.state["phases"]["recon"] = recon
        o._update_context_memory(findings)

    def test_update_context_memory_rich(self):
        o = _orch()
        o.state["waf"] = {"name": "cloudflare"}
        vc = SimpleNamespace(
            dbms="mysql", cloud_provider="gcp", os_type="linux",
            ssti_engine="jinja2", has_admin_panel=True, has_graphql=True,
            ssrf_cloud_creds=["AKIA"], lfi_readable_paths=["/var/log/auth.log"],
            debug_endpoints=["/actuator"], discovered_versions={"php": "8.1"},
        )
        vc.best_exploit_path = lambda: ["lfi_log_poison_rce"]
        findings = {
            "__meta__": {"type": "meta"},
            "f1": {"type": "sqli", "result": {"dbms": "postgres"}},
            "f2": {"type": "ssrf", "result": {"cloud": "aws"}},
            "f3": {"type": "lfi", "result": {"os_type": "windows"}},
            "f4": {"type": "cmdi", "result": {"os_type": "linux"}},
            "f5": {"type": "auth_bypass", "result": {"credentials": ["a:b"]}},
            "f6": {"type": "jwt", "result": {"tokens_found": [{"token": "T"}]}},
            "f7": {"type": "other", "result": {}},
        }
        self._run(o, vc, findings, ports=[{"port": 3389}],
                  techs=["Spring Boot", "Django", "Flask", "Laravel", "ThinkPHP",
                         "Express", "Node.js", "WordPress", "Amazon S3",
                         "Google Cloud", "Azure Cloud", "Aliyun OSS"])
        pairs = [(c[0][0], c[0][1]) for c in o.context_memory.set.call_args_list]
        assert ("framework", "Spring Boot") in pairs
        assert ("framework", "Django") in pairs
        assert ("framework", "Flask") in pairs
        assert ("framework", "Laravel") in pairs
        assert ("framework", "ThinkPHP") in pairs
        assert ("framework", "Express") in pairs
        assert ("framework", "WordPress") in pairs
        assert ("cloud_provider", "aws") in pairs
        assert ("cloud_provider", "gcp") in pairs
        assert ("cloud_provider", "azure") in pairs
        assert ("cloud_provider", "alibaba") in pairs
        assert ("waf", "cloudflare") in pairs
        assert ("os_type", "windows") in pairs
        assert ("dbms", "postgres") in pairs
        assert ("creds", ["a:b"]) in pairs
        assert ("session_token", "T") in pairs
        assert ("dbms", "mysql") in pairs
        assert ("template_engine", "jinja2") in pairs
        assert ("admin_panel", True) in pairs
        assert ("has_graphql", True) in pairs
        assert ("cloud_creds", ["AKIA"]) in pairs
        assert ("lfi_readable_paths", ["/var/log/auth.log"]) in pairs
        assert ("debug_endpoints", ["/actuator"]) in pairs
        assert ("php", "8.1") in pairs
        assert ("best_exploit_paths", ["lfi_log_poison_rce"]) in pairs

    def test_update_context_memory_empty(self):
        o = _orch()
        o.state["waf"] = {}
        vc = SimpleNamespace(
            dbms=None, cloud_provider=None, os_type=None, ssti_engine=None,
            has_admin_panel=False, has_graphql=False, ssrf_cloud_creds=[],
            lfi_readable_paths=[], debug_endpoints=[], discovered_versions={},
        )
        vc.best_exploit_path = lambda: []
        self._run(o, vc, {"f": {"type": "other", "result": {}}},
                  ports=[{"port": 22}], techs=[])
        pairs = [(c[0][0], c[0][1]) for c in o.context_memory.set.call_args_list]
        assert ("os_type", "linux") in pairs

    def test_update_context_memory_ports_windows(self):
        o = _orch()
        o.state["waf"] = {}
        vc = SimpleNamespace(
            dbms=None, cloud_provider=None, os_type=None, ssti_engine=None,
            has_admin_panel=False, has_graphql=False, ssrf_cloud_creds=[],
            lfi_readable_paths=[], debug_endpoints=[], discovered_versions={},
        )
        vc.best_exploit_path = lambda: []
        self._run(o, vc, {}, ports=[{"port": 3389}], techs=[])
        pairs = [(c[0][0], c[0][1]) for c in o.context_memory.set.call_args_list]
        assert ("os_type", "windows") in pairs


class TestPhaseDetect:
    def test_phase_detect_orchestration(self):
        o = _orch()
        o.threads = 1
        o.state["phases"]["recon"] = {"technologies": {"technologies": [{"name": "nginx"}]}}
        o.last_hypotheses = []
        o._select_detectors = MagicMock(return_value=["cmdi"])
        o._fingerprint_waf_cached = MagicMock(return_value={"name": "cf"})
        o._build_test_points = MagicMock(return_value=[{"url": "u", "param": "p"}])
        o._filter_by_budget = MagicMock(side_effect=lambda pts: pts)
        o.profiler.profile_batch.return_value = 3
        o._phase_detect_scan = MagicMock(return_value={"f": {"type": "cmdi"}})
        o._phase_detect_semantic = MagicMock()
        o._phase_detect_second_order = MagicMock()
        o._phase_detect_type_confusion = MagicMock()
        o._phase_detect_bayes = MagicMock()
        o.vuln_ctx.get.return_value = SimpleNamespace(debug_endpoints=["/actuator"])
        o.oob_server.register_callback_id.return_value = "oob-url"
        o.oob_server.start_dns.return_value = "oob.test"
        result = o.phase_detect()
        assert result == {"f": {"type": "cmdi"}}
        assert o.state["waf"]["name"] == "cf"
        assert o.state["ai_prepared"]["waf"] == "cf"
        assert o.state["ai_prepared"]["technologies"] == ["nginx"]
        assert o.state["ai_prepared"]["debug_endpoints"] == ["/actuator"]
        o.oob_server.register_callback_id.assert_called_once()
        o.profiler.profile_batch.assert_called_once()

    def test_phase_detect_scan_sequential(self):
        o = _orch()
        o.threads = 1
        o._budget_ok = MagicMock(return_value=True)
        o._run_kali_recon = MagicMock()
        finding = {"type": "cmdi", "url": "u", "param": "p"}
        o._test_single_point = MagicMock(return_value=[finding])
        o.oob_server.pop_callbacks.return_value = []
        res = o._phase_detect_scan(
            [{"url": "u", "param": "p"}, {"url": "u2", "param": "p2"}],
            ["cmdi"], "cf", 80.0, "cb1", "oob", "oob.test")
        assert res["cmdi|u|p"] is finding
        assert o.state["phases"]["detect"]["test_points"] == 2
        assert o.all_findings is res
        o._run_kali_recon.assert_called_once()

    def test_phase_detect_scan_parallel_with_oob(self):
        o = _orch()
        o.threads = 4
        o._budget_ok = MagicMock(return_value=True)
        o._run_kali_recon = MagicMock()
        o._test_single_point = MagicMock(return_value=[])
        cb = SimpleNamespace(path="/cb", client=("1.2.3.4", 1234))
        o.oob_server.pop_callbacks.return_value = [cb]
        res = o._phase_detect_scan(
            [{"url": "u", "param": "p"}], ["cmdi"], None, 50.0, "cb1", None, None)
        assert res["__oob_callbacks__"]["result"]["vulnerable"] is True
        assert res["__oob_callbacks__"]["result"]["callbacks"][0]["path"] == "/cb"

    def test_phase_detect_scan_parallel_budget_break(self):
        o = _orch()
        o.threads = 4
        o._budget_ok = MagicMock(side_effect=[True, False])
        o._run_kali_recon = MagicMock()
        o._test_single_point = MagicMock(return_value=[])
        o.oob_server.pop_callbacks.return_value = []
        o._phase_detect_scan(
            [{"url": "u", "param": "p"}, {"url": "u2", "param": "p2"}],
            ["cmdi"], None, 50.0, "cb", None, None)

    def test_phase_detect_scan_worker_exception(self):
        o = _orch()
        o.threads = 4
        o._budget_ok = MagicMock(return_value=True)
        o._run_kali_recon = MagicMock()
        o._test_single_point = MagicMock(side_effect=RuntimeError("worker"))
        o.oob_server.pop_callbacks.return_value = []
        o._phase_detect_scan(
            [{"url": "u", "param": "p"}], ["cmdi"], None, 50.0, "cb", None, None)

    def test_phase_detect_scan_sequential_budget_break(self):
        o = _orch()
        o.threads = 1
        o._budget_ok = MagicMock(return_value=False)
        o._run_kali_recon = MagicMock()
        o._test_single_point = MagicMock(return_value=[])
        o.oob_server.pop_callbacks.return_value = []
        o._phase_detect_scan(
            [{"url": "u", "param": "p"}], ["cmdi"], None, 5.0, "cb", None, None)
        o._test_single_point.assert_not_called()

    def test_phase_detect_semantic(self):
        o = _orch()
        findings = {
            "__oob__": {"type": "oob"},
            "skip": {"vulnerable": False},
            "short": {"vulnerable": True, "response_text": "tiny"},
            "f1": {"vulnerable": True, "response_text": "A" * 80},
        }
        with patch("tools.orchestrator.analyze_single_response",
                   side_effect=[{"baseline": True}, {"errors": ["sql error"]}]) as sem, \
             patch("tools.orchestrator.compare_responses",
                   return_value={"diff": 1}):
            o._phase_detect_semantic(findings)
        assert findings["f1"]["semantic"] == {"errors": ["sql error"]}
        assert findings["f1"]["response_changes"] == {"diff": 1}
        assert findings["f1"]["error_signals"] == ["sql error"]
        assert sem.call_count == 2

    def test_phase_detect_semantic_baseline_error(self):
        o = _orch()
        o.sess.get.side_effect = RuntimeError("down")
        with patch("tools.orchestrator.analyze_single_response",
                   return_value={}) as sem:
            o._phase_detect_semantic({"f": {"vulnerable": True,
                                            "response_text": "B" * 80}})
        assert sem.call_count == 1

    def test_phase_detect_second_order(self):
        o = _orch()
        o.attack_graph = MagicMock()
        o.attack_graph.nodes = {"sqli_found": {}}
        o.verifier = MagicMock()
        o.verifier.verify.return_value = {"confirmed": True, "confidence": 0.9,
                                          "methods_succeeded": ["m1"]}
        findings = {
            "__meta__": {"confidence_score": 0.9},
            "low": {"type": "xss", "confidence_score": 0.2},
            "f1": {"type": "sqli", "url": "u", "param": "p",
                   "confidence_score": 0.6, "result": {}},
        }
        o._phase_detect_second_order(findings)
        assert findings["f1"]["second_order_verified"] is True
        assert findings["f1"]["verification_confidence"] == 0.9
        o.attack_graph.integrate_evidence.assert_called_once()
        o.verifier.verify.assert_called_once()

    def test_phase_detect_second_order_exception(self):
        o = _orch()
        o.attack_graph = None
        o.verifier = MagicMock()
        o.verifier.verify.side_effect = RuntimeError("boom")
        findings = {"f1": {"type": "sqli", "url": "u", "param": "p",
                           "confidence_score": 0.6, "result": {}}}
        o._phase_detect_second_order(findings)
        assert "second_order_verified" not in findings["f1"]

    def test_phase_detect_type_confusion(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=True)
        tc = SimpleNamespace(success=True, error_leak=False, vuln_type="type_confusion",
                             evidence="ev", original_type="int", confused_type="str",
                             status_changed=True, risk_level="medium")
        toctou = SimpleNamespace(success=True, evidence="race")
        detector = MagicMock()
        detector.detect.return_value = [tc]
        detector.detect_toctou.return_value = [toctou]
        findings = {}
        with patch("tools.orchestrator.TypeConfusionDetector", return_value=detector):
            o._phase_detect_type_confusion([{"url": "u", "param": "p"}], findings)
        assert findings["type_confusion|u|p"]["confidence_score"] == 0.70
        assert findings["race_condition|u|p"]["confidence_score"] == 0.75

    def test_phase_detect_type_confusion_error_and_budget(self):
        o = _orch()
        o._budget_ok = MagicMock(return_value=False)
        detector = MagicMock()
        with patch("tools.orchestrator.TypeConfusionDetector", return_value=detector):
            o._phase_detect_type_confusion([{"url": "u", "param": "p"}], {})
        detector.detect.assert_not_called()
        o2 = _orch()
        o2._budget_ok = MagicMock(return_value=True)
        detector2 = MagicMock()
        detector2.detect.side_effect = RuntimeError("boom")
        with patch("tools.orchestrator.TypeConfusionDetector", return_value=detector2):
            o2._phase_detect_type_confusion([{"url": "u", "param": "p"}], {})

    def test_phase_detect_bayes_updates(self):
        o = _orch()
        o._backtrack_findings = [{"type": "SQLi", "result": {"a": 1}}]
        o.last_hypotheses = [_Hyp()]
        o.reasoner = MagicMock()
        o.reasoner.update_with_evidence.return_value = [_Hyp()]
        o.reasoner.suggest_detectors.return_value = ["cmdi", "xsscheck"]
        o._phase_detect_bayes(["cmdi"])
        o.reasoner.update_with_evidence.assert_called_once()
        o.reasoner.suggest_detectors.assert_called_once()

    def test_phase_detect_bayes_without_hypotheses(self):
        o = _orch()
        o._backtrack_findings = [{"type": "sqli", "result": {}}]
        o.last_hypotheses = []
        o.reasoner = MagicMock()
        o._phase_detect_bayes([])
        o.reasoner.update_with_evidence.assert_not_called()

    def test_phase_detect_bayes_no_findings(self):
        o = _orch()
        o._backtrack_findings = []
        o._phase_detect_bayes([])
        assert o.last_hypotheses == []


class TestPhaseAiHunt:
    def test_ai_hunt_success(self):
        o = _orch()
        intel = {"brief": "brief text", "anomalies_found": 2, "deep_results_count": 3}
        o.all_findings = {}
        with patch("tools.ai_vuln_hunter.generate_target_brief",
                   return_value=intel) as m:
            res = o.phase_ai_hunt()
        assert res is intel
        assert o.state["phases"]["ai_hunt"] is intel
        assert m.call_args[1]["base_url"] == o.target

    def test_ai_hunt_exception(self):
        o = _orch()
        with patch("tools.ai_vuln_hunter.generate_target_brief",
                   side_effect=RuntimeError("no ai")):
            res = o.phase_ai_hunt()
        assert res == {"anomalies_found": 0, "scan_count": 0}
        assert "error" in o.state["phases"]["ai_hunt"]


class TestPhasePivot:
    def test_pivot_with_suggested_chain_and_cache(self):
        o = _orch()
        o.all_findings = {"k": {"type": "sqli", "url": "u", "param": "p",
                                "result": {}}}
        o.last_hypotheses = [_Hyp()]
        o.reasoner = MagicMock()
        o.reasoner.update_with_evidence.return_value = [_Hyp()]
        o.reasoner.suggest_chains.return_value = [("sqli_to_rce", "u", "p")]
        o._chain_cache = {"sqli|u|p": {"success": True}}
        fn = MagicMock(return_value={"success": True,
                                     "credentials_extracted": ["c:d"],
                                     "rce_available": True, "rce_method": "m"})
        with patch("tools.chain_engine.ChainEngine"), \
             patch("tools.orchestrator_engine.chains.by_name",
                   return_value={"sqli_to_rce": ("sqli", fn)}), \
             patch("tools.orchestrator.pivot_on_intermediate_result",
                   return_value={"pivoted": False, "phases": []}):
            res = o.phase_pivot()
        assert fn.call_count == 1
        assert {a["success"] for a in res["pivot_actions"]} == {True}
        assert o.state["phases"]["pivot"] is res

    def test_pivot_dispatch_handlers(self):
        o = _orch()
        o.all_findings = {"k": {"type": "auth_bypass", "url": "u", "param": "p",
                                "result": {}}}
        o.last_hypotheses = []
        o.state["phases"]["auth_bypass"] = {"vulnerable": True}
        chain = MagicMock()
        chain.chain_auth_to_admin.return_value = {"success": True}
        with patch("tools.chain_engine.ChainEngine", return_value=chain), \
             patch("tools.orchestrator.pivot_on_intermediate_result",
                   return_value={"pivoted": True, "phases": [
                       {"phase": "auth_pivot"},
                       {"phase": "graphql_pivot"},
                       {"phase": "unknown_pivot"},
                   ]}):
            res = o.phase_pivot()
        chain.chain_auth_to_admin.assert_called_once_with(o.target)
        assert {"success": True} in res["pivot_actions"]

    def test_pivot_no_chains(self):
        o = _orch()
        o.all_findings = {}
        o.last_hypotheses = []
        with patch("tools.chain_engine.ChainEngine"), \
             patch("tools.orchestrator_engine.chains.by_name", return_value={}), \
             patch("tools.orchestrator.pivot_on_intermediate_result",
                   return_value={"pivoted": False}):
            res = o.phase_pivot()
        assert res["pivot_actions"] == []

    def test_run_suggested_chain_skips_used_and_unknown(self):
        o = _orch()
        pr = {"pivot_actions": [], "exploits": []}
        used = {"sqli_to_rce"}
        o._pivot_run_suggested_chain("sqli_to_rce", [], {}, pr, used)
        o._pivot_run_suggested_chain("unknown", [], {}, pr, used)
        fn = MagicMock()
        o._pivot_run_suggested_chain(
            "sqli_to_rce", [{"type": "xss", "url": "u", "param": "p"}],
            {"sqli_to_rce": ("sqli", fn)}, pr, set())
        fn.assert_not_called()
        assert pr["pivot_actions"] == []

    def test_run_suggested_chain_exception(self):
        o = _orch()
        pr = {"pivot_actions": [], "exploits": []}
        fn = MagicMock(side_effect=RuntimeError("boom"))
        o._pivot_run_suggested_chain("sqli_to_rce",
                                     [{"type": "sqli", "url": "u", "param": "p"}],
                                     {"sqli_to_rce": ("sqli", fn)}, pr, set())
        assert pr["pivot_actions"] == []

    def test_pivot_handlers_table_complete(self):
        assert set(_PIVOT_HANDLERS) == {
            "ssrf_pivot", "lfi_pivot", "sqli_pivot", "jwt_pivot",
            "auth_pivot", "deser_pivot", "graphql_pivot",
        }


class TestPivotHandlers:
    def _pr(self):
        return {"pivot_actions": [], "exploits": []}

    def test_handle_ssrf(self):
        o = _orch()
        chain = MagicMock()
        chain.chain_ssrf_to_rce.return_value = {"success": True}
        with patch("tools.orchestrator.ssrf_chain_attack",
                   return_value={"rce_achieved": True, "rce_method": "redis",
                                 "services_found": 2, "ssh_keys": ["k"]}):
            used = o._pivot_handle_ssrf([{"type": "ssrf", "url": "u", "param": "p"}],
                                        chain, self._pr())
        assert used == {"ssrf_to_rce"}

    def test_handle_ssrf_exception(self):
        o = _orch()
        chain = MagicMock()
        chain.chain_ssrf_to_rce.return_value = {"success": False}
        with patch("tools.orchestrator.ssrf_chain_attack",
                   side_effect=RuntimeError("boom")):
            used = o._pivot_handle_ssrf([{"type": "ssrf", "url": "u", "param": "p"}],
                                        chain, self._pr())
        assert used == {"ssrf_to_rce"}

    def test_handle_ssrf_no_match(self):
        o = _orch()
        assert o._pivot_handle_ssrf([{"type": "xss", "url": "u", "param": "p"}],
                                    MagicMock(), self._pr()) == set()

    def test_handle_lfi_and_sqli_and_deser(self):
        o = _orch()
        chain = MagicMock()
        chain.chain_lfi_to_rce.return_value = {"success": True}
        chain.chain_sqli_to_rce.return_value = {"success": True}
        chain.chain_deser_to_rce.return_value = {"success": True}
        assert o._pivot_handle_lfi([{"type": "lfi", "url": "u", "param": "p"}],
                                   chain, self._pr()) == {"lfi_to_rce"}
        assert o._pivot_handle_sqli([{"type": "sqli", "url": "u", "param": "p"}],
                                    chain, self._pr()) == {"sqli_to_rce"}
        assert o._pivot_handle_deser([{"type": "deser", "url": "u", "param": "p"}],
                                     chain, self._pr()) == {"deser_to_rce"}
        assert o._pivot_handle_lfi([], chain, self._pr()) == set()
        assert o._pivot_handle_sqli([], chain, self._pr()) == set()
        assert o._pivot_handle_deser([], chain, self._pr()) == set()
        other = [{"type": "xss", "url": "u", "param": "p"}]
        assert o._pivot_handle_lfi(other, chain, self._pr()) == set()
        assert o._pivot_handle_sqli(other, chain, self._pr()) == set()
        assert o._pivot_handle_deser(other, chain, self._pr()) == set()

    def test_handle_jwt(self):
        o = _orch()
        with patch("tools.jwt_exploiter.check",
                   return_value={"vulnerable": True}) as m:
            used = o._pivot_handle_jwt([{"type": "jwt", "url": "u", "param": "p"}],
                                       MagicMock(), self._pr())
        assert used == set()
        assert m.call_args[1]["param"] == "p"
        assert o._pivot_handle_jwt([{"type": "xss", "url": "u", "param": "p"}],
                                   MagicMock(), self._pr()) == set()
        with patch("tools.jwt_exploiter.check", side_effect=RuntimeError("x")):
            o._pivot_handle_jwt([{"type": "jwt", "url": "u", "param": "p"}],
                                MagicMock(), self._pr())

    def test_handle_auth_and_graphql(self):
        o = _orch()
        o.state["phases"]["auth_bypass"] = {"vulnerable": True}
        chain = MagicMock()
        chain.chain_auth_to_admin.return_value = {"success": True}
        assert o._pivot_handle_auth([], chain, self._pr()) == {"auth_bypass_to_rce"}
        o.state["phases"]["auth_bypass"] = {}
        assert o._pivot_handle_auth([], chain, self._pr()) == set()
        pr = self._pr()
        o._pivot_handle_graphql([{"type": "graphql", "url": "u", "param": "p"}], chain, pr)
        assert pr["pivot_actions"][0]["chain"] == "graphql_deep"
        assert o._pivot_handle_graphql([], chain, self._pr()) == set()


class TestKaliRecon:
    def test_not_available(self):
        o = _orch()
        with patch("tools.kali_executor.is_available", return_value=False):
            o._run_kali_recon()
        assert "technologies" not in o.state

    def test_available_with_results(self):
        o = _orch()
        o.state["phases"]["detect"] = {"findings": {}}
        with patch("tools.kali_executor.is_available", return_value=True), \
             patch("tools.kali_toolset.whatweb_identify",
                   return_value={"technologies": ["nginx"]}), \
             patch("tools.kali_toolset.nmap_scan",
                   return_value={"ports": [80], "count": 1}), \
             patch("tools.kali_toolset.nuclei_scan",
                   return_value={"findings": [{"template": "t1", "info": {}}],
                                 "count": 1}):
            o._run_kali_recon()
        assert o.state["technologies"] == ["nginx"]
        assert o.state["open_ports"] == [80]
        assert o.state["nuclei_findings"][0]["template"] == "t1"
        assert "nuclei|t1|%s" % o.target in o.state["phases"]["detect"]["findings"]

    def test_available_exceptions_swallowed(self):
        o = _orch()
        with patch("tools.kali_executor.is_available", return_value=True), \
             patch("tools.kali_toolset.whatweb_identify",
                   side_effect=RuntimeError("a")), \
             patch("tools.kali_toolset.nmap_scan",
                   side_effect=RuntimeError("b")), \
             patch("tools.kali_toolset.nuclei_scan",
                   side_effect=RuntimeError("c")):
            o._run_kali_recon()
        assert "nuclei_findings" not in o.state


class TestDualSessionWeaponize:
    def test_dual_session_skipped_without_high_priv(self):
        o = _orch()
        assert o.phase_dual_session() == {"skipped": True,
                                          "reason": "no high_priv session"}

    def test_dual_session_findings_injected(self):
        o = _orch(high_priv_sess=MagicMock())
        o.dual_session = MagicMock()
        o.dual_session.test_batch.return_value = {
            "bola_count": 1, "info_disclosure_count": 1, "tested": 5,
            "bola_findings": [{"url": "u1", "param": "id", "evidence": ["e1"]}],
            "info_disclosure_findings": [{"url": "u2", "param": "id",
                                          "evidence": ["e2"]}],
        }
        o._build_test_points = MagicMock(return_value=[{"url": "u", "param": "p"}])
        o.state["phases"]["detect"] = {"findings": {}}
        res = o.phase_dual_session()
        assert res["bola_count"] == 1
        findings = o.state["phases"]["detect"]["findings"]
        assert findings["bola|u1|id"]["type"] == "bola"
        assert findings["info_disclosure|u2|id"]["type"] == "info_disclosure"

    def test_weaponize_with_findings_and_auth(self):
        o = _orch()
        o.state["phases"]["detect"] = {"findings": {
            "ok": {"type": "cmdi", "url": "u", "param": "p", "result": {}},
            "boom": {"type": "sqli", "url": "u2", "param": "p2", "result": {}},
            "none": {"type": "other", "url": "u3", "param": "p3", "result": {}},
        }}
        o.state["phases"]["auth_bypass"] = {
            "path_bypasses": [{"path": "/admin"}], "cookie_bypasses": [],
            "header_bypasses": []}

        def side(finding, *a, **k):
            if finding.get("type") == "sqli":
                raise RuntimeError("boom")
            if finding.get("type") == "other":
                return None
            return {"exploit_ready": True}

        with patch("tools.orchestrator.weaponizer.weaponize_one",
                   side_effect=side):
            res = o.phase_weaponize()
        assert res["ok"]["exploit_ready"] is True
        assert res["auth_bypass"]["total"] == 1
        assert o.state["phases"]["weaponize"] is res

    def test_weaponize_empty(self):
        o = _orch()
        o.state["phases"]["detect"] = {"findings": {}}
        with patch("tools.orchestrator.weaponizer.weaponize_one") as m:
            res = o.phase_weaponize()
        assert res == {}
        m.assert_not_called()


class TestPhaseAdvanced:
    def test_advanced_with_webshell(self):
        o = _orch()
        o.sess.get.return_value = _resp(200, "cmd output")

        def make_pty(exec_cmd):
            pty = MagicMock()
            pty.upgrade.return_value = {"success": True}
            pty._run.side_effect = lambda cmd: exec_cmd(cmd)
            return pty

        exploits = {"k": {"webshell": {"webshell_url": "http://ws/x"},
                          "sqli_webshell": {}, "lfi_webshell": {}}}
        with patch("tools.tunnel_agent.socks5_over_webshell",
                   return_value={"success": True, "deploy_commands": ["id"]}), \
             patch("tools.tunnel_agent.chisel_tunnel",
                   return_value={"success": True}), \
             patch("tools.interactive_shell.PTYShell", side_effect=make_pty), \
             patch("tools.lateral_move.steal_ssh_keys",
                   return_value={"success": True, "keys": ["ssh-rsa AAA"]}), \
             patch("tools.post_exploit.webshell_persistence",
                   return_value={"paths": ["/tmp/.x"]}), \
             patch("tools.post_exploit.cron_persistence",
                   return_value={"cron_line": "* * * * * id"}), \
             patch("tools.c2_beacon.C2Server"):
            res = o.phase_advanced(exploits)
        assert res["tunnels"][0]["success"] is True
        assert res["chisel_tunnel"]["success"] is True
        assert res["pty_upgrade"]["success"] is True
        assert res["enum_output"] == "cmd output"
        assert res["ssh_keys"] == ["ssh-rsa AAA"]
        assert res["post_exploit"]["webshell_hidden"] == ["/tmp/.x"]
        assert res["c2_active"] is True
        assert o.state["phases"]["advanced"] is res

    def test_advanced_without_webshell_c2_failure(self):
        o = _orch()
        with patch("tools.c2_beacon.C2Server",
                   side_effect=RuntimeError("port busy")):
            res = o.phase_advanced({"k": {"result": {}}})
        assert res["tunnels"] == []
        assert res["c2_active"] is False

    def test_advanced_shell_exec_exception(self):
        o = _orch()
        o.sess.get.side_effect = RuntimeError("no shell")

        def make_pty(exec_cmd):
            pty = MagicMock()
            pty.upgrade.return_value = {"success": False}
            pty._run.side_effect = lambda cmd: exec_cmd(cmd)
            return pty

        with patch("tools.tunnel_agent.socks5_over_webshell",
                   return_value={"success": True, "deploy_commands": ["id"]}), \
             patch("tools.tunnel_agent.chisel_tunnel",
                   return_value={"success": False}), \
             patch("tools.interactive_shell.PTYShell", side_effect=make_pty), \
             patch("tools.lateral_move.steal_ssh_keys",
                   return_value={"success": False}), \
             patch("tools.post_exploit.webshell_persistence",
                   return_value={"paths": []}), \
             patch("tools.post_exploit.cron_persistence",
                   return_value={"cron_line": "x"}), \
             patch("tools.c2_beacon.C2Server"):
            res = o.phase_advanced({"k": {"webshell": {"webshell_url": "http://ws/x"}}})
        assert res["tunnels"][0]["success"] is True
        assert "pty_upgrade" not in res
        assert res["ssh_keys"] == []
        assert res["enum_output"] == ""


class TestPipeline:
    def test_phase_pipeline(self):
        o = _orch()
        pr = {
            "asset_graph": {"total_nodes": 3, "total_edges": 2,
                            "connected_components": 1},
            "crown_jewels": ["db", "admin"],
            "attack_chains": [{"score": 0.9, "target": "db", "hops": 2}],
            "differential": {"confirmed_on_high_value": 1,
                             "expected_high_value": 2,
                             "crown_jewel_reached": ["db"]},
        }
        with patch("tools.pipeline.run_pipeline", return_value=pr) as m:
            res = o.phase_pipeline()
        assert res is pr
        assert o.pipeline_result is pr
        assert m.call_args[0][1] == o.target


class TestRunOrchestration:
    def _prep(self, o, findings=None, ab_total=0, weaponize=None):
        o.oob_server = MagicMock()
        o.phase_recon = MagicMock(return_value={})
        o.phase_attack_plan = MagicMock(return_value={})
        o.phase_reason = MagicMock(return_value=[])
        o.phase_crawl = MagicMock(return_value={"summary": {}, "endpoints": {}})
        o.phase_mine = MagicMock(return_value={})
        o.phase_auth_bypass = MagicMock(return_value={
            "total_bypasses": ab_total, "path_bypasses": [], "cookie_bypasses": [],
            "header_bypasses": [], "method_bypasses": []})
        o.phase_detect = MagicMock(return_value=findings if findings is not None else {})
        o.phase_ai_hunt = MagicMock(return_value={})
        o.phase_pivot = MagicMock(return_value={"pivot_actions": [{"success": True}]})
        o.phase_dual_session = MagicMock(return_value={})
        o.phase_weaponize = MagicMock(return_value=weaponize or {})
        o.phase_advanced = MagicMock(return_value={})
        o.phase_pipeline = MagicMock(return_value={})
        o.phase_report = MagicMock(return_value={})

    def test_run_full_path_with_exploits(self):
        o = _orch()
        self._prep(o, findings={"k": {"type": "sqli"}}, ab_total=1,
                   weaponize={"k": {"exploit_ready": True}})
        o.phase_advanced.return_value = {"tunnels": [1], "c2_active": True,
                                         "ssh_keys": ["k"], "post_exploit": True}
        o.high_priv_sess = MagicMock()
        with patch("tools.orchestrator.PlaywrightEngine") as pw:
            pw.is_available.return_value = False
            report = o.run()
        assert "elapsed_seconds" in report
        o.oob_server.start.assert_called_once()
        o.oob_server.stop.assert_called_once()
        o.phase_dual_session.assert_called_once()
        o.phase_weaponize.assert_called_once()
        o.phase_advanced.assert_called_once()
        o.phase_pipeline.assert_called_once()
        o.phase_ai_hunt.assert_called_once()

    def test_run_without_findings_skips_weaponize(self):
        # 回归: 干净目标 (无 finding / 无 auth bypass) 不再因 exploits 未赋值
        # 抛 UnboundLocalError, 且不进入武器化/高级利用阶段.
        o = _orch()
        self._prep(o, findings={}, ab_total=0, weaponize={})
        with patch("tools.orchestrator.PlaywrightEngine") as pw:
            pw.is_available.return_value = False
            report = o.run()
        assert "elapsed_seconds" in report
        o.phase_weaponize.assert_not_called()
        o.phase_advanced.assert_not_called()
        o.phase_pipeline.assert_called_once()

    def test_run_spa_crawl_and_empty_weaponize(self):
        o = _orch()
        self._prep(o, findings={}, ab_total=1, weaponize={})
        crawl = {"summary": {"is_spa": True, "js_api_discovered": 2,
                             "pages_crawled": 1, "endpoints_found": 0,
                             "unique_params": 0},
                 "endpoints": {}}
        o.phase_crawl = MagicMock(return_value=crawl)
        spa = {"api_routes": ["/api/a"], "js_api_routes": ["/r"]}
        with patch("tools.orchestrator.PlaywrightEngine.is_available",
                   return_value=True), \
             patch("tools.orchestrator.crawl_spa", return_value=spa):
            report = o.run()
        assert crawl["spa_crawl"] is spa
        assert crawl["endpoints"]["/api/a"]["spa_api"] is True
        o.phase_advanced.assert_not_called()
        assert "elapsed_seconds" in report
        o.phase_mine.assert_called_once_with(crawl)

    def test_module_level_run_delegates(self):
        from tools.orchestrator import run as orch_run
        with patch("tools.orchestrator.Orchestrator") as mock_o:
            mock_o.return_value.run.return_value = {"ok": True}
            assert orch_run("http://t.test", sess=MagicMock()) == {"ok": True}
        mock_o.assert_called_once()
        assert mock_o.call_args[0][0] == "http://t.test"

    def test_run_spa_crawl_exception(self):
        o = _orch()
        self._prep(o, findings={}, ab_total=1, weaponize={})
        o.phase_pivot = MagicMock(return_value={"pivot_actions": []})
        crawl = {"summary": {"is_spa": True}, "endpoints": {}}
        o.phase_crawl = MagicMock(return_value=crawl)
        with patch("tools.orchestrator.PlaywrightEngine.is_available",
                   return_value=True), \
             patch("tools.orchestrator.crawl_spa",
                   side_effect=RuntimeError("browser down")):
            report = o.run()
        assert "spa_crawl" not in crawl
        assert "elapsed_seconds" in report




