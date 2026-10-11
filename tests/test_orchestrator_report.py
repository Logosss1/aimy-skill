"""Report assembly and persistence coverage for tools/orchestrator.py.

Companion to tests/test_orchestrator_coverage.py: focuses on phase_report,
_report_group/_report_summary/_report_recon, storage resume/save helpers and
the WAF cache. Fully offline; sessions and storages are mocks.
"""

from unittest.mock import MagicMock, patch

from tools.orchestrator import Orchestrator


def _orch(target="http://target.test", **kw):
    o = Orchestrator(target, sess=MagicMock(), **kw)
    o.oob_server = MagicMock()
    o.context_memory = MagicMock()
    o.vuln_ctx = MagicMock()
    return o


class TestReportHelpers:
    def test_report_group(self):
        findings = {
            "k1": {"type": "sqli", "url": "http://x/a", "param": "id"},
            "k2": {"type": "sqli", "url": "http://x/b", "param": "id"},
            "k3": {"type": "xss", "url": "http://x/a", "param": "q"},
        }
        by_type, by_url = Orchestrator._report_group(findings)
        assert set(by_type) == {"sqli", "xss"}
        assert len(by_type["sqli"]) == 2
        assert by_url["http://x/a"] == ["sqli", "xss"]

    def test_report_summary_empty(self):
        s = Orchestrator._report_summary({}, {}, {}, {}, {})
        assert s["vulnerabilities"] == 0
        assert s["critical"] is False
        assert s["exploit_ready_details"] == []
        assert s["param_hits"] == []

    def test_report_summary_critical_via_finding_flag(self):
        findings = {"k": {"type": "sqli", "url": "http://x/", "param": "id",
                          "result": {"rce_available": True}}}
        s = Orchestrator._report_summary(findings, {"sqli": [findings["k"]]},
                                         {"http://x/": ["sqli"]}, {}, {})
        assert s["critical"] is True
        assert s["by_type"] == {"sqli": 1}
        assert s["param_hits"] == ["http://x/?id [sqli]"]

    def test_report_summary_critical_via_auth_bypass(self):
        s = Orchestrator._report_summary({}, {}, {}, {},
                                         {"total_bypasses": 2})
        assert s["critical"] is True
        assert s["exploit_ready_details"] == ["auth_bypass(2)"]

    def test_report_summary_exploit_ready(self):
        exploits = {"e1": {"exploit_ready": True},
                    "e2": {"exploit_ready": False}}
        s = Orchestrator._report_summary({}, {}, {}, exploits, {})
        assert s["exploit_ready"] == 2
        assert s["exploit_ready_details"] == ["e1"]
        assert s["critical"] is True

    def test_report_recon_full(self):
        recon = {
            "technologies": {"technologies": [{"name": "PHP"}, {"name": "Nginx"}]},
            "open_ports": {"open_ports": [{"port": 80}, {"port": 443}]},
            "git_leak": {"git_exposed": True, "sensitive_finds": [{}, {}]},
            "directories": {"interesting": ["/admin"]},
            "attack_plan": {"risk_score": 7},
        }
        detection = {"test_points": 42}
        crawl_summary = {"pages_crawled": 10, "endpoints_found": 5,
                         "is_spa": True, "js_api_discovered": 3}
        mine_data = {"/": {"all_params": ["a", "b"]},
                     "/x": {"all_params": ["c"]}, "bad": "not-a-dict"}
        r = Orchestrator._report_recon(recon, detection, crawl_summary,
                                       mine_data, {"name": "cloudflare"})
        assert r["technologies"] == ["PHP", "Nginx"]
        assert r["open_ports"] == [80, 443]
        assert r["git_exposed"] is True
        assert r["git_sensitive"] == 2
        assert r["directories"] == 1
        assert r["pages_crawled"] == 10
        assert r["endpoints"] == 5
        assert r["params_mined"] == 3
        assert r["test_points"] == 42
        assert r["is_spa"] is True
        assert r["js_api_discovered"] == 3
        assert r["waf"] == "cloudflare"
        assert r["risk_score"] == 7

    def test_report_recon_defaults(self):
        r = Orchestrator._report_recon({}, {}, {}, {}, {})
        assert r["technologies"] == []
        assert r["open_ports"] == []
        assert r["git_exposed"] is False
        assert r["risk_score"] == 0
        assert r["waf"] is None


class TestPhaseReport:
    def _populate(self, o):
        o.state["phases"]["detect"] = {
            "test_points": 4,
            "findings": {
                "k1": {"type": "sqli", "url": "http://x/?id=1", "param": "id",
                       "confidence_score": 0.9, "result": {"dbms": "mysql"},
                       "second_order_verified": True},
                "k2": {"type": "xss", "url": "http://x/", "param": "q",
                       "result": {}},
            },
        }
        o.state["phases"]["weaponize"] = {"k1": {"exploit_ready": True}}
        o.state["phases"]["auth_bypass"] = {
            "vulnerable": True, "total_bypasses": 1,
            "path_bypasses": [{"path": "/admin"}]}
        o.state["phases"]["recon"] = {
            "technologies": {"technologies": [{"name": "nginx"}]},
            "open_ports": {"open_ports": [{"port": 80}]},
            "git_leak": {"git_exposed": True, "sensitive_finds": [{}]},
            "directories": {"interesting": [{"path": "/a"}]},
            "attack_plan": {"risk_score": 5},
        }
        o.state["phases"]["crawl"] = {"summary": {
            "pages_crawled": 3, "endpoints_found": 2,
            "is_spa": False, "js_api_discovered": 1}}
        o.state["phases"]["param_mine"] = {"/": {"all_params": ["a", "b"]}}
        o.state["waf"] = {"name": "cloudflare"}

    def test_phase_report_assembly(self):
        o = _orch()
        self._populate(o)
        o.attack_graph = MagicMock()
        o.attack_graph.summary.return_value = {"total_nodes": 1}
        o.context_memory.get_stats.return_value = {"entries": 2}
        o.pipeline_result = {"asset_graph": {"total_nodes": 1}}
        report = o.phase_report()
        assert report["target"] == o.target
        assert report["summary"]["vulnerabilities"] == 2
        assert report["summary"]["by_type"] == {"sqli": 1, "xss": 1}
        assert report["details"]["sqli"][0]["param"] == "id"
        assert report["exploits"] == {"k1": {"exploit_ready": True}}
        assert "vulnerable" not in report["auth_bypass"]
        assert report["auth_bypass"]["total_bypasses"] == 1
        assert report["recon"]["technologies"] == ["nginx"]
        assert report["recon"]["risk_score"] == 5
        assert report["attack_graph"] == {"total_nodes": 1}
        assert report["context_memory"] == {"entries": 2}
        assert report["pipeline"] == o.pipeline_result
        assert report["second_order_verified"] == 1
        assert o.state["phases"]["report"] is report

    def test_phase_report_without_graph_or_pipeline(self):
        o = _orch()
        self._populate(o)
        o.context_memory.get_stats.return_value = {}
        report = o.phase_report()
        assert report["attack_graph"] == {}
        assert "pipeline" not in report

    def test_phase_report_persists_to_storage(self):
        o = _orch()
        self._populate(o)
        o.context_memory.get_stats.return_value = {}
        o._storage = MagicMock()
        o._storage.session_id.return_value = "sid"
        o.phase_report()
        cur = o._storage._conn.cursor.return_value
        cur.execute.assert_called_once()
        o._storage._conn.commit.assert_called_once()

    def test_phase_report_persist_exception_swallowed(self):
        o = _orch()
        self._populate(o)
        o.context_memory.get_stats.return_value = {}
        o._storage = MagicMock()
        o._storage._conn.cursor.side_effect = RuntimeError("db gone")
        report = o.phase_report()
        assert report["summary"]["vulnerabilities"] == 2


class TestStorageHelpers:
    def test_init_storage_without_resume(self):
        fake = MagicMock()
        with patch("tools.storage.SessionStore", return_value=fake) as m:
            o = _orch()
            o.init_storage(name="sess1", resume=False)
        m.assert_called_once_with("sess1")
        assert o._storage is fake
        assert o._storage_name == "sess1"
        o.context_memory.set_storage.assert_called_once_with(fake)
        o.vuln_ctx.set_storage.assert_called_once_with(fake)

    def test_init_storage_with_resume(self):
        fake = MagicMock()
        fake.load_all_context.return_value = {}
        fake.load_vuln_context.return_value = {}
        fake.load_all_phases.return_value = {}
        fake.load_findings.return_value = []
        fake.load_report.return_value = None
        with patch("tools.storage.SessionStore", return_value=fake):
            o = _orch()
            o.init_storage(name="sess2", resume=True)
        o.context_memory.restore.assert_not_called()
        o.vuln_ctx.restore.assert_not_called()

    def test_resume_state_restores_everything(self):
        storage = MagicMock()
        storage.load_all_context.return_value = {"framework": "Spring"}
        storage.load_vuln_context.return_value = {"dbms": "mysql"}
        storage.load_all_phases.return_value = {"recon": {"x": 1}, "bad": "str"}
        storage.load_findings.return_value = [{
            "vuln_type": "sqli", "url": "u", "param": "id",
            "detail": {"a": 1}, "confidence": 0.9}]
        storage.load_report.return_value = {"r": 1}
        o = _orch()
        o._storage = storage
        o._resume_state()
        o.context_memory.restore.assert_called_once_with({"framework": "Spring"})
        o.vuln_ctx.restore.assert_called_once_with({"dbms": "mysql"})
        assert o.state["phases"]["recon"] == {"x": 1}
        assert "bad" not in o.state["phases"]
        assert o.all_findings["sqli|u|id"]["confidence_score"] == 0.9
        assert o.all_findings["sqli|u|id"]["vulnerable"] is True
        assert o.state["report"] == {"r": 1}

    def test_save_phase_paths(self):
        o = _orch()
        o._save_phase("recon")
        o._storage = MagicMock()
        o._save_phase("recon")
        o._storage.save_phase.assert_not_called()
        o.state["phases"]["recon"] = {"a": 1}
        o._save_phase("recon")
        o._storage.save_phase.assert_called_once()
        args = o._storage.save_phase.call_args[0]
        assert args[0] == "recon"
        assert args[1]["_data"] == {"a": 1}
        o._storage.save_phase.side_effect = RuntimeError("disk full")
        o._save_phase("recon")

    def test_save_findings_paths(self):
        o = _orch()
        o._save_findings({"k": {"type": "x"}})
        o._storage = MagicMock()
        findings = {
            "high": {"type": "sqli", "url": "u", "param": "id",
                     "confidence_score": 0.9, "result": {"a": 1}},
            "low": {"type": "xss", "url": "u", "param": "q",
                    "confidence_score": 0.4, "result": {}},
            "__meta__": {"type": "meta"},
        }
        o._save_findings(findings)
        assert o._storage.save_finding.call_count == 2
        severities = {c[1]["severity"] for c in o._storage.save_finding.call_args_list}
        assert severities == {"high", "medium"}
        assert o._storage.save_finding.call_args_list[0][1]["payload"] == ""
        o._storage.save_finding.side_effect = RuntimeError("db gone")
        o._save_findings(findings)


class TestWafCache:
    def test_cache_hit(self):
        o = _orch()
        o.context_memory.get.return_value = "cloudflare"
        with patch("tools.orchestrator.waf_bypass.fingerprint_waf") as m:
            info = o._fingerprint_waf_cached()
        m.assert_not_called()
        assert info == {"name": "cloudflare"}

    def test_cache_miss_sets_memory(self):
        o = _orch()
        o.context_memory.get.return_value = None
        with patch("tools.orchestrator.waf_bypass.fingerprint_waf",
                   return_value={"name": "akamai"}) as m:
            info = o._fingerprint_waf_cached()
        m.assert_called_once()
        assert info["name"] == "akamai"
        o.context_memory.set.assert_called_once()
        assert o.context_memory.set.call_args[0][:2] == ("waf", "akamai")

    def test_cache_miss_without_name(self):
        o = _orch()
        o.context_memory.get.return_value = None
        with patch("tools.orchestrator.waf_bypass.fingerprint_waf",
                   return_value={}):
            info = o._fingerprint_waf_cached()
        assert info == {}
        o.context_memory.set.assert_not_called()
