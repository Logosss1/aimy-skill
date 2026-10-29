"""Offline coverage + detection-defect tests for the auto-pwn / fuzz pipeline.

Only adds tests: no source, conftest or config changes. All HTTP, clock and
randomness access is mocked, so the suite is deterministic, offline and fast.

The former ``*_defect`` tests were rewritten after the capability fixes: they
now pin the corrected behaviour and fail if a regression reintroduces the old
defect they used to document.
"""

import random
from unittest.mock import MagicMock, patch

import pytest
import requests

from tools.adaptive_payload import adapt_payload, select_payloads, suggest_additional_tests
from tools.attack_surface import (
    TECH_CVE_DB,
    build_attack_plan,
    lookup_cves,
    pivot_on_intermediate_result,
    rank_attack_paths,
    visualize_attack_paths,
)
from tools.auto_pwn import Belief, HypothesisDrivenAgent, auto_pwn
from tools.fuzz_engine import GRAMMARS, FuzzEngine, FuzzSeed, run_fuzz
from tools.param_miner import COMMON_GET_PARAMS, COMMON_POST_PARAMS, ParamMiner, mine
from tools.reasoning_engine import Hypothesis
from tools.vuln_context import VulnContext

TARGET = "http://target.test"


def _resp(status=200, text="hello body", elapsed=0.1, url="http://target.test/"):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    r.url = url
    r.elapsed.total_seconds.return_value = elapsed
    return r


def _sess():
    s = MagicMock()
    s.get.return_value = _resp()
    s.post.return_value = _resp()
    return s


def _agent(sess=None):
    return HypothesisDrivenAgent(TARGET, sess or _sess())


def _hyp(vuln_type, detail=None, param=None, confidence=0.5, priority=0):
    return Hypothesis(
        vuln_type=vuln_type,
        confidence=confidence,
        param=param,
        detail=detail or {},
        priority=priority,
    )


def _fake_ctx(**fields):
    class _Ctx:
        def __init__(self):
            self._ctx = VulnContext(**fields)

        def get(self):
            return self._ctx

    return _Ctx()


@pytest.fixture
def frozen_random(monkeypatch):
    monkeypatch.setattr(random, "choice", lambda seq: seq[0])
    monkeypatch.setattr(random, "shuffle", lambda seq: None)
    monkeypatch.setattr(random, "randint", lambda a, b: 1)


# ---------------------------------------------------------------------------
# tools/auto_pwn.py
# ---------------------------------------------------------------------------


class TestBelief:
    def test_update_success_raises_belief(self):
        b = Belief(0.5)
        b.update({"success": True, "evidence": "e"})
        assert b.belief == pytest.approx(0.65)
        assert b.evidence_for == ["e"]
        assert b.evidence_against == []

    def test_update_vulnerable_counts_as_success(self):
        b = Belief(0.5)
        b.update({"vulnerable": True})
        assert b.belief > 0.5
        assert b.evidence_against == []

    def test_update_uses_repr_when_no_evidence(self):
        b = Belief(0.5)
        b.update({"success": True})
        assert b.evidence_for[0].startswith("{")

    def test_update_failure_decays_and_records_no_result(self):
        b = Belief(0.5)
        b.update({"vulnerable": False})
        assert b.belief == pytest.approx(0.425)
        assert b.evidence_against == ["no result"]

    def test_repr(self):
        assert repr(Belief(0.5)) == "Belief(0.50)"


class TestExecuteHypothesis:
    def test_internal_pivot_200(self):
        sess = _sess()
        sess.get.return_value = _resp(200, "ok")
        result = _agent(sess).execute_hypothesis(_hyp("internal_pivot"))
        assert result["success"] is True
        assert result["detail"] == {"status": 200}

    def test_internal_pivot_non_200_fails(self):
        sess = _sess()
        sess.get.return_value = _resp(404)
        assert _agent(sess).execute_hypothesis(_hyp("internal_pivot"))["success"] is False

    def test_cve_http_get(self):
        sess = _sess()
        sess.get.return_value = _resp(200)
        h = _hyp("rce", detail={"type": "cve", "cve": "CVE-2022-22965", "exploit_type": "http_get"})
        result = _agent(sess).execute_hypothesis(h)
        assert result["success"] is True
        assert result["detail"]["cve"] == "CVE-2022-22965"
        sess.get.assert_called_once_with(TARGET, timeout=10.0)

    def test_cve_http_post_xml(self):
        sess = _sess()
        sess.post.return_value = _resp(200)
        h = _hyp(
            "deser",
            detail={"type": "cve", "cve": "CVE-2017-10271", "exploit_type": "http_post_xml"},
        )
        result = _agent(sess).execute_hypothesis(h)
        assert result["success"] is True
        assert "<?xml" in sess.post.call_args.kwargs["data"]

    def test_cve_error_status_is_not_success(self):
        sess = _sess()
        sess.get.return_value = _resp(404)
        h = _hyp("rce", detail={"type": "cve", "cve": "X", "exploit_type": "http_get"})
        assert _agent(sess).execute_hypothesis(h)["success"] is False

    def test_cve_request_exception_captured_not_vulnerable(self):
        sess = _sess()
        sess.get.side_effect = RuntimeError("net down")
        h = _hyp("rce", detail={"type": "cve", "cve": "X", "exploit_type": "http_get"})
        result = _agent(sess).execute_hypothesis(h)
        assert result["success"] is False
        assert result["detail"] == {"error": "net down"}

    @pytest.mark.parametrize("status", [503, 401])
    def test_cve_status_outside_200_399_not_counted_as_success(self, status):
        """Success requires 200 <= status < 400, so 503/401 are failures."""
        sess = _sess()
        sess.get.return_value = _resp(status, "not a usable response")
        h = _hyp("rce", detail={"type": "cve", "cve": "X", "exploit_type": "http_get"})
        result = _agent(sess).execute_hypothesis(h)
        assert result["success"] is False
        assert result["detail"] == {"status": status, "cve": "X"}

    def test_cve_unimplemented_ajp_vector_reports_note(self):
        """Ghostcat (ajp_protocol) has no implementation: it is skipped with an
        explicit note instead of falling through to the no-handler branch."""
        sess = _sess()
        h = _hyp(
            "lfi/rce",
            detail={
                "type": "cve",
                "cve": "CVE-2020-1938",
                "name": "Ghostcat",
                "exploit_type": "ajp_protocol",
            },
        )
        result = _agent(sess).execute_hypothesis(h)
        assert result == {
            "hypothesis": "lfi/rce",
            "success": False,
            "detail": {"note": "cve_vector_ajp_protocol_not_implemented", "cve": "CVE-2020-1938"},
        }
        assert sess.get.call_count == 0

    def test_cve_unimplemented_http_post_vector_skips_generic_cmdi(self):
        """Drupalgeddon2 http_post has no implementation: it must not run the
        generic cmdi detector, and must report its own skip note."""
        with patch(
            "tools.cmdi_detector.check", return_value={"vulnerable": False, "probe": "cmdi"}
        ) as check:
            h = _hyp(
                "rce",
                detail={
                    "type": "cve",
                    "cve": "CVE-2018-7600",
                    "name": "Drupalgeddon2",
                    "exploit_type": "http_post",
                },
            )
            result = _agent().execute_hypothesis(h)
        assert not check.called
        assert result["success"] is False
        assert result["detail"] == {
            "note": "cve_vector_http_post_not_implemented",
            "cve": "CVE-2018-7600",
        }

    def test_sqli_handler_and_alt_param_detection(self):
        def fake_check(url, param, sess, timeout):
            return {"vulnerable": param == "ID", "evidence": ["alt hit"]}

        with patch("tools.sql_injection.check", side_effect=fake_check):
            result = _agent().execute_hypothesis(_hyp("sql_injection", param="id"))
        assert result["vulnerable"] is True
        assert result["_found_via_alt_param"] == "ID"
        assert result["_url"] == TARGET
        assert result["_param"] == "id"

    _DETECTOR_BRANCHES = [
        ("ssrf", "tools.ssrf_detector"),
        ("lfi", "tools.lfi_scanner"),
        ("path_traversal", "tools.lfi_scanner"),
        ("cmdi", "tools.cmdi_detector"),
        ("rce", "tools.cmdi_detector"),
        ("ssti", "tools.ssti_detector"),
        ("xss", "tools.xss_detector"),
        ("jwt", "tools.jwt_detector"),
        ("deser", "tools.deserialization_detector"),
        ("xxe", "tools.xxe_detector"),
    ]

    @pytest.mark.parametrize("vtype,module", _DETECTOR_BRANCHES)
    def test_detector_branch_maps_through(self, vtype, module):
        with patch(
            module + ".check", return_value={"vulnerable": True, "evidence": ["e"]}
        ) as check:
            result = _agent().execute_hypothesis(_hyp(vtype, param="q"))
        assert check.called
        assert result["vulnerable"] is True
        assert result["_param"] == "q"
        assert result["_next_steps"]

    def test_auth_bypass_metadata_enriched(self):
        """The auth branch enriches with target/param, so _url is the target and
        _param falls back to the default 'id'."""
        with patch(
            "tools.auth_bypass.check", return_value={"vulnerable": True, "total_bypasses": 1}
        ):
            result = _agent().execute_hypothesis(_hyp("auth_bypass"))
        assert result["vulnerable"] is True
        assert result["_url"] == TARGET
        assert result["_param"] == "id"
        assert result["_next_steps"] == ["verify", "weaponize-auth"]

    def test_detector_exception_marked_not_vulnerable_defect(self):
        """DEFECT(D4): a crashed detector is indistinguishable from a clean negative."""
        with patch("tools.lfi_scanner.check", side_effect=RuntimeError("boom")):
            result = _agent().execute_hypothesis(_hyp("lfi"))
        assert result == {"vulnerable": False, "error": "boom"}

    def test_unknown_vuln_type_has_no_handler(self):
        assert _agent().execute_hypothesis(_hyp("weird"))["note"] == "no handler for weird"


class TestLearnAndHistory:
    def test_learn_records_vulnerable_result(self):
        agent = _agent()
        agent.learn(_hyp("sqli", confidence=0.6), {"vulnerable": True, "evidence": ["e"]})
        assert agent.attack_history[0]["result"] is True
        assert agent.beliefs["sqli"].belief > 0.6

    def test_learn_records_success_only_result(self):
        """success=True (no 'vulnerable' key) is stored as result=True in history."""
        sess = _sess()
        sess.get.return_value = _resp(200, "internal ok")
        agent = _agent(sess)
        h = _hyp("internal_pivot")
        agent.learn(h, agent.execute_hypothesis(h))
        assert agent.attack_history[0]["result"] is True
        assert agent.beliefs["internal_pivot"].belief > 0.5


class TestShouldContinue:
    def test_fresh_agent_continues(self):
        assert _agent().should_continue() is True

    def test_stops_at_max_iterations(self):
        agent = _agent()
        agent._iteration = 30
        assert agent.should_continue(30) is False

    def test_stops_after_ten_negative_tests(self):
        agent = _agent()
        for _ in range(12):
            agent.learn(_hyp("xss"), {"vulnerable": False})
        assert agent.should_continue() is False

    def test_recent_success_keeps_going(self):
        agent = _agent()
        for _ in range(11):
            agent.learn(_hyp("xss"), {"vulnerable": False})
        agent.learn(_hyp("xss"), {"vulnerable": True})
        assert agent.should_continue() is True


class TestRunLoop:
    def _hooked_agent(self):
        agent = _agent()
        agent.gather_intel = MagicMock(return_value={"attack_paths": []})
        agent.form_hypotheses = MagicMock(
            side_effect=lambda intel: [Hypothesis(vuln_type="sqli", confidence=0.9)]
        )
        agent.chain_engine = MagicMock()
        return agent

    def test_run_confirms_and_composes_chains(self):
        agent = self._hooked_agent()
        agent.execute_hypothesis = MagicMock(return_value={"vulnerable": True, "evidence": ["e"]})
        ok_fn, boom_fn = MagicMock(), MagicMock(side_effect=RuntimeError("chain boom"))
        agent.chain_engine.auto_compose.return_value = [
            {"chain": "sqli_to_rce", "param": "id"},
            {"chain": "boom", "param": "id"},
        ]
        agent.chain_engine._chain_map.return_value = {"sqli_to_rce": ok_fn, "boom": boom_fn}
        summary = agent.run(max_iterations=2)
        assert summary["iterations"] == 2
        assert summary["hypotheses_tested"] == 2
        assert len(summary["confirmed"]) == 2
        assert ok_fn.call_count == 2
        assert boom_fn.call_count == 2
        assert summary["beliefs"]["sqli"] == 0.95

    def test_run_continues_through_success_only_findings(self):
        """success-only results count as findings in history, so the loop keeps
        running (all 30 iterations) and lists them in the summary."""
        agent = self._hooked_agent()
        agent.execute_hypothesis = MagicMock(return_value={"success": True})
        summary = agent.run(max_iterations=30)
        assert summary["iterations"] == 30
        assert summary["hypotheses_tested"] == 30
        assert len(summary["confirmed"]) == 30
        assert all(h["result"] is True for h in summary["confirmed"])

    def test_run_without_hypotheses_does_nothing(self):
        agent = self._hooked_agent()
        agent.form_hypotheses = MagicMock(return_value=[])
        summary = agent.run()
        assert summary["iterations"] == 0
        assert summary["history"] == []


class TestGatherIntelAndHypotheses:
    def test_gather_intel_maps_orchestrator_output(self):
        sess = _sess()
        agent = HypothesisDrivenAgent(TARGET, sess)
        orch_cls = MagicMock()
        orch_cls.return_value.phase_recon.return_value = {
            "technologies": {
                "technologies": [{"id": "spring", "name": "Spring", "version": "5.3"}]
            },
            "open_ports": {"open_ports": [{"port": 445}]},
            "git_leak": {"git_exposed": True},
            "directories": {"interesting": [{"path": "/admin"}]},
        }
        with (
            patch("tools.orchestrator.Orchestrator", orch_cls),
            patch("tools.auto_pwn.full_network_scan", return_value={"total_alive": 2}) as scan,
            patch("tools.auto_pwn.rank_attack_paths", return_value=[{"type": "cve"}]) as rank,
        ):
            intel = agent.gather_intel()
        orch_cls.assert_called_once_with(TARGET, sess, 10.0, fast_recon=True)
        scan.assert_called_once_with()
        assert intel["techs"] == [{"id": "spring", "name": "Spring", "version": "5.3"}]
        assert intel["ports"] == [{"port": 445}]
        assert intel["dirs"] == [{"path": "/admin"}]
        assert intel["internal_scan"] == {"total_alive": 2}
        assert intel["attack_paths"] == [{"type": "cve"}]
        rank.assert_called_once_with(intel["techs"], intel["ports"], {"git_exposed": True})

    def test_gather_intel_swallows_all_failures_defect(self):
        """DEFECT(D4): recon/internal-scan exceptions are silently debug-logged."""
        with (
            patch("tools.orchestrator.Orchestrator", side_effect=RuntimeError("no orch")),
            patch("tools.auto_pwn.full_network_scan", side_effect=RuntimeError("no net")),
            patch("tools.auto_pwn.rank_attack_paths", return_value=[]),
        ):
            intel = _agent().gather_intel()
        assert intel["techs"] == []
        assert intel["ports"] == []
        assert "internal_scan" not in intel
        assert intel["attack_paths"] == []

    def test_form_hypotheses_orders_cve_pivot_and_reasoner(self):
        agent = _agent()
        agent.reasoner = MagicMock()
        agent.reasoner.analyze.return_value = [
            Hypothesis(vuln_type="xss", confidence=0.6, priority=2)
        ]
        intel = {
            "techs": [],
            "ports": [],
            "dirs": [],
            "git": {},
            "attack_paths": [
                {
                    "type": "cve",
                    "impact": "RCE",
                    "score": 18.0,
                    "cve": "CVE-2022-22965",
                    "name": "Spring4Shell",
                    "exploit_type": "http_get",
                }
            ],
            "internal_scan": {"total_alive": 3},
        }
        hyps = agent.form_hypotheses(intel)
        assert [h.vuln_type for h in hyps] == ["rce", "internal_pivot", "xss"]
        assert hyps[0].confidence == 0.95
        assert hyps[0].detail["cve"] == "CVE-2022-22965"
        assert hyps[1].evidence == ["3 hosts discovered"]

    def test_form_hypotheses_caps_attack_paths_at_ten(self):
        agent = _agent()
        agent.reasoner = MagicMock()
        agent.reasoner.analyze.return_value = []
        paths = [
            {
                "type": "cve",
                "impact": "RCE",
                "score": 5.0,
                "cve": "C-%d" % i,
                "name": "n",
                "exploit_type": "manual",
            }
            for i in range(12)
        ]
        assert len(agent.form_hypotheses({"attack_paths": paths})) == 10


class TestModuleAutoPwn:
    def test_auto_pwn_injects_session_and_runs(self):
        sess = _sess()
        agent_cls = MagicMock()
        agent_cls.return_value.run.return_value = {"ok": True}
        with patch("tools.auto_pwn.HypothesisDrivenAgent", agent_cls):
            out = auto_pwn(TARGET, sess=sess, timeout=3.0, max_iterations=7)
        agent_cls.assert_called_once_with(TARGET, sess, 3.0)
        agent_cls.return_value.run.assert_called_once_with(max_iterations=7)
        assert out == {"ok": True}


# ---------------------------------------------------------------------------
# tools/fuzz_engine.py
# ---------------------------------------------------------------------------


class TestFuzzSeed:
    def test_mutate_low_intensity_returns_value_only(self):
        assert FuzzSeed("abc", "sql").mutate(0.1) == ["abc"]

    def test_mutate_medium_has_case_and_doubling(self):
        out = FuzzSeed("abc", "sql").mutate(0.3)
        assert "ABC" in out and "abcabc" in out

    def test_mutate_high_adds_whitespace_and_injection(self, frozen_random):
        out = FuzzSeed("1=1", "sql").mutate(0.8)
        assert "\t1=1" in out
        assert "1=1\n" in out
        assert "1=1 OR 1=1" in out
        assert "1' 1=1" in out


class TestSeedPoolAndGenerate:
    def test_init_seeds_covers_all_grammars(self):
        engine = FuzzEngine(_sess())
        assert set(engine.seed_pool) == set(GRAMMARS)
        for vt, seeds in engine.seed_pool.items():
            assert seeds
            assert all(s.vuln_type == vt for s in seeds)

    def test_generate_known_type_uses_its_grammar(self, frozen_random):
        payloads = FuzzEngine(_sess()).generate("sql", count=6)
        assert len(payloads) == 6
        assert set(payloads) == {"' OR 1=1 --", "' or 1=1 --", "' OR 1=1 --' OR 1=1 --"}
        assert all("1 1 1" not in p for p in payloads)

    def test_templates_with_unknown_placeholders_are_skipped(self, frozen_random):
        """Templates referencing placeholders that have no grammar pool are skipped
        entirely, so no seed is rendered with a bogus '1' filler."""
        engine = FuzzEngine(_sess())
        sql_templates = [s.value for s in engine.seed_pool["sql"] if s.grammar]
        cmdi_templates = [s.value for s in engine.seed_pool["cmdi"] if s.grammar]
        assert sql_templates == ["' OR 1=1 --"]
        assert cmdi_templates == ["|id", "`id`", "$(id)"]
        assert all("1 1 1" not in s.value for s in engine.seed_pool["sql"])

    def test_generate_unknown_type_returns_empty(self, frozen_random):
        """A vuln type without a grammar returns [] instead of SQL payloads."""
        assert FuzzEngine(_sess()).generate("open_redirect", count=4) == []

    def test_generate_without_any_seed_returns_empty(self):
        engine = FuzzEngine(_sess())
        engine.seed_pool = {}
        assert engine.generate("sql", count=5) == []

    def test_init_seeds_skips_broken_template_but_keeps_value_seeds(self, monkeypatch):
        monkeypatch.setattr(random, "choice", MagicMock(side_effect=RuntimeError("no candidate")))
        engine = FuzzEngine(_sess())
        assert engine.seed_pool["sql"]
        assert all(s.grammar is None for s in engine.seed_pool["sql"])


class TestGenerateHybrid:
    def test_param_map_path_and_hints_select_vuln_types(self):
        engine = FuzzEngine(_sess())
        engine.generate = MagicMock(side_effect=lambda vt, count=5: ["P:%s" % vt])
        out = engine.generate_hybrid("q", "/api/v1/login", ["MySQL", "php", "spring"])
        kinds = {p.split(":", 1)[1] for p in out}
        assert {"sql", "xss", "ssti", "ssrf", "cmdi", "lfi", "deser", "el"} <= kinds
        assert len(out) <= 30

    def test_url_param_selects_grammarless_types(self):
        engine = FuzzEngine(_sess())
        engine.generate = MagicMock(side_effect=lambda vt, count=5: ["P:%s" % vt])
        out = engine.generate_hybrid("url")
        kinds = {p.split(":", 1)[1] for p in out}
        assert {"ssrf", "open_redirect"} <= kinds

    def test_upload_path_adds_lfi_and_cmdi(self):
        engine = FuzzEngine(_sess())
        engine.generate = MagicMock(side_effect=lambda vt, count=5: ["P:%s" % vt])
        out = engine.generate_hybrid("notmapped", "/upload/file")
        kinds = {p.split(":", 1)[1] for p in out}
        assert {"lfi", "cmdi", "sql", "xss"} <= kinds


class TestTestPayloads:
    def test_status_change_marks_interesting(self):
        sess = _sess()
        sess.get.side_effect = [_resp(200, "A" * 10), _resp(500, "boom")]
        engine = FuzzEngine(sess)
        results = engine.test_payloads(TARGET + "/x", "id", ["%s" % "1' OR 1=1--"])
        assert len(results) == 1
        assert results[0]["interesting"] is True
        assert results[0]["body_preview"] == "boom"
        assert len(engine.interesting_inputs) == 1

    def test_large_size_change_marks_interesting(self):
        sess = _sess()
        sess.get.side_effect = [_resp(200, "A" * 10), _resp(200, "B" * 100)]
        results = FuzzEngine(sess).test_payloads(TARGET + "/x", "id", ["p"])
        assert results[0]["size_ratio"] == pytest.approx(10.0)
        assert results[0]["interesting"] is True

    def test_time_delay_marks_interesting(self):
        sess = _sess()
        sess.get.side_effect = [_resp(200, "A" * 10, 0.1), _resp(200, "A" * 10, 4.0)]
        results = FuzzEngine(sess).test_payloads(TARGET + "/x", "id", ["sleep"])
        assert results[0]["interesting"] is True

    def test_identical_response_not_interesting(self):
        sess = _sess()
        sess.get.side_effect = [_resp(200, "A" * 10), _resp(200, "A" * 10)]
        engine = FuzzEngine(sess)
        results = engine.test_payloads(TARGET + "/x", "id", ["p"])
        assert results[0]["interesting"] is False
        assert engine.interesting_inputs == []

    def test_timeout_and_error_payloads_recorded(self):
        """A timed-out payload is kept as an interesting entry (possible
        time-based injection); other exceptions become error entries, so no
        payload vanishes silently."""
        sess = _sess()
        sess.get.side_effect = [
            _resp(200, "A"),
            _resp(200, "ok"),
            requests.Timeout("slow"),
            RuntimeError("boom"),
        ]
        engine = FuzzEngine(sess)
        results = engine.test_payloads(TARGET, "id", ["first", "slow", "bad"])
        assert [r["payload"] for r in results] == ["first", "slow", "bad"]
        timeout_res, error_res = results[1], results[2]
        assert timeout_res["interesting"] is True
        assert timeout_res["note"] == "timeout (possible time-based)"
        assert timeout_res["status"] == 0
        assert engine.interesting_inputs == [timeout_res]
        assert error_res == {"payload": "bad", "error": "boom", "interesting": False}

    def test_baseline_failure_skips_diff_and_size_checks(self):
        """When the baseline request fails, diff/size judgements are skipped, so a
        normal response is no longer flagged as interesting."""
        sess = _sess()
        sess.get.side_effect = [RuntimeError("no route"), _resp(200, "12345")]
        engine = FuzzEngine(sess)
        results = engine.test_payloads(TARGET, "id", ["p"])
        assert results[0]["interesting"] is False
        assert "body_preview" not in results[0]
        assert engine.interesting_inputs == []

    def test_baseline_status_argument_ignored_defect(self):
        """DEFECT(D8): the baseline_status parameter is never used by the engine."""
        sess = _sess()
        sess.get.side_effect = [_resp(200, "A" * 10), _resp(500, "boom")]
        results = FuzzEngine(sess).test_payloads(TARGET, "id", ["p"], baseline_status=500)
        assert results[0]["interesting"] is True  # 500 == caller-declared baseline


class TestFuzzEndpointAndBatch:
    @staticmethod
    def _engine(responses):
        sess = _sess()
        sess.get.side_effect = responses
        return FuzzEngine(sess)

    def test_fuzz_endpoint_counts(self):
        engine = self._engine([_resp(200, "A"), _resp(500, "x"), _resp(500, "y")])
        engine.generate_hybrid = MagicMock(return_value=["a", "b"])
        out = engine.fuzz_endpoint(TARGET + "/p", "id")
        assert out["payloads_tested"] == 2
        assert out["interesting"] == 2
        assert len(out["interesting_results"]) == 2

    def test_fuzz_endpoint_truncates_interesting_list_to_ten(self):
        payloads = ["p%d" % i for i in range(12)]
        engine = self._engine([_resp(200, "A")] + [_resp(500, str(i)) for i in range(12)])
        engine.generate_hybrid = MagicMock(return_value=payloads)
        out = engine.fuzz_endpoint(TARGET + "/p", "id")
        assert out["payloads_tested"] == 12
        assert out["interesting"] == 12
        assert len(out["interesting_results"]) == 10
        assert len(out["all_results"]) == 12

    def test_fuzz_batch_skips_endpoints_without_url_or_param(self):
        engine = self._engine([_resp(200, "A"), _resp(200, "A")])
        engine.generate_hybrid = MagicMock(return_value=["x"])
        out = engine.fuzz_batch(
            [
                {"url": TARGET + "/a", "param": "id"},
                {"url": "", "param": "id"},
                {"url": TARGET + "/b"},
            ]
        )
        assert out["endpoints_fuzzed"] == 1
        assert out["total_payloads"] == 1
        assert out["total_interesting"] == 0

    def test_run_fuzz_dispatches_batch(self):
        with patch.object(FuzzEngine, "fuzz_batch", return_value={"b": 1}) as batch:
            out = run_fuzz(_sess(), TARGET, endpoints=[{"url": "u", "param": "p"}])
        batch.assert_called_once()
        assert out == {"b": 1}

    def test_run_fuzz_defaults_to_single_endpoint(self):
        with patch.object(FuzzEngine, "fuzz_endpoint", return_value={"e": 1}) as single:
            out = run_fuzz(_sess(), TARGET)
        single.assert_called_once_with(TARGET, "id")
        assert out == {"e": 1}


# ---------------------------------------------------------------------------
# tools/adaptive_payload.py
# ---------------------------------------------------------------------------


class TestAdaptPayload:
    @pytest.mark.parametrize(
        "dbms,first",
        [
            ("MySQL 8.0", "sleep"),
            ("PostgreSQL 14", "pg_sleep"),
            ("MSSQL", "waitfor"),
            ("Microsoft SQL Server 2019", "waitfor"),
            ("Oracle 19c", "dbms_pipe"),
        ],
    )
    def test_sqli_dbms_profiles(self, dbms, first):
        assert adapt_payload("sqli", _fake_ctx(dbms=dbms))["preferred"][0] == first

    def test_sqli_no_dbms_uses_generic_sleeps(self):
        hints = adapt_payload("sqli", _fake_ctx())
        assert hints["preferred"] == ["sleep", "pg_sleep", "waitfor"]

    def test_sqli_debug_mode_custom(self):
        hints = adapt_payload("sqli", _fake_ctx(dbms="mysql", has_debug_mode=True))
        assert "stacked_queries_for_debug" in hints["custom"]

    @pytest.mark.parametrize(
        "cloud,first,custom",
        [
            ("AWS", "169.254.169.254", "imdsv2_token"),
            ("GCP", "metadata.google.internal", "Metadata-Flavor: Google"),
            ("Azure", "169.254.169.254/metadata/instance", "api-version=2021-02-01"),
            ("Alibaba", "100.100.100.200", None),
        ],
    )
    def test_ssrf_cloud_profiles(self, cloud, first, custom):
        hints = adapt_payload("ssrf", _fake_ctx(cloud_provider=cloud))
        assert hints["preferred"][0] == first
        if custom:
            assert custom in hints["custom"]

    def test_ssrf_generic_and_admin_panel(self):
        hints = adapt_payload("ssrf", _fake_ctx(has_admin_panel=True))
        assert "file:///etc/passwd" in hints["preferred"]
        assert "internal_admin_portal_scan" in hints["custom"]

    def test_lfi_os_and_safe_chars(self):
        win = adapt_payload("lfi", _fake_ctx(os_type="Windows Server"))
        assert win["preferred"][0] == "c:/windows/win.ini"
        lin = adapt_payload("lfi", _fake_ctx(sqli_safe_chars=["/"]))
        assert lin["preferred"][0] == "/etc/passwd"
        assert "use_sqli_safe_chars_in_path" in lin["custom"]

    def test_cmdi_profiles(self):
        win = adapt_payload("cmdi", _fake_ctx(os_type="Windows", waf_name="WAF"))
        assert "ipconfig" in win["preferred"]
        assert "waf_bypass_for_cmdi" in win["custom"]
        assert adapt_payload("cmdi", _fake_ctx())["preferred"][0] == "id"

    @pytest.mark.parametrize(
        "engine,first",
        [
            ("Jinja2", "{{config}}"),
            ("FreeMarker", "${7*7}"),
            ("Velocity", "#set($x=7*7)$x"),
            ("SpEL", "${7*7}"),
            ("Spring", "${7*7}"),
            ("Smarty", "{$smarty.version}"),
        ],
    )
    def test_ssti_engine_profiles(self, engine, first):
        assert adapt_payload("ssti", _fake_ctx(ssti_engine=engine))["preferred"][0] == first

    def test_ssti_default(self):
        hints = adapt_payload("ssti", _fake_ctx())
        assert hints["preferred"] == ["{{7*7}}", "${7*7}", "{{7*'7'}}"]

    def test_deser_frameworks_and_versions(self):
        spring = adapt_payload(
            "deser",
            _fake_ctx(frameworks=["Spring Boot 2.7"], discovered_versions={"jackson": "2.9"}),
        )
        assert spring["preferred"][0] == "jackson"
        assert "jackson=2.9" in spring["custom"]
        assert adapt_payload("deser", _fake_ctx(frameworks=["Struts2"]))["preferred"][0] == "ognl"
        shiro = adapt_payload("deser", _fake_ctx(frameworks=["Shiro"]))
        assert shiro["preferred"][0] == "rememberme"

    def test_unknown_type_returns_empty_hints(self):
        hints = adapt_payload("xss", _fake_ctx(dbms="mysql"))
        assert hints == {"preferred": [], "avoid": [], "custom": []}


class TestSelectPayloads:
    POOL = [
        {"payload": "pg_sleep(5)"},
        {"payload": "sleep(5)"},
        {"payload": "nonblocking"},
        {"payload": "waitfor delay"},
        {"payload": "plain"},
    ]

    def test_mysql_preferred_ranked_first(self):
        out = select_payloads("sqli", _fake_ctx(dbms="mysql"), self.POOL)
        assert out[0]["payload"] == "sleep(5)"

    def test_avoided_payload_excluded(self):
        """Payloads matching the avoid list (wrong DBMS) are dropped entirely,
        not just ranked lower."""
        out = select_payloads("sqli", _fake_ctx(dbms="mysql"), self.POOL)
        payloads = [p["payload"] for p in out]
        assert "pg_sleep(5)" not in payloads
        assert "waitfor delay" not in payloads
        assert payloads == ["sleep(5)", "nonblocking", "plain"]

    def test_no_hints_returns_up_to_ten(self):
        """With no preferred hints the pool is returned up to a cap of 10."""
        pool = [{"payload": "p%d" % i} for i in range(8)]
        assert len(select_payloads("xss", _fake_ctx(), pool)) == 8

    def test_scored_result_capped_at_ten(self):
        pool = [{"payload": "sleep %d" % i} for i in range(15)]
        assert len(select_payloads("sqli", _fake_ctx(dbms="mysql"), pool)) == 10

    def test_custom_hint_adds_score(self):
        pool = [{"payload": "plain"}, {"payload": "spring=5.3"}]
        out = select_payloads(
            "deser", _fake_ctx(frameworks=["spring"], discovered_versions={"spring": "5.3"}), pool
        )
        assert out[0]["payload"] == "spring=5.3"


class TestSuggestAdditionalTests:
    def test_sqli_lowercase_dbms(self):
        out = suggest_additional_tests("sqli", _fake_ctx(dbms="mysql", has_debug_mode=True))
        assert "try_debug_sqli_stack" in out
        assert "try_into_outfile" in out
        assert suggest_additional_tests("sqli", _fake_ctx(dbms="mssql")) == ["enable_xp_cmdshell"]

    def test_sqli_uppercase_dbms_matched(self):
        """The dbms check is case-insensitive: 'MSSQL'/'MySQL' trigger their advice."""
        assert suggest_additional_tests("sqli", _fake_ctx(dbms="MSSQL")) == ["enable_xp_cmdshell"]
        assert suggest_additional_tests("sqli", _fake_ctx(dbms="MySQL")) == ["try_into_outfile"]

    def test_ssrf_lfi_cmdi_suggestions(self):
        assert suggest_additional_tests(
            "ssrf", _fake_ctx(cloud_provider="aws", has_admin_panel=True)
        ) == ["extract_cloud_credentials", "scan_internal_services"]
        lfi = suggest_additional_tests(
            "lfi",
            _fake_ctx(
                lfi_readable_paths=["/var/log/nginx.log", "/proc/self/environ"], frameworks=["PHP"]
            ),
        )
        assert "try_log_poison_rce" in lfi
        assert "try_ssh_key_extraction" in lfi
        assert "try_php_filter_wrapper" in lfi
        cmdi = suggest_additional_tests("cmdi", _fake_ctx(has_file_upload=True, dbms="mysql"))
        assert cmdi == ["upload_reverse_shell", "try_os_command_via_database"]

    def test_no_suggestions_for_unknown_type(self):
        assert suggest_additional_tests("xss", _fake_ctx(has_debug_mode=True)) == []


# ---------------------------------------------------------------------------
# tools/param_miner.py
# ---------------------------------------------------------------------------


class TestParamMinerProbe:
    @staticmethod
    def _frozen_time(monkeypatch):
        monkeypatch.setattr("time.time", lambda: 1000.0)

    def test_baseline_success(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "root page")
        base = ParamMiner(TARGET, sess)._baseline(TARGET + "/x")
        assert base["status"] == 200
        assert base["length"] == len("root page")
        assert base["url"] == "http://target.test/"

    def test_baseline_failure_returns_zero_probe(self):
        sess = _sess()
        sess.get.side_effect = RuntimeError("down")
        assert ParamMiner(TARGET, sess)._baseline(TARGET)["status"] == 0

    def test_test_param_get_reflected(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "hello test_0_q world")
        result = ParamMiner(TARGET, sess)._test_param(TARGET + "/x", "q")
        assert result["reflected"] is True
        assert result["preview"].startswith("hello")

    def test_test_param_get_not_reflected(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "x" * 50)
        assert ParamMiner(TARGET, sess)._test_param(TARGET + "/x", "q")["reflected"] is False

    def test_test_param_short_body(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "abc")
        assert ParamMiner(TARGET, sess)._test_param(TARGET + "/x", "q")["reflected"] is False

    def test_test_param_post_uses_form_data(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.post.return_value = _resp(200, "ok test_0_user")
        result = ParamMiner(TARGET, sess)._test_param(TARGET + "/login", "user", "POST")
        assert result["method"] == "POST"
        assert sess.post.call_args.kwargs["data"] == {"user": "test_0_user"}

    def test_test_param_error_path(self):
        sess = _sess()
        sess.get.side_effect = RuntimeError("boom")
        result = ParamMiner(TARGET, sess)._test_param(TARGET, "id")
        assert result["error"] == "request failed"
        assert result["status"] == 0

    def test_reflection_beyond_2000_chars_found(self, monkeypatch):
        """Reflection is searched in the full body, not only the first 2000 chars."""
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "B" * 2500 + "test_0_q")
        result = ParamMiner(TARGET, sess)._test_param(TARGET + "/x", "q")
        assert result["reflected"] is True
        assert result["preview"] == "B" * 200

    def test_get_http_lazy_session_defaults(self):
        with patch("tools.param_miner.requests.Session") as session_cls:
            m = ParamMiner(TARGET)
            http = m._get_http()
            again = m._get_http()
        session_cls.assert_called_once()
        assert http is again
        http.headers.__setitem__.assert_called_once_with("User-Agent", "Mozilla/5.0")

    def test_get_http_uses_supplied_session(self):
        sess = _sess()
        m = ParamMiner(TARGET, sess)
        assert m._get_http() is sess
        sess.headers.__setitem__.assert_called_once_with("User-Agent", "Mozilla/5.0")


class TestParamMinerBatch:
    @staticmethod
    def _frozen_time(monkeypatch):
        monkeypatch.setattr("time.time", lambda: 1000.0)

    def test_identical_200_response_not_reported(self, monkeypatch):
        """A param that leaves a constant 200 response unchanged is not 'found'."""
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "A" * 100)
        found = ParamMiner(TARGET, sess).mine_get(TARGET + "/x", ["ghost_param"])
        assert found == []
        assert sess.get.call_count == 2  # baseline + probe

    def test_identical_404_response_excluded(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(404, "not found")
        assert ParamMiner(TARGET, sess).mine_get(TARGET + "/x", ["ghost"]) == []

    def test_size_change_sets_different(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.side_effect = [_resp(200, "A" * 100), _resp(200, "A" * 50)]
        found = ParamMiner(TARGET, sess).mine_get(TARGET + "/x", ["p"])
        assert found[0]["different"] is True

    def test_threaded_batch_excludes_identical_200_params(self, monkeypatch):
        """Threaded mining probes every param but reports none of the unchanged
        200 responses (the old inclusion clause reported all four)."""
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "A" * 100)
        found = ParamMiner(TARGET, sess, threads=2).mine_get(TARGET + "/x", ["a", "b", "c", "d"])
        assert found == []
        assert sess.get.call_count == 5  # 1 baseline + 4 probes

    def test_delay_sleeps_between_probes(self, monkeypatch):
        self._frozen_time(monkeypatch)
        sleep = MagicMock()
        monkeypatch.setattr("time.sleep", sleep)
        sess = _sess()
        sess.get.return_value = _resp(200, "A" * 100)
        ParamMiner(TARGET, sess, delay=0.1).mine_get(TARGET + "/x", ["a", "b"])
        assert sleep.call_count == 2

    def test_post_mining_uses_post_baseline(self, monkeypatch):
        """POST probes are diffed against a POST baseline (data={}), so a
        constant empty POST body is not reported as a find."""
        self._frozen_time(monkeypatch)
        sess = _sess()
        sess.get.return_value = _resp(200, "G" * 5000)
        sess.post.return_value = _resp(200, "")
        found = ParamMiner(TARGET, sess).mine_post(TARGET + "/login", ["username"])
        assert found == []
        assert sess.get.call_count == 0
        assert sess.post.call_args_list[0].kwargs["data"] == {}
        assert sess.post.call_args_list[1].kwargs["data"] == {"username": "test_0_username"}


class TestParamMinerMine:
    def test_mine_get_defaults_to_common_list(self):
        m = ParamMiner(TARGET, _sess())
        m._batch_test = MagicMock(return_value=[])
        assert m.mine_get(TARGET + "/x") == []
        m._batch_test.assert_called_once_with(TARGET + "/x", COMMON_GET_PARAMS, "GET")

    def test_mine_post_defaults_to_common_list(self):
        m = ParamMiner(TARGET, _sess())
        m._batch_test = MagicMock(return_value=[])
        m.mine_post(TARGET + "/x")
        m._batch_test.assert_called_once_with(TARGET + "/x", COMMON_POST_PARAMS, "POST")

    def test_mine_endpoint_merges_get_post_and_known(self):
        m = ParamMiner(TARGET, _sess())
        m.mine_get = MagicMock(return_value=[{"param": "a"}])
        m.mine_post = MagicMock(return_value=[{"param": "b"}])
        out = m.mine_endpoint(TARGET + "/x", ["a", "c"])
        assert out["total_found"] == 3
        assert out["all_params"] == ["a", "b", "c"]

    def test_mine_all_sequential_uses_endpoint_url_or_base(self):
        m = ParamMiner(TARGET, _sess())
        m.mine_endpoint = MagicMock(return_value={"url": "?"})
        out = m.mine_all({"/a": {"params": ["p"]}, "/b": {"url": "http://other/b"}})
        assert set(out) == {"/a", "/b"}
        calls = [c.args for c in m.mine_endpoint.call_args_list]
        assert (TARGET + "/a", ["p"]) in calls
        assert ("http://other/b", []) in calls

    def test_mine_all_threaded(self):
        m = ParamMiner(TARGET, _sess(), threads=2)
        m.mine_endpoint = MagicMock(return_value={})
        assert set(m.mine_all({"/a": {}, "/b": {}})) == {"/a", "/b"}

    def test_mine_all_empty(self):
        assert ParamMiner(TARGET, _sess()).mine_all({}) == {}

    def test_run_defaults_to_root_endpoint(self):
        m = ParamMiner(TARGET, _sess())
        m.mine_all = MagicMock(return_value={})
        m.run()
        m.mine_all.assert_called_once_with({"/": {"url": TARGET, "methods": ["GET"], "params": []}})

    def test_module_mine_builds_miner(self):
        sess = _sess()
        with patch("tools.param_miner.ParamMiner") as miner_cls:
            miner_cls.return_value.run.return_value = {"ok": 1}
            out = mine(TARGET, endpoints={"/a": {}}, sess=sess, timeout=5.0, threads=3, delay=0.5)
        miner_cls.assert_called_once_with(TARGET, sess, 5.0, 3, 0.5)
        miner_cls.return_value.run.assert_called_once_with({"/a": {}})
        assert out == {"ok": 1}


# ---------------------------------------------------------------------------
# tools/attack_surface.py
# ---------------------------------------------------------------------------


class TestLookupCves:
    def test_version_range_match_and_exploit_metadata(self):
        hits = lookup_cves("spring", "5.3.20")
        assert {h["cve"] for h in hits} == {"CVE-2022-22965", "CVE-2022-22963", "CVE-2022-22950"}
        top = [h for h in hits if h["cve"] == "CVE-2022-22965"][0]
        assert top["exploit_available"] is True
        assert top["difficulty"] == "easy"
        assert top["exploit_type"] == "http_get"

    def test_missing_version_returns_all_entries(self):
        assert len(lookup_cves("spring")) == len(TECH_CVE_DB["spring"]) == 4

    def test_non_numeric_version_returns_all_with_unconfirmed_flag(self):
        """An unparseable version ('unknown' or '') enables the lookup for every
        entry and marks each hit with version_unconfirmed=True."""
        hits = lookup_cves("spring", "unknown")
        assert len(hits) == len(TECH_CVE_DB["spring"]) == 4
        assert all(h["version_unconfirmed"] is True for h in hits)
        assert {h["cve"] for h in lookup_cves("spring", "")} == {h["cve"] for h in hits}
        assert all(h["version_unconfirmed"] is False for h in lookup_cves("spring", "5.3.20"))

    def test_range_end_is_exclusive(self):
        """Ranges are half-open [start, end): tomcat 10 no longer matches ranges
        ending at 10, while tomcat 9 matches both of its ranges."""
        hits = {h["cve"] for h in lookup_cves("tomcat", "10.0.27")}
        assert hits == {"CVE-2021-42340"}
        assert "CVE-2020-1938" not in hits and "CVE-2020-13935" not in hits
        assert {h["cve"] for h in lookup_cves("tomcat", "9.0.5")} == {
            "CVE-2020-1938",
            "CVE-2020-13935",
        }

    def test_unknown_tech_returns_empty(self):
        assert lookup_cves("apache", "2.4") == []


class TestRankAttackPaths:
    def test_cve_score_includes_exploit_and_easy_bonus(self):
        top = rank_attack_paths([{"id": "spring", "version": "5.3.20"}], [])[0]
        assert top["cve"] == "CVE-2022-22965"
        assert top["score"] == 18.0
        assert top["type"] == "cve"

    def test_open_port_paths_from_attack_map(self):
        paths = rank_attack_paths([], [{"port": 445}, {"port": 12345}])
        assert {p["check"] for p in paths} == {"smb_null_session", "smb_eternal_blue"}
        assert all(p["score"] == 8 and p["impact"] == "RCE" for p in paths)

    def test_git_leak_path_scored_by_sensitive_count(self):
        paths = rank_attack_paths([], [], {"git_exposed": True, "sensitive_finds": ["a", "b", "c"]})
        assert paths[0]["type"] == "git_leak"
        assert paths[0]["score"] == 10

    def test_paths_sorted_by_score_descending(self):
        paths = rank_attack_paths([{"id": "spring", "version": "5.3"}], [{"port": 3306}])
        scores = [p["score"] for p in paths]
        assert scores == sorted(scores, reverse=True)


class TestVisualizeAttackPaths:
    def test_empty(self):
        assert visualize_attack_paths([]) == "No attack paths identified."

    def test_structural_scores_get_expected_labels(self):
        text = visualize_attack_paths(
            [
                {
                    "type": "open_port",
                    "port": 445,
                    "module": "smb",
                    "check": "smb_null_session",
                    "score": 8,
                    "impact": "RCE",
                },
                {"type": "git_leak", "score": 9, "sensitive_finds": 2, "impact": "Data Exfil"},
            ]
        )
        assert "[HIGH] Port 445" in text
        assert "[CRIT] .git leak" in text

    def test_high_score_cve_rendered_as_crit(self):
        """Score thresholds are >=9 [CRIT] / >=7 [HIGH] / >=5 [MED] / else [LOW],
        so an 18.0 CVSS path is rendered [CRIT] instead of [LOW]."""
        text = visualize_attack_paths(
            [
                {
                    "type": "cve",
                    "cve": "CVE-2022-22965",
                    "name": "Spring4Shell",
                    "impact": "RCE",
                    "score": 18.0,
                    "exploit_type": "http_get",
                }
            ]
        )
        assert "[CRIT]" in text
        assert "[LOW]" not in text

    @pytest.mark.parametrize(
        "score,label",
        [
            (9, "[CRIT]"),
            (7, "[HIGH]"),
            (5, "[MED]"),
            (4.9, "[LOW]"),
            (0, "[LOW]"),
        ],
    )
    def test_score_band_boundaries(self, score, label):
        text = visualize_attack_paths(
            [
                {
                    "type": "cve",
                    "cve": "C-1",
                    "name": "n",
                    "impact": "RCE",
                    "score": score,
                    "exploit_type": "manual",
                }
            ]
        )
        assert label in text

    def test_output_capped_at_fifteen_paths(self):
        paths = [
            {
                "type": "cve",
                "cve": "C-%d" % i,
                "name": "n",
                "impact": "RCE",
                "score": 5,
                "exploit_type": "manual",
            }
            for i in range(20)
        ]
        assert len(visualize_attack_paths(paths).splitlines()) == 16


class TestBuildAttackPlan:
    def test_full_plan_scores_and_dedupes(self):
        plan = build_attack_plan(
            {
                "target": TARGET,
                "technologies": [{"id": "spring", "name": "Spring", "version": "5.3"}],
                "open_ports": [{"port": 445}],
                "git_leak": {"git_exposed": True, "sensitive_finds": ["a", "b"]},
            }
        )
        assert plan["target"] == TARGET
        assert [p["phase"] for p in plan["phases"]] == ["tech_specific", "open_port", "git_leak"]
        assert plan["critical_paths"] == ["/actuator", "/swagger-resources"]
        assert plan["recommended_detectors"] == ["ssti", "deser", "ssrf", "sql_injection"]
        assert plan["risk_score"] == 25

    def test_no_tech_detected_falls_back_to_generic(self):
        plan = build_attack_plan({})
        assert plan["phases"][0]["phase"] == "generic"
        assert len(plan["recommended_detectors"]) == 11

    def test_port_only_plan_keeps_generic_fallback(self):
        plan = build_attack_plan({"open_ports": [{"port": 9200}]})
        phases = [p["phase"] for p in plan["phases"]]
        assert phases[0] == "open_port" and "generic" in phases
        assert plan["risk_score"] == 3

    def test_medium_port_adds_one_to_risk_score(self):
        plan = build_attack_plan({"open_ports": [{"port": 80}]})
        assert plan["risk_score"] == 1
        assert [p.get("module") for p in plan["phases"]] == ["http", None]

    def test_unmapped_tech_falls_back_to_generic(self):
        """A detected but unmapped stack (apache) now gets the generic broad
        scan instead of an empty plan."""
        plan = build_attack_plan({"technologies": [{"id": "apache", "name": "Apache"}]})
        assert [p["phase"] for p in plan["phases"]] == ["generic"]
        assert plan["recommended_detectors"] == [
            "sql_injection",
            "xss",
            "lfi",
            "ssrf",
            "cmdi",
            "ssti",
            "cors",
            "jwt",
            "graphql",
            "nosqli",
            "proto_pollution",
        ]

    def test_subdomains_and_directories_discarded_defect(self):
        """DEFECT(D18): subdomains/directories go into dead locals (lines 357/360)."""
        plan = build_attack_plan(
            {"target": TARGET, "subdomains": ["a.target.test"], "directories": [{"path": "/admin"}]}
        )
        assert "a.target.test" not in str(plan)


_PIVOT_CASES = [
    ("ssrf", "ssrf_pivot"),
    ("jwt", "jwt_pivot"),
    ("sql_injection", "sqli_pivot"),
    ("sqli", "sqli_pivot"),
    ("lfi", "lfi_pivot"),
    ("deser", "deser_pivot"),
    ("auth_bypass", "auth_pivot"),
    ("auth-bypass", "auth_pivot"),
    ("graphql", "graphql_pivot"),
    ("ssti", "ssti_pivot"),
    ("xss", "xss_pivot"),
    ("rce", "rce_pivot"),
    ("cmdi", "rce_pivot"),
]


class TestPivotOnIntermediateResult:
    @pytest.mark.parametrize("vtype,phase", _PIVOT_CASES)
    def test_known_finding_types_add_pivot_phase(self, vtype, phase):
        out = pivot_on_intermediate_result(
            {"vulnerabilities": [{"type": vtype}]}, {"phases": [], "recommended_detectors": []}
        )
        assert out["pivoted"] is True
        assert out["phases"][0]["phase"] == phase

    def test_ssrf_pivot_registers_detector(self):
        out = pivot_on_intermediate_result({"vulnerabilities": [{"type": "ssrf"}]}, {"phases": []})
        assert "ssrf_pwn" in out["recommended_detectors"]

    def test_ssti_xss_rce_findings_add_pivot_phases(self):
        """ssti/xss/rce findings now add pivot phases; previously they were dropped."""
        current = {"phases": [{"phase": "generic"}]}
        out = pivot_on_intermediate_result(
            {"vulnerabilities": [{"type": "xss"}, {"type": "ssti"}, {"type": "rce"}]}, current
        )
        assert out["pivoted"] is True
        assert [p["phase"] for p in out["phases"]] == [
            "xss_pivot",
            "ssti_pivot",
            "rce_pivot",
            "generic",
        ]
        assert out["phases"][0]["trigger"] == "xss_detected"
        assert out["phases"][1]["trigger"] == "ssti_detected"
        assert out["phases"][2]["trigger"] == "rce_detected"
        assert current == {"phases": [{"phase": "generic"}]}

    def test_caller_plan_not_mutated_by_pivot(self):
        """recommended_detectors is deep-copied, so the caller's plan is untouched
        while the returned plan carries the new detector."""
        current = {"phases": [], "recommended_detectors": ["sql_injection"]}
        out = pivot_on_intermediate_result({"vulnerabilities": [{"type": "ssrf"}]}, current)
        assert current["recommended_detectors"] == ["sql_injection"]
        assert out["recommended_detectors"] == ["sql_injection", "ssrf_pwn"]
        assert out["phases"][0]["phase"] == "ssrf_pivot"
