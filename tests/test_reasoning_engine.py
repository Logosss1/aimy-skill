
from tools.reasoning_engine import (
    Hypothesis,
    ReasoningEngine,
    _dir_detail,
    _has_dir,
    _has_port,
    _has_tech,
    _has_vuln,
    _rule_graphql,
    _rule_jwt_found,
    _rule_php_lfi,
    _rule_spring_actuator,
)


class TestReasoningEngineCore:
    def test_hypothesis_defaults(self):
        h = Hypothesis(vuln_type="sqli", confidence=0.8)
        assert h.evidence == []
        assert h.priority == 5
        assert h.param is None
        d = h.to_dict()
        assert d["vuln_type"] == "sqli"
        assert d["confidence"] == 0.8

    def test_engine_initialization(self):
        engine = ReasoningEngine("http://target.test")
        assert engine.target == "http://target.test"
        assert "rce" in engine.bayesian_likelihoods
        assert engine.bayesian_likelihoods["rce"] == 0.95
        assert engine.prior_map == {}


class TestHelperFunctions:
    def test_has_tech_positive(self):
        assert _has_tech(["php 7.4", "nginx"], "php") is True

    def test_has_tech_negative(self):
        assert _has_tech(["nginx", "python"], "php") is False

    def test_has_dir_positive(self):
        assert _has_dir(["/admin", "/api"], "/api") is True

    def test_has_dir_negative(self):
        assert _has_dir(["/index", "/home"], "/api") is False

    def test_has_port_true(self):
        assert _has_port([22, 80, 443], 80) is True

    def test_has_port_false(self):
        assert _has_port([22, 443], 80) is False

    def test_has_vuln_true(self):
        assert _has_vuln({"sqli", "xss"}, "sqli") is True

    def test_has_vuln_false(self):
        assert _has_vuln({"xss", "lfi"}, "sqli") is False

    def test_dir_detail_found(self):
        dirs = [{"path": "/admin/login", "status": 200}, {"path": "/api", "status": 200}]
        result = _dir_detail(dirs, "/admin")
        assert result["path"] == "/admin/login"
        assert result["status"] == 200

    def test_dir_detail_not_found(self):
        dirs = [{"path": "/index", "status": 200}]
        assert _dir_detail(dirs, "/admin") is None


class TestReasoningEngineAnalyze:
    def _ctx(self, **overrides):
        ctx = {
            "technologies": [{"id": "php", "name": "PHP"}],
            "open_ports": [{"port": 80}],
            "directories": [{"path": "/index.php", "status": 200}],
            "git_leak": {},
            "vulnerabilities": [],
            "crawl_endpoints": {},
            "attack_plan": {},
        }
        ctx.update(overrides)
        return ctx

    def test_analyze_spring_actuator_exposed(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            technologies=[{"id": "spring", "name": "Spring Boot"}],
            directories=[{"path": "/actuator", "status": 200}],
        )
        hyps = engine.analyze(ctx)
        actuator_h = [h for h in hyps if h.vuln_type == "actuator_exposed"]
        assert len(actuator_h) == 1
        assert actuator_h[0].confidence == 0.60

    def test_analyze_spring_env_leak(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            technologies=[{"id": "spring", "name": "Spring Boot"}],
            directories=[{"path": "/actuator/env", "status": 200, "size": 5000}],
        )
        hyps = engine.analyze(ctx)
        env_h = [h for h in hyps if "env leak" in h.evidence[0]]
        assert len(env_h) == 1
        assert env_h[0].confidence == 0.95

    def test_analyze_php_lfi_chain(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            technologies=[{"id": "php", "name": "PHP"}],
            vulnerabilities=[{"type": "lfi"}],
            directories=[{"path": "/index.php", "status": 200}],
        )
        hyps = engine.analyze(ctx)
        rce_h = [h for h in hyps if h.vuln_type == "rce"]
        assert len(rce_h) == 1
        assert "PHP + LFI" in rce_h[0].evidence[0]

    def test_analyze_redis_noauth(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(open_ports=[{"port": 6379}, {"port": 80}])
        hyps = engine.analyze(ctx)
        redis_h = [h for h in hyps if h.vuln_type == "unauthorized_access" and h.detail.get("service") == "redis"]
        assert len(redis_h) == 1
        assert redis_h[0].confidence == 0.70

    def test_analyze_mysql_exposed(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(open_ports=[{"port": 3306}, {"port": 80}])
        hyps = engine.analyze(ctx)
        mysql_h = [h for h in hyps if h.vuln_type == "unauthorized_access" and h.detail.get("service") == "mysql"]
        assert len(mysql_h) == 1
        assert mysql_h[0].confidence == 0.50

    def test_analyze_docker_exposed(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(open_ports=[{"port": 2375}, {"port": 80}])
        hyps = engine.analyze(ctx)
        docker_h = [h for h in hyps if h.vuln_type == "unauthorized_access"]
        assert len(docker_h) >= 1

    def test_analyze_git_exposed(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            git_leak={"git_exposed": True, "sensitive_finds": ["/config.php"]},
        )
        hyps = engine.analyze(ctx)
        git_h = [h for h in hyps if h.vuln_type == "git_leak"]
        assert len(git_h) == 1
        assert git_h[0].confidence == 0.95

    def test_analyze_admin_panel_found(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            directories=[{"path": "/admin", "status": 200}],
        )
        hyps = engine.analyze(ctx)
        admin_h = [h for h in hyps if "admin" in h.evidence[0].lower()]
        assert len(admin_h) >= 1

    def test_analyze_graphql_detected(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            directories=[{"path": "/graphql", "status": 200}],
        )
        hyps = engine.analyze(ctx)
        gql_h = [h for h in hyps if h.vuln_type == "graphql_abuse"]
        assert len(gql_h) == 0

    def test_analyze_graphql_vuln_confirmed(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            directories=[{"path": "/graphql", "status": 200}],
            vulnerabilities=[{"type": "graphql"}],
        )
        hyps = engine.analyze(ctx)
        gql_h = [h for h in hyps if h.vuln_type == "graphql_abuse"]
        assert len(gql_h) == 1
        assert gql_h[0].confidence == 0.85

    def test_analyze_k8s_api(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(open_ports=[{"port": 6443}, {"port": 80}])
        hyps = engine.analyze(ctx)
        k8s_h = [h for h in hyps if h.detail.get("service") == "k8s_api"]
        assert len(k8s_h) == 1
        assert k8s_h[0].confidence == 0.65

    def test_analyze_jwt_found(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            directories=[{"path": "/api/auth", "status": 200}],
            vulnerabilities=[{"type": "jwt", "result": {"type": ""}}],
        )
        hyps = engine.analyze(ctx)
        jwt_h = [h for h in hyps if h.vuln_type == "jwt_exploit"]
        assert len(jwt_h) == 1
        assert jwt_h[0].confidence == 0.85

    def test_analyze_empty_context(self):
        engine = ReasoningEngine("http://target.test")
        hyps = engine.analyze({})
        assert hyps == []

    def test_analyze_hypotheses_sorted_by_priority(self):
        engine = ReasoningEngine("http://target.test")
        ctx = self._ctx(
            technologies=[{"id": "spring", "name": "Spring Boot"}],
            directories=[{"path": "/actuator/env", "status": 200}],
            open_ports=[{"port": 6379}],
        )
        hyps = engine.analyze(ctx)
        priorities = [h.priority for h in hyps]
        assert priorities == sorted(priorities)


class TestReasoningEngineUpdate:
    def test_update_with_evidence_confirmed(self):
        engine = ReasoningEngine("http://target.test")
        h = Hypothesis(vuln_type="rce", confidence=0.5, evidence=[])
        evidence = {"rce": {"vulnerable": True}}
        updated = engine.update_with_evidence([h], evidence)
        assert updated[0].confidence > 0.5

    def test_update_with_evidence_not_vulnerable(self):
        engine = ReasoningEngine("http://target.test")
        h = Hypothesis(vuln_type="rce", confidence=0.5, evidence=[])
        evidence = {"rce": {"vulnerable": False}}
        updated = engine.update_with_evidence([h], evidence)
        assert updated[0].confidence < 0.5

    def test_update_with_evidence_unknown(self):
        engine = ReasoningEngine("http://target.test")
        h = Hypothesis(vuln_type="rce", confidence=0.5, evidence=[])
        updated = engine.update_with_evidence([h], {"xss": {"vulnerable": True}})
        assert updated[0].confidence < 0.5

    def test_update_from_findings(self):
        engine = ReasoningEngine("http://target.test")
        h = Hypothesis(vuln_type="sqli", confidence=0.3, evidence=[])
        findings = {"key1": {"result": {"type": "sqli"}}}
        updated = engine.update_from_findings([h], findings)
        assert len(updated) == 1

    def test_update_confidence_high_but_no_evidence(self):
        engine = ReasoningEngine("http://target.test")
        h = Hypothesis(vuln_type="rce", confidence=0.5, evidence=[])
        updated = engine.update_with_evidence([h], {})
        assert updated[0].confidence < 0.5


class TestReasoningEngineScoring:
    def test_score_endpoint_high_value(self):
        engine = ReasoningEngine("http://target.test")
        assert engine.score_endpoint("file", []) == 0.9
        assert engine.score_endpoint("url", []) == 0.9
        assert engine.score_endpoint("id", []) == 0.9

    def test_score_endpoint_prefix(self):
        engine = ReasoningEngine("http://target.test")
        assert engine.score_endpoint("file_path", []) == 0.7
        assert engine.score_endpoint("api_key", []) == 0.9

    def test_score_endpoint_keyword(self):
        engine = ReasoningEngine("http://target.test")
        assert engine.score_endpoint("title", []) == 0.4
        assert engine.score_endpoint("category", []) == 0.4

    def test_score_endpoint_tech_bonus(self):
        engine = ReasoningEngine("http://target.test")
        assert engine.score_endpoint("random_param", ["php", "nginx"]) == 0.3

    def test_score_endpoint_default(self):
        engine = ReasoningEngine("http://target.test")
        assert engine.score_endpoint("random_param", ["nginx"]) == 0.1

    def test_score_endpoint_case_insensitive(self):
        engine = ReasoningEngine("http://target.test")
        assert engine.score_endpoint("FILE", []) == 0.9
        assert engine.score_endpoint("ID", []) == 0.9


class TestReasoningEngineChains:
    def test_suggest_detectors(self):
        engine = ReasoningEngine("http://target.test")
        hyps = [
            Hypothesis(vuln_type="sqli", confidence=0.9, suggested_detector="sqlcheck"),
            Hypothesis(vuln_type="xss", confidence=0.8, suggested_detector="xsscheck"),
        ]
        result = engine.suggest_detectors(hyps)
        assert result == ["sqlcheck", "xsscheck"]

    def test_suggest_detectors_dedup(self):
        engine = ReasoningEngine("http://target.test")
        hyps = [
            Hypothesis(vuln_type="sqli", confidence=0.9, suggested_detector="sqlcheck"),
            Hypothesis(vuln_type="xss", confidence=0.8, suggested_detector="sqlcheck"),
        ]
        result = engine.suggest_detectors(hyps)
        assert result == ["sqlcheck"]

    def test_suggest_chains(self):
        engine = ReasoningEngine("http://target.test")
        hyps = [
            Hypothesis(vuln_type="ssrf", confidence=0.9,
                       suggested_chain="ssrf_to_rce", endpoint="/fetch", param="url"),
            Hypothesis(vuln_type="xss", confidence=0.8,
                       suggested_chain="xss_to_auth", endpoint="/search", param="q"),
        ]
        confirmed = {"ssrf", "xss"}
        chains = engine.suggest_chains(hyps, confirmed)
        assert len(chains) == 2
        assert ("ssrf_to_rce", "/fetch", "url") in chains

    def test_suggest_chains_filters_unconfirmed(self):
        engine = ReasoningEngine("http://target.test")
        hyps = [
            Hypothesis(vuln_type="ssrf", confidence=0.9,
                       suggested_chain="ssrf_to_rce", endpoint="/fetch", param="url"),
        ]
        chains = engine.suggest_chains(hyps, set())
        assert len(chains) == 0

    def test_correlate_hypotheses_ssrf_lfi(self):
        engine = ReasoningEngine("http://target.test")
        hyps = [
            Hypothesis(vuln_type="ssrf", confidence=0.8, param="url"),
            Hypothesis(vuln_type="lfi", confidence=0.7, param="url"),
        ]
        merged = engine.correlate_hypotheses(hyps)
        assert len(merged) >= 1

    def test_correlate_hypotheses_no_merge(self):
        engine = ReasoningEngine("http://target.test")
        hyps = [
            Hypothesis(vuln_type="sqli", confidence=0.8, param="id"),
            Hypothesis(vuln_type="xss", confidence=0.7, param="q"),
        ]
        merged = engine.correlate_hypotheses(hyps)
        assert len(merged) == 2


class TestRuleFunctions:
    def test_rule_spring_actuator_none(self):
        ctx = {"all_techs": ["nginx"], "dirs": [], "dir_full": [], "ports": [], "port_data": [], "git": {}, "existing_vulns": [], "existing_types": set()}
        assert _rule_spring_actuator(**ctx) is None

    def test_rule_php_lfi_none(self):
        ctx = {"all_techs": ["nginx"], "dirs": [], "dir_full": [], "ports": [], "port_data": [], "git": {}, "existing_vulns": [], "existing_types": set()}
        assert _rule_php_lfi(**ctx) is None

    def test_rule_graphql_none(self):
        ctx = {"all_techs": [], "dirs": [], "dir_full": [], "ports": [], "port_data": [], "git": {}, "existing_vulns": [], "existing_types": set()}
        assert _rule_graphql(**ctx) is None

    def test_rule_jwt_none(self):
        ctx = {"all_techs": [], "dirs": [], "dir_full": [], "ports": [], "port_data": [], "git": {}, "existing_vulns": [], "existing_types": set()}
        assert _rule_jwt_found(**ctx) is None
