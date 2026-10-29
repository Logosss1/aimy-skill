"""Coverage tests for tools/attack_tree.py and tools/constraint_graph.py.

Pure in-process logic: no sockets, no subprocesses, no network.
"""

import json
from unittest import mock

import pytest

from tools.attack_tree import AttackTree, AttackTreeNode
from tools.constraint_graph import (
    Constraint,
    ConstraintBreaker,
    ConstraintGraph,
    Relationship,
    check,
)


class TestAttackTreeNode:
    def test_to_dict_rounds_and_serialises(self):
        node = AttackTreeNode(
            id="n1",
            vuln_type="sqli",
            description="desc",
            confidence=0.12345678,
            children=["c"],
            verified=True,
            chain_name="chain",
            cve_ids=["CVE-1"],
        )
        data = node.to_dict()
        assert data == {
            "id": "n1",
            "vuln_type": "sqli",
            "description": "desc",
            "confidence": 0.1235,
            "children": ["c"],
            "verified": True,
            "chain_name": "chain",
            "cve_ids": ["CVE-1"],
        }

    def test_make_id(self):
        tree = AttackTree()
        assert tree._make_id("entry_xss", 3) == "entry_xss_3"


class TestAttackTreeBuild:
    def _sample_tree(self):
        tree = AttackTree()
        tree.build_from_recon(
            technologies=["spring boot", "wordpress", "php"],
            open_ports=[6379, 3306, 2375, 9999, 5432],
            directories=["/actuator", "/wp-json", "/phpinfo"],
            vulns=[{"type": "sqli", "cve_ids": ["CVE-2022-21661"]}, {"type": "unknown"}],
        )
        return tree

    def test_branches_services_and_entries(self):
        tree = self._sample_tree()
        assert tree.root_id == "root"
        assert tree.nodes["root"].children == ["branch_web", "branch_service"]
        assert set(tree.nodes) >= {
            "branch_web",
            "branch_service",
            "entry_sqli_0",
            "entry_ssrf_1",
            "entry_sqli_2",
            "entry_xss_3",
            "entry_lfi_4",
            "svc_redis_1",
            "svc_mysql_2",
            "svc_docker_3",
        }
        assert tree.nodes["entry_sqli_0"].cve_ids == ["CVE-2022-21661"]
        assert tree.nodes["entry_sqli_0"].confidence == 0.76
        assert tree.nodes["entry_ssrf_1"].confidence == 0.95
        assert all(n.confidence > 0 for n in tree.nodes.values())

    def test_propagate_inflates_children_from_parents(self):
        tree = AttackTree()
        tree.build_from_recon([], [], [], [])
        assert tree.nodes["branch_web"].confidence == 0.95
        assert tree.nodes["branch_service"].confidence == 0.80

    def test_grandchildren_specs_expand_recursively(self):
        """模板第 4 元素为子节点列表时递归展开 (修复: 曾被误存到 chain_name)."""
        tree = AttackTree()
        tree.build_from_recon(["spring"], [], [], [])
        entry_id = next(n for n in tree.nodes if n.startswith("entry_ssrf"))
        cloud_id = entry_id + "_cloud_metadata"
        cloud = tree.nodes[cloud_id]
        assert cloud.chain_name is None
        assert cloud.children == [cloud_id + "_iam_keys", cloud_id + "_k8s_metadata"]
        assert tree.nodes[cloud_id + "_iam_keys"].chain_name == "ssrf_to_rce"
        assert tree.nodes[cloud_id + "_k8s_metadata"].chain_name == "ssrf_to_rce"

    @pytest.mark.parametrize(
        "techs, dirs, expected",
        [
            (["spring"], [], [("ssrf", 0.70)]),
            (["spring boot"], ["/actuator"], [("ssrf", 0.95)]),
            (["wordpress"], [], [("xss", 0.60)]),
            (["wordpress"], ["/wp-json"], [("sqli", 0.75), ("xss", 0.60)]),
            (["wordpress"], ["/xmlrpc"], [("sqli", 0.75), ("xss", 0.60)]),
            (["laravel"], [], [("rce", 0.60)]),
            (["laravel"], ["/ignition"], [("rce", 0.85)]),
            (["thinkphp"], [], [("sqli", 0.75), ("rce", 0.65)]),
            (["php"], [], [("lfi", 0.70)]),
            (["php"], ["/phpinfo"], [("lfi", 0.85)]),
            (["tomcat"], [], [("rce", 0.65)]),
            (["tomcat"], ["/manager/html"], [("rce", 0.85)]),
            (["weblogic"], [], [("rce", 0.85)]),
            (["struts"], [], [("rce", 0.85)]),
            (["drupal"], [], [("rce", 0.75)]),
            (["exchange"], [], [("ssrf", 0.80)]),
            (["asp.net"], [], [("lfi", 0.55)]),
            (["iis"], [], [("lfi", 0.55)]),
            (["jenkins"], [], [("rce", 0.70)]),
            ([], [], []),
        ],
    )
    def test_detect_web_exploit_paths(self, techs, dirs, expected):
        tree = AttackTree()
        found = tree._detect_web_exploit_paths(techs, dirs, set())
        assert [(f[0], f[1]) for f in found] == expected

    def test_detect_web_exploit_paths_carries_cves(self):
        tree = AttackTree()
        weblogic = tree._detect_web_exploit_paths(["weblogic"], [], set())
        assert weblogic[0][2] == ["CVE-2020-14882", "CVE-2017-10271"]
        spring = tree._detect_web_exploit_paths(["spring boot"], [], set())
        assert spring[0][2] == ["CVE-2022-22965"]


class TestAttackTreeBuilders:
    def _tree_with_parent(self):
        tree = AttackTree()
        parent = AttackTreeNode(id="p", vuln_type="p", description="parent", confidence=0.5)
        tree.add_node(parent)
        return tree, parent

    def test_build_entry_branch_unknown_type_is_noop(self):
        tree, parent = self._tree_with_parent()
        tree._build_entry_branch("does-not-exist", parent, 0)
        assert list(tree.nodes) == ["p"]

    def test_build_entry_branch_with_overrides(self):
        tree, parent = self._tree_with_parent()
        tree._build_entry_branch(
            "xss", parent, 7, overrides={"cve_ids": ["C1"]}, confidence_override=0.42
        )
        entry = tree.nodes["entry_xss_7"]
        assert parent.children == ["entry_xss_7"]
        assert entry.confidence == 0.42
        assert entry.cve_ids == ["C1"]
        assert entry.chain_name is not None
        assert entry.transition_prob == 0.80

    def test_build_service_branch_unknown_service_is_noop(self):
        tree, parent = self._tree_with_parent()
        tree._build_service_branch("postgres", parent, 1)
        assert list(tree.nodes) == ["p"]

    def test_build_service_branch_redis(self):
        tree, parent = self._tree_with_parent()
        tree._build_service_branch("redis", parent, 1)
        svc = tree.nodes["svc_redis_1"]
        assert parent.children == ["svc_redis_1"]
        assert svc.confidence == 0.80
        assert "svc_redis_1_ssh_key_inject" in tree.nodes

    def test_build_child_nodes_skips_malformed_spec(self):
        tree, parent = self._tree_with_parent()
        tree._build_child_nodes(parent, [("a", "b", "c")])
        assert parent.children == []

    def test_build_child_nodes_four_tuple_uses_string_chain(self):
        tree, parent = self._tree_with_parent()
        tree._build_child_nodes(parent, [("kid", "desc", 0.8, "chain_x")])
        kid = tree.nodes["p_kid"]
        assert kid.chain_name == "chain_x"
        assert kid.confidence == pytest.approx(0.4)
        assert parent.children == ["p_kid"]

    def test_build_child_nodes_five_tuple_single_prefix(self):
        """修复: 5 元组路径只加一次父前缀, 孙节点正常递归."""
        tree, parent = self._tree_with_parent()
        tree._build_child_nodes(
            parent, [("kid2", "desc", 0.5, "chain_y", [("gkid", "g", 0.9, None)])]
        )
        assert "p_kid2" in tree.nodes
        assert "p_p_kid2" not in tree.nodes
        assert tree.nodes["p_kid2"].chain_name == "chain_y"
        assert "p_kid2_gkid" in tree.nodes
        assert tree.nodes["p_kid2_gkid"].chain_name is None

    def test_build_child_nodes_depth_cap(self):
        tree, parent = self._tree_with_parent()
        tree._build_child_nodes(parent, [("deep", "d", 0.5, None)], depth=4)
        assert parent.children == []

    def test_first_chain(self):
        tree = AttackTree()
        assert tree._first_chain({"children": [("a", "b", 0.5, "chain")]}) == "chain"
        assert tree._first_chain({"children": [("a", "b", 0.5, None)]}) is None
        assert tree._first_chain({}) is None

    @pytest.mark.parametrize(
        "port, expected",
        [
            (6379, "redis"),
            (3306, "mysql"),
            (5432, "postgres"),
            (2375, "docker"),
            (2376, "docker"),
            (9200, "elasticsearch"),
            (27017, "mongodb"),
            (11211, "memcached"),
            (4899, "rsync"),
            (9999, None),
        ],
    )
    def test_port_to_service(self, port, expected):
        assert AttackTree()._port_to_service(port) == expected


class TestAttackTreePropagation:
    def _manual_tree(self, parent_conf, child_conf):
        tree = AttackTree()
        tree.root_id = "root"
        root = AttackTreeNode(id="root", vuln_type="root", description="r", confidence=parent_conf)
        child = AttackTreeNode(
            id="leaf",
            vuln_type="leaf",
            description="l",
            confidence=child_conf,
            parent_id="root",
            transition_prob=1.0,
        )
        tree.add_node(root)
        tree.add_node(child)
        root.children.append("leaf")
        return tree

    def test_propagate_without_root_is_noop(self):
        tree = AttackTree()
        tree.propagate()
        assert tree.root_id is None

    def test_propagate_ignores_zero_confidence_parent(self):
        tree = self._manual_tree(parent_conf=0.0, child_conf=0.4)
        tree.propagate()
        assert tree.nodes["leaf"].confidence == 0.4

    def test_propagate_down_unknown_node_is_noop(self):
        tree = AttackTree()
        tree._propagate_down("missing", 1.0)
        assert tree.nodes == {}

    def test_integrate_evidence_unknown_node_is_noop(self):
        tree = AttackTree()
        tree.integrate_evidence("missing", True)
        assert tree.nodes == {}

    def test_integrate_evidence_confirmed_boosts_upwards(self):
        tree = AttackTree()
        tree.root_id = "root"
        root = AttackTreeNode(id="root", vuln_type="root", description="r", confidence=1.0)
        mid = AttackTreeNode(
            id="mid",
            vuln_type="mid",
            description="m",
            confidence=0.3,
            parent_id="root",
            transition_prob=1.0,
        )
        leaf = AttackTreeNode(
            id="leaf",
            vuln_type="leaf",
            description="l",
            confidence=0.3,
            parent_id="mid",
            transition_prob=1.0,
        )
        tree.add_node(root)
        tree.add_node(mid)
        tree.add_node(leaf)
        root.children.append("mid")
        mid.children.append("leaf")

        tree.integrate_evidence("leaf", True)
        assert leaf.verified is True
        assert leaf.evidence == ["confirmed"]
        assert leaf.confidence == pytest.approx(0.7941176, abs=1e-6)
        assert mid.confidence == pytest.approx(0.7941176, abs=1e-6)
        assert "boosted_by_child_leaf" in mid.evidence

    def test_integrate_evidence_not_confirmed_is_clamped_low(self):
        tree = AttackTree()
        node = AttackTreeNode(id="n", vuln_type="n", description="", confidence=0.001)
        tree.add_node(node)
        tree.integrate_evidence("n", False)
        assert node.confidence == 0.01
        assert node.verified is False
        assert node.evidence == ["not_found"]

    def test_integrate_evidence_prior_one_is_clamped_high(self):
        tree = AttackTree()
        node = AttackTreeNode(id="n", vuln_type="n", description="", confidence=1.0)
        tree.add_node(node)
        tree.integrate_evidence("n", True)
        assert node.confidence == 0.99

    def test_propagate_up_without_parent_is_noop(self):
        node = AttackTreeNode(id="n", vuln_type="n", description="", confidence=0.5)
        tree = AttackTree()
        tree.add_node(node)
        tree._propagate_up("n")
        assert node.confidence == 0.5

    def test_propagate_up_with_missing_parent_is_noop(self):
        node = AttackTreeNode(
            id="n", vuln_type="n", description="", confidence=0.5, parent_id="ghost"
        )
        tree = AttackTree()
        tree.add_node(node)
        tree._propagate_up("n")
        assert node.confidence == 0.5

    def test_propagate_up_keeps_parent_when_not_boosted(self):
        tree = AttackTree()
        parent = AttackTreeNode(id="parent", vuln_type="p", description="", confidence=0.95)
        child = AttackTreeNode(
            id="kid",
            vuln_type="k",
            description="",
            confidence=0.5,
            parent_id="parent",
            transition_prob=1.0,
        )
        tree.add_node(parent)
        tree.add_node(child)
        parent.children.append("kid")
        tree._propagate_up("kid")
        assert parent.confidence == 0.95
        assert parent.evidence == []

    def test_propagate_up_skips_missing_and_zero_prob_children(self):
        tree = AttackTree()
        parent = AttackTreeNode(id="parent", vuln_type="p", description="", confidence=0.5)
        zero = AttackTreeNode(
            id="zero",
            vuln_type="z",
            description="",
            confidence=0.9,
            parent_id="parent",
            transition_prob=0.0,
        )
        tree.add_node(parent)
        tree.add_node(zero)
        parent.children.extend(["ghost", "zero"])
        tree._propagate_up("zero")
        assert parent.confidence == 0.5
        assert parent.evidence == []

    def test_best_paths_empty_tree(self):
        assert AttackTree().best_paths() == []

    def test_best_paths_ranked_and_bounded(self):
        tree = AttackTree()
        tree.build_from_recon(["spring boot", "wordpress"], [6379], ["/actuator"], [])
        paths = tree.best_paths()
        assert paths
        confs = [p["confidence"] for p in paths]
        assert confs == sorted(confs, reverse=True)
        for path in paths:
            assert path["depth"] == len(path["path"])
            assert path["path"][0]["id"] == "root"
            assert path["leaf_id"] == path["path"][-1]["id"]
        assert len(paths) <= 10

    def test_best_paths_min_confidence_filters(self):
        tree = AttackTree()
        tree.build_from_recon(["spring"], [6379], [], [])
        assert tree.best_paths(min_confidence=0.99) == []

    def test_summary_and_json(self):
        tree = AttackTree()
        tree.build_from_recon(["php"], [6379], [], [])
        tree.integrate_evidence("svc_redis_1", True)
        summary = tree.summary()
        assert summary["total_nodes"] == len(tree.nodes)
        assert summary["root_confidence"] == 1.0
        assert len(summary["best_paths"]) <= 5
        assert summary["verified_nodes"][0]["id"] == "svc_redis_1"
        parsed = json.loads(tree.to_json())
        assert parsed["total_nodes"] == summary["total_nodes"]

    def test_summary_without_root(self):
        tree = AttackTree()
        assert tree.summary()["root_confidence"] == 0.0


class TestConstraintGraphIngest:
    def test_ingest_request_query_body_and_params(self):
        graph = ConstraintGraph()
        graph.ingest_request("http://t/p?a=1&a=2&b=x", '{"c": 3}', params={"d": "4"})
        assert graph._param_values["a"] == ["1", "2"]
        assert graph._param_values["c"] == ["3"]
        assert graph._param_values["d"] == ["4"]
        assert graph._param_names >= {"a", "b", "c", "d"}

    def test_ingest_request_nested_json_body(self):
        graph = ConstraintGraph()
        graph.ingest_request("http://t/p", '{"outer": {"inner": "v"}}')
        assert "outer" in graph._param_names
        assert graph._param_values["outer"] == ["{'inner': 'v'}"]

    def test_ingest_request_form_urlencoded_body(self):
        graph = ConstraintGraph()
        graph.ingest_request("http://t/p", "user=admin&pass=s3cret&empty=")
        assert graph._param_values["user"] == ["admin"]
        assert graph._param_values["pass"] == ["s3cret"]
        assert "empty" not in graph._param_names

    def test_ingest_request_json_list_body_is_ignored(self):
        graph = ConstraintGraph()
        graph.ingest_request("http://t/p", "[1, 2, 3]")
        assert graph._param_names == set()

    def test_ingest_response_skips_errors(self):
        graph = ConstraintGraph()
        graph.ingest_response(404, '{"price": 5}')
        assert graph._param_names == set()

    def test_ingest_response_json_and_201(self):
        graph = ConstraintGraph()
        graph.ingest_response(201, '{"price": 5, "items": [{"sku": "a1", "n": 7}]}')
        assert graph._param_values["price"] == ["5"]
        assert "sku" in graph._param_names
        assert "n" in graph._param_names

    def test_ingest_response_json_scalar_list_adds_nothing(self):
        graph = ConstraintGraph()
        graph.ingest_response(200, '["a", "b"]')
        assert graph._param_names == set()

    def test_ingest_response_html_extraction(self):
        graph = ConstraintGraph()
        html = '<input name="user" value="bob"> {"role": "admin", "x": 1}'
        graph.ingest_response(200, html)
        assert graph._param_values["user"] == ["bob"]
        assert graph._param_values["role"] == ["admin"]


class TestConstraintGraphHelpers:
    def test_add_param_value_skips_blanks(self):
        graph = ConstraintGraph()
        graph._add_param_value("", "v")
        graph._add_param_value("k", "   ")
        assert graph._param_names == set()

    def test_add_param_value_dedupes_within_window(self):
        graph = ConstraintGraph()
        for _ in range(3):
            graph._add_param_value("p", "same")
        assert graph._param_values["p"] == ["same"]

    def test_add_param_value_appends_old_value_outside_window(self):
        graph = ConstraintGraph()
        for i in range(25):
            graph._add_param_value("p", "v%d" % i)
        graph._add_param_value("p", "v24")
        assert graph._param_values["p"][-1] == "v24"
        assert graph._param_values["p"].count("v24") == 2

    def test_extract_from_json_numeric_names_and_strings(self):
        graph = ConstraintGraph()
        graph._extract_from_json({"score": 5, "price": 5, "note": "text"}, "")
        assert "score" not in graph._param_values
        assert "score" in graph._param_names
        assert graph._param_values["price"] == ["5"]
        assert graph._param_values["note"] == ["text"]

    def test_extract_from_json_truncates_long_lists(self):
        graph = ConstraintGraph()
        graph._extract_from_json([{"k": "v%d" % i} for i in range(8)], "")
        assert graph._param_values["k"] == ["v0", "v1", "v2", "v3", "v4"]


class TestConstraintGraphDetection:
    def test_detect_numerical_relationships_double(self):
        graph = ConstraintGraph()
        graph._param_values = {"a": ["2", "3"], "b": ["4", "6"], "c": ["0"]}
        rels = graph.detect_numerical_relationships()
        assert {(r.source_param, r.target_param, r.relation) for r in rels} == {("a", "b", "a*2=b")}
        assert graph.relationships == rels
        assert all(r.target_param != "c" for r in rels)

    def test_detect_numerical_relationships_inverse(self):
        graph = ConstraintGraph()
        graph._param_values = {"a": ["0.5"], "b": ["2"]}
        rels = graph.detect_numerical_relationships()
        assert [(r.relation, r.confidence) for r in rels] == [("a*b=1", 0.8)]

    def test_detect_numerical_relationships_length_mismatch(self):
        graph = ConstraintGraph()
        graph._param_values = {"a": ["2"], "b": ["4", "6", "8", "10"]}
        assert graph.detect_numerical_relationships() == []

    def test_detect_numerical_relationships_ignores_non_numeric(self):
        graph = ConstraintGraph()
        graph._param_values = {"a": ["x"], "b": ["4"]}
        assert graph.detect_numerical_relationships() == []

    def test_detect_constraints_price_and_qty(self):
        graph = ConstraintGraph()
        graph._param_names = {"price", "qty"}
        constraints = graph.detect_constraints()
        types = [c.type for c in constraints]
        assert types == ["price_tamper", "price_qty_mismatch"]
        assert constraints[0].severity == "high"
        assert graph.get_mutation_suggestions()["price"] == ["0", "-1", "999999", "0.01"]
        assert graph.constraints == constraints

    def test_detect_constraints_percentage_and_privilege(self):
        graph = ConstraintGraph()
        graph._param_names = {
            "discount_rate",
            "role",
            "is_admin",
            "group_id",
            "percent_off",
            "other",
        }
        constraints = graph.detect_constraints()
        pct = [c for c in constraints if c.type == "percentage_abuse"]
        mass = [c for c in constraints if c.type == "mass_assignment"]
        assert {c.params[0] for c in pct} == {"discount_rate", "percent_off"}
        assert {c.params[0] for c in mass} == {"role", "is_admin", "group_id"}
        assert all(c.severity == "critical" for c in mass)
        assert len(constraints) == 5

    def test_add_mutation_suggestion_dedupes(self):
        graph = ConstraintGraph()
        graph._add_mutation_suggestion("p", ["1", "2", "1"])
        graph._add_mutation_suggestion("p", ["2", "3"])
        assert graph.get_mutation_suggestions() == {"p": ["1", "2", "3"]}

    def test_get_mutation_suggestions_empty(self):
        assert ConstraintGraph().get_mutation_suggestions() == {}

    def test_summary_structure(self):
        graph = ConstraintGraph()
        graph._param_values = {"price": ["1", "2"], "qty": ["2"]}
        graph._param_names = {"price", "qty"}
        graph.detect_numerical_relationships()
        graph.detect_constraints()
        summary = graph.summary()
        assert summary["params_discovered"] == 2
        assert summary["param_values"]["price"] == ["1", "2"]
        assert any(c["type"] == "price_tamper" for c in summary["constraints"])
        assert summary["relationships"]
        raw_rels = graph.relationships
        assert isinstance(raw_rels[0], Relationship)
        assert isinstance(graph.constraints[0], Constraint)


class TestConstraintBreaker:
    def test_generate_break_tests_from_suggestions_and_price(self):
        graph = ConstraintGraph()
        graph._add_mutation_suggestion("price", ["0", "-1"])
        tests = ConstraintBreaker(graph).generate_break_tests("http://t/p", "price")
        techniques = {t["technique"] for t in tests}
        assert techniques == {"constraint_break", "price_manipulation"}
        suggestion_tests = [t for t in tests if t["technique"] == "constraint_break"]
        assert [t["value"] for t in suggestion_tests] == ["0", "-1"]
        price_tests = [t for t in tests if t["technique"] == "price_manipulation"]
        assert len(price_tests) == 8
        assert {t["variant"] for t in price_tests} == {
            "numeric_overflow",
            "negative",
            "decimal_injection",
            "zero",
            "negative_large",
            "scientific",
            "null",
            "string_injection",
        }

    def test_generate_break_tests_quantity(self):
        graph = ConstraintGraph()
        tests = ConstraintBreaker(graph).generate_break_tests("http://t/p", "item_count")
        quantity_tests = [t for t in tests if t["technique"] == "quantity_abuse"]
        assert len(quantity_tests) == 5
        assert [t["variant"] for t in quantity_tests] == [
            "negative",
            "zero",
            "overflow",
            "fraction",
            "string",
        ]

    def test_generate_break_tests_unrelated_param(self):
        assert (
            ConstraintBreaker(ConstraintGraph()).generate_break_tests("http://t/p", "search") == []
        )


class TestConstraintCheckEntryPoint:
    def test_check_with_param_returns_break_tests(self):
        sess = mock.Mock()
        sess.get.return_value = mock.Mock(
            status_code=200, text='{"price": 100, "qty": 2, "role": "user"}'
        )
        result = check("http://t/p", param="price", sess=sess)
        assert result["vulnerable"] is False
        assert result["graph"]["params_discovered"] == 3
        assert result["tests"]
        assert {t["technique"] for t in result["tests"]} == {
            "constraint_break",
            "price_manipulation",
        }

    def test_check_without_param_has_no_tests_key(self):
        sess = mock.Mock()
        sess.get.return_value = mock.Mock(status_code=200, text="<html></html>")
        result = check("http://t/p", sess=sess)
        assert "tests" not in result
        assert result["graph"]["params_discovered"] == 0

    def test_check_swallows_request_errors(self):
        sess = mock.Mock()
        sess.get.side_effect = RuntimeError("no route")
        result = check("http://t/p", param="price", sess=sess)
        assert result["vulnerable"] is False
        assert result["graph"]["params_discovered"] == 0
        assert "tests" in result

    def test_check_creates_session_when_none(self):
        with mock.patch("requests.Session") as session_cls:
            session_cls.return_value.get.return_value = mock.Mock(
                status_code=200, text='{"amount": 10, "qty": 3}'
            )
            result = check("http://t/p")
        assert result["graph"]["params_discovered"] == 2
        session_cls.return_value.get.assert_called_once()
