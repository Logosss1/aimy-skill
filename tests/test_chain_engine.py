import re
from unittest.mock import MagicMock, patch

import pytest
import responses


class TestChainEngineInit:
    def test_init_default_session(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        assert engine.results == {}
        assert engine.timeout == 10.0
        assert engine.sess is not None

    def test_init_custom_session(self):
        from tools.chain_engine import ChainEngine

        sess = MagicMock()
        engine = ChainEngine(sess=sess, timeout=5.0)
        assert engine.sess is sess
        assert engine.timeout == 5.0


class TestExtractCredsFromText:
    def test_extract_aws_creds(self):
        from tools.chain_engine import _extract_creds_from_text

        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY"
        result = _extract_creds_from_text(text)
        assert len(result) >= 1
        assert any("aws" in str(c) for c in result)

    def test_extract_no_creds(self):
        from tools.chain_engine import _extract_creds_from_text

        result = _extract_creds_from_text("just some random text")
        assert result == []

    def test_extract_database_creds(self):
        from tools.chain_engine import _extract_creds_from_text

        text = "DB_PASSWORD=hunter2\nDATABASE_URL=postgres://localhost"
        result = _extract_creds_from_text(text)
        assert len(result) >= 1


class TestChainMap:
    def test_chain_map_has_all_chains(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        mp = engine._chain_map()
        expected_chains = [
            "ssrf_to_rce",
            "ssrf_cloud_pwn",
            "lfi_to_rce",
            "lfi_auto_webshell",
            "lfi_to_ssh",
            "sqli_to_rce",
            "sqli_to_data",
            "xss_to_hijack",
            "xss_to_cred",
            "auth_bypass_to_pwn",
            "deser_to_rce",
            "debug_abuse",
        ]
        for chain in expected_chains:
            assert chain in mp, "Missing chain: %s" % chain

    def test_chain_map_functions_are_callable(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        mp = engine._chain_map()
        for name, fn in mp.items():
            assert callable(fn), "%s is not callable" % name


class TestAutoCompose:
    def test_auto_compose_ssrf_cloud_metadata(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {
                "type": "ssrf",
                "evidence": [{"payload": "url=http://169.254.169.254"}],
                "url": "http://test.com/page",
                "param": "url",
            }
        }
        composed = engine.auto_compose(findings)
        assert any(c["chain"] == "ssrf_cloud_pwn" for c in composed)

    def test_auto_compose_sqli_union(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {"type": "sqli", "evidence": [], "url": "http://test.com/page", "param": "id"}
        }
        composed = engine.auto_compose(findings)
        assert len(composed) == 0

    def test_auto_compose_no_matching_rules(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {
                "type": "info_disclosure",
                "evidence": [],
                "url": "http://test.com/page",
                "param": "q",
            }
        }
        composed = engine.auto_compose(findings)
        assert len(composed) == 0

    def test_auto_compose_xss_stored(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {"type": "xss", "evidence": [], "url": "http://test.com/page", "param": "q"}
        }
        composed = engine.auto_compose(findings)
        assert len(composed) == 0

    def test_auto_compose_deser_gadget(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {
                "type": "deser",
                "evidence": [{"payload": "rO0ABX..."}],
                "url": "http://test.com/page",
                "param": "data",
            }
        }
        composed = engine.auto_compose(findings)
        assert any(c["chain"] == "deser_to_rce" for c in composed)


class TestExecuteAutoChains:
    def test_execute_auto_chains_success(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {
                "type": "ssrf",
                "evidence": [{"payload": "url=http://169.254.169.254"}],
                "url": "http://test.com/page?url=x",
                "param": "url",
            }
        }
        engine.chain_ssrf_cloud_pwn = MagicMock(return_value={"success": True})
        result = engine.execute_auto_chains(findings, "http://test.com/page", "url")
        assert "composed_chains" in result
        assert "results" in result
        assert result["results"]["ssrf_cloud_pwn"]["success"] is True

    def test_execute_auto_chains_exception(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {
                "type": "ssrf",
                "evidence": [{"payload": "url=http://169.254.169.254"}],
                "url": "http://test.com/page?url=x",
                "param": "url",
            }
        }
        engine.chain_ssrf_cloud_pwn = MagicMock(side_effect=RuntimeError("connection failed"))
        result = engine.execute_auto_chains(findings, "http://test.com/page", "url")
        assert "error" in result["results"]["ssrf_cloud_pwn"]

    def test_execute_auto_chains_no_matches(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        findings = {
            "f1": {
                "type": "info_disclosure",
                "evidence": [],
                "url": "http://test.com/page",
                "param": "q",
            }
        }
        result = engine.execute_auto_chains(findings, "http://test.com/page", "q")
        assert result["composed_chains"] == []
        assert result["results"] == {}


class TestRunMethod:
    def test_run_default_chain(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        engine.full_chain = MagicMock(return_value={"overall_success": True})
        result = engine.run("http://test.com/page", "id")
        engine.full_chain.assert_called_once()
        assert result["overall_success"] is True

    def test_run_specific_chain(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        engine.chain_ssrf_to_rce = MagicMock(
            return_value={"chain": "ssrf_to_rce", "success": False}
        )
        result = engine.run("http://test.com/page?url=x", "url", chain="ssrf_to_rce")
        engine.chain_ssrf_to_rce.assert_called_once()
        assert result["chain"] == "ssrf_to_rce"

    def test_run_unknown_chain_falls_back(self):
        from tools.chain_engine import ChainEngine

        engine = ChainEngine()
        engine.full_chain = MagicMock(return_value={"overall_success": True})
        result = engine.run("http://test.com/page", "id", chain="nonexistent")
        engine.full_chain.assert_called_once()
        assert result["overall_success"] is True


class TestChainMethods:
    @pytest.fixture
    def engine(self):
        from tools.chain_engine import ChainEngine

        return ChainEngine(timeout=2.0)

    @responses.activate
    def test_chain_xss_to_cred_steal(self, engine):
        responses.add(responses.GET, re.compile(r".*"), status=200, body="ok")
        result = engine.chain_xss_to_cred_steal("http://test.com/page", "q")
        assert result["chain"] == "xss_to_cred_steal"
        assert "steps" in result

    @responses.activate
    def test_chain_lfi_to_ssh_no_key(self, engine):
        responses.add(responses.GET, re.compile(r".*"), status=200, body="no ssh key here")
        result = engine.chain_lfi_to_ssh("http://test.com/page?file=x", "file")
        assert result["chain"] == "lfi_to_ssh"
        assert "steps" in result

    @responses.activate
    def test_chain_lfi_to_rce_no_success(self, engine):
        responses.add(responses.GET, re.compile(r".*"), status=200, body="some log content")
        result = engine.chain_lfi_to_rce("http://test.com/page?file=x", "file")
        assert result["chain"] == "lfi_to_rce"
        assert "steps" in result

    @responses.activate
    def test_chain_debug_abuse_no_findings(self, engine):
        responses.add(responses.GET, re.compile(r".*"), status=404, body="not found")
        result = engine.chain_debug_abuse("http://test.com/page")
        assert result["chain"] == "debug_abuse"

    @responses.activate
    def test_chain_xss_to_hijack_no_success(self, engine):
        responses.add(responses.GET, re.compile(r".*"), status=200, body="ok")
        result = engine.chain_xss_to_hijack("http://test.com/page", "q")
        assert result["chain"] == "xss_to_account_hijack"
        assert "steps" in result

    @responses.activate
    def test_chain_deser_to_rce_no_success(self, engine):
        responses.add(responses.POST, re.compile(r".*"), status=200, body="ok")
        result = engine.chain_deser_to_rce("http://test.com/page", "data")
        assert result["chain"] == "deser_to_rce"
        assert "steps" in result

    @responses.activate
    def test_chain_lfi_auto_webshell_no_success(self, engine):
        responses.add(responses.GET, re.compile(r".*"), status=200, body="some content")
        result = engine.chain_lfi_auto_webshell("http://test.com/page?file=x", "file")
        assert result["chain"] == "lfi_auto_webshell"

    @responses.activate
    def test_chain_sqli_to_rce_no_success(self, engine):
        with patch("tools.chain_engine.sql_injection") as mock_sqli:
            mock_sqli.check.return_value = {"vulnerable": False}
            responses.add(responses.GET, re.compile(r".*"), status=200, body="no sqli")
            result = engine.chain_sqli_to_rce("http://test.com/page", "id")
            assert result["chain"] == "sqli_to_rce"

    @responses.activate
    def test_chain_auth_to_admin_no_success(self, engine):
        with patch("tools.chain_engine.auth_bypass") as mock_ab:
            mock_ab.check.return_value = {"vulnerable": False}
            responses.add(responses.GET, re.compile(r".*"), status=200, body="ok")
            result = engine.chain_auth_to_admin("http://test.com/page", "q")
            assert result["chain"] == "auth_bypass_to_admin"


class TestRunFunction:
    def test_run_function_default(self):
        from tools.chain_engine import run

        with patch("tools.chain_engine.ChainEngine") as mock_engine:
            mock_instance = mock_engine.return_value
            mock_instance.run.return_value = {"chain": "full_chain", "success": True}
            result = run("http://test.com/page", "id")
            assert result["success"] is True
            mock_instance.run.assert_called_once_with("http://test.com/page", "id", "full_chain")

    def test_run_function_custom_chain(self):
        from tools.chain_engine import run

        with patch("tools.chain_engine.ChainEngine") as mock_engine:
            mock_instance = mock_engine.return_value
            mock_instance.run.return_value = {"chain": "ssrf_to_rce", "success": True}
            result = run("http://test.com/page", "url", chain="ssrf_to_rce", sess=None)
            assert result["chain"] == "ssrf_to_rce"


class TestPrivateTryFunctions:
    @responses.activate
    def test_try_ssrf_cloud_metadata_no_creds(self):
        from tools.chain_engine import _try_ssrf_cloud_metadata

        responses.add(responses.GET, re.compile(r".*"), status=200, body="ok")
        import requests

        sess = requests.Session()
        result = _try_ssrf_cloud_metadata("url", sess, "http://test.com/page?url=PLACEHOLDER", 2.0)
        assert result["chain"] == "ssrf_to_metadata"
        assert result["success"] is False

    @responses.activate
    def test_try_ssrf_cloud_metadata_success(self):
        from tools.chain_engine import _try_ssrf_cloud_metadata

        body = '{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI"}'
        responses.add(responses.GET, re.compile(r".*"), status=200, body=body)
        import requests

        sess = requests.Session()
        result = _try_ssrf_cloud_metadata("url", sess, "http://test.com/page?url=PLACEHOLDER", 2.0)
        assert result["success"] is True
        assert result["cloud"] is not None

    @responses.activate
    def test_try_deser_to_rce_with_evidence(self):
        from tools.chain_engine import _try_deser_to_rce

        responses.add(responses.POST, re.compile(r".*"), status=200, body="ok")
        import requests

        sess = requests.Session()
        result = _try_deser_to_rce("data", sess, "http://test.com/page", 2.0)
        assert result["success"] is True
        assert result["method"] == "gadget_test"

    @responses.activate
    def test_try_deser_to_rce_no_evidence(self):
        from tools.chain_engine import _try_deser_to_rce

        responses.add(responses.POST, re.compile(r".*"), status=500, body="server error")
        import requests

        sess = requests.Session()
        result = _try_deser_to_rce("data", sess, "http://test.com/page", 2.0)
        assert result["chain"] == "deser_to_rce"
        assert result["success"] is False
