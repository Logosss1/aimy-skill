"""Tests for tools.orchestrator_engine.weaponizer extracted dispatch."""
from unittest import mock

from tools.orchestrator_engine import weaponizer


class TestWeaponizeOneDispatch:
    def test_unknown_vtype_returns_none(self):
        finding = {"type": "unknown_xyz", "url": "http://x/", "param": "id"}
        result = weaponizer.weaponize_one(
            finding, sess=None, timeout=2.0, vuln_ctx=mock.Mock(), webshell_urls=[],
        )
        assert result is None

    def test_dispatches_xss(self):
        finding = {"type": "xss", "url": "http://x/", "param": "q"}
        with mock.patch("tools.xss_validator.check",
                        return_value={"validated": True}) as m:
            result = weaponizer.weaponize_one(
                finding, sess=None, timeout=2.0,
                vuln_ctx=mock.Mock(), webshell_urls=[],
            )
        assert result is not None
        assert result.get("xss_validated", {}).get("validated") is True
        m.assert_called_once()

    def test_jwt_with_token(self):
        finding = {
            "type": "jwt", "url": "http://x/", "param": "auth",
            "result": {"tokens_found": [{"token": "eyJhbGc.eyJzdWI.signature"}]},
        }
        with mock.patch("tools.jwt_exploiter.check",
                        return_value={"cracked": True}) as m:
            result = weaponizer.weaponize_one(
                finding, sess=None, timeout=2.0,
                vuln_ctx=mock.Mock(), webshell_urls=[],
            )
        assert result is not None
        assert result.get("jwt_exploit", {}).get("cracked") is True
        m.assert_called_once()

    def test_jwt_no_token_falls_back_to_none_test(self):
        finding = {
            "type": "jwt", "url": "http://x/", "param": "auth",
            "result": {"tokens_found": []},
        }
        with mock.patch("tools.jwt_exploiter.check",
                        return_value={"alg": "none"}) as m:
            result = weaponizer.weaponize_one(
                finding, sess=None, timeout=2.0,
                vuln_ctx=mock.Mock(), webshell_urls=[],
            )
        assert result is not None
        assert result.get("jwt_none_test", {}).get("alg") == "none"
        m.assert_called_once_with(token=None, sess=None, url="http://x/",
                                  param="auth", timeout=2.0)

    def test_sqli_appends_webshell_url(self):
        finding = {"type": "sqli", "url": "http://x/", "param": "id"}
        vuln_ctx = mock.Mock()
        vuln_ctx.get.return_value.discovered_versions = {"web_root": "/var/www"}
        webshells: list = []
        with mock.patch("tools.sqli_weaponizer.check", return_value={}):
            with mock.patch("tools.weaponize_engine.sqli_into_outfile",
                            return_value={"success": True,
                                          "webshell_url": "http://x/shell.php"}):
                result = weaponizer.weaponize_one(
                    finding, sess=None, timeout=2.0,
                    vuln_ctx=vuln_ctx, webshell_urls=webshells,
                )
        assert result is not None
        assert "http://x/shell.php" in webshells

    def test_ssrf_dispatches(self):
        finding = {"type": "ssrf", "url": "http://x/", "param": "u"}
        with mock.patch("tools.ssrf_pwn.run", return_value={"cloud_metadata": {}}):
            with mock.patch("tools.ssrf_pwn.check", return_value={"vulnerable": True}):
                result = weaponizer.weaponize_one(
                    finding, sess=None, timeout=2.0,
                    vuln_ctx=mock.Mock(), webshell_urls=[],
                )
        assert result is not None
        assert result.get("ssrf_pwn", {}).get("vulnerable") is True

    def test_lfi_rce_available(self):
        finding = {
            "type": "lfi", "url": "http://x/", "param": "f",
            "result": {"rce_available": True},
        }
        with mock.patch("tools.reverse_shell.deploy_webshell",
                        return_value={"success": True, "url": "http://x/c.php"}):
            with mock.patch("tools.weaponize_engine.deploy_webshell_lfi",
                            return_value={"success": False}):
                result = weaponizer.weaponize_one(
                    finding, sess=None, timeout=2.0,
                    vuln_ctx=mock.Mock(), webshell_urls=[],
                )
        assert result is not None
        assert result.get("rce") is True
        assert result.get("exploit_ready") is True


if __name__ == "__main__":
    import unittest
    unittest.main()
