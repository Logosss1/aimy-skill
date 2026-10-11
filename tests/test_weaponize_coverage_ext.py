import subprocess

import requests

from tools import weaponize_engine as we


class FakeResp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class HandlerSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self.verify = True

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.handler("GET", url, kwargs)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.handler("POST", url, kwargs)


def _raise_handler(method, url, kwargs):
    raise RuntimeError("network down")


class TestSqliOutfileExt:
    def test_get_webshell_success(self):
        def handler(method, url, kwargs):
            if "c=id" in url:
                return FakeResp(200, "uid=33 gid=33")
            return FakeResp(200, "ok")

        result = we.sqli_into_outfile(
            "http://t.test/exec?id=1", "id", HandlerSession(handler), timeout=1.0
        )
        assert result["success"] is True
        assert result["method"] == "sqli_outfile"
        assert "output" in result["evidence"][0]

    def test_probe_requests_raise(self):
        def handler(method, url, kwargs):
            if "?c=id" in url:
                raise RuntimeError("boom")
            return FakeResp(200, "ok")

        result = we.sqli_into_outfile(
            "http://t.test/exec?id=1", "id", HandlerSession(handler), timeout=1.0
        )
        assert result["success"] is False

    def test_post_webshell_success(self):
        def handler(method, url, kwargs):
            if method == "POST":
                return FakeResp(200, "uid=33")
            if "shell.php" in url:
                return FakeResp(200, "no marker")
            return FakeResp(200, "ok")

        result = we.sqli_into_outfile(
            "http://t.test/exec?id=1", "id", HandlerSession(handler), timeout=1.0
        )
        assert result["success"] is True
        assert result["method"] == "sqli_outfile"
        assert result["evidence"][0]["method"] == "POST"

    def test_xp_cmdshell_success(self):
        def handler(method, url, kwargs):
            if "EXEC" in url:
                return FakeResp(200, "uid=500")
            return FakeResp(404, "")

        result = we.sqli_into_outfile(
            "http://t.test/exec?id=1", "id", HandlerSession(handler), timeout=1.0
        )
        assert result["success"] is True
        assert result["method"] == "xp_cmdshell"
        assert result["dbms"] == "mssql"

    def test_shell_probes_raise(self):
        def handler(method, url, kwargs):
            if "shell.php" in url:
                raise RuntimeError("boom")
            return FakeResp(404, "")

        result = we.sqli_into_outfile(
            "http://t.test/exec?id=1", "id", HandlerSession(handler), timeout=1.0
        )
        assert result["success"] is False

    def test_all_requests_raise(self):
        result = we.sqli_into_outfile(
            "http://t.test/exec?id=1", "id", HandlerSession(_raise_handler), timeout=1.0
        )
        assert result["success"] is False


class TestDeployLfiExt:
    def test_poison_request_exception(self):
        result = we.deploy_webshell_lfi(
            "http://t.test/read?file=/tmp/x",
            "file",
            HandlerSession(_raise_handler),
            timeout=1.0,
        )
        assert result["success"] is False

    def test_read_request_exception(self):
        def handler(method, url, kwargs):
            if "/var/log" in url:
                raise RuntimeError("boom")
            return FakeResp(200, "")

        result = we.deploy_webshell_lfi(
            "http://t.test/read?file=/tmp/x", "file", HandlerSession(handler), timeout=1.0
        )
        assert result["success"] is False

    def test_inner_command_exception(self):
        def handler(method, url, kwargs):
            if "&c=" in url:
                raise RuntimeError("boom")
            if "/var/log" in url:
                return FakeResp(200, "system warning")
            return FakeResp(200, "")

        result = we.deploy_webshell_lfi(
            "http://t.test/read?file=/tmp/x", "file", HandlerSession(handler), timeout=1.0
        )
        assert result["success"] is False


class _R:
    def __init__(self, code, out):
        self.returncode = code
        self.stdout = out
        self.stderr = ""


class TestAwsTakeoverExt:
    def test_raw_outputs_and_session_token(self, monkeypatch):
        captured = {}

        def fake_run(cmd_list, **kwargs):
            captured["token"] = kwargs["env"].get("AWS_SESSION_TOKEN")
            sub = cmd_list[1]
            if sub == "sts":
                return _R(0, "{broken")
            if sub == "iam":
                return _R(0, "{broken")
            if sub == "s3":
                return _R(0, "")
            if sub == "ec2":
                return _R(0, "{broken")
            return _R(0, "")

        monkeypatch.setattr(we.subprocess, "run", fake_run)
        result = we.ssrf_to_aws_takeover("AKIAEXAMPLE", "secret", session_token="tok")
        assert result["success"] is True
        assert result["access"]["caller_identity_raw"] == "{broken"
        assert captured["token"] == "tok"
        assert "roles_count" not in result["access"]
        assert "ec2_instances" not in result["access"]
        actions = [s["action"] for s in result["steps"]]
        assert "s3_list_buckets" in actions
        assert "sts_get_caller_identity" not in actions

    def test_timeout(self, monkeypatch):
        def fake_run(cmd_list, **kwargs):
            raise subprocess.TimeoutExpired(cmd_list, 1)

        monkeypatch.setattr(we.subprocess, "run", fake_run)
        result = we.ssrf_to_aws_takeover("AKIAEXAMPLE", "secret")
        assert result["success"] is False
        assert result["error"] == "timeout"

    def test_generic_exception(self, monkeypatch):
        def fake_run(cmd_list, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(we.subprocess, "run", fake_run)
        result = we.ssrf_to_aws_takeover("AKIAEXAMPLE", "secret")
        assert result["success"] is False
        assert result["error"] == "boom"


class TestRunCommandExt:
    def test_request_exception(self):
        class RaisingSession:
            def get(self, *args, **kwargs):
                raise requests.RequestException("boom")

            def post(self, *args, **kwargs):
                raise requests.RequestException("boom")

        result = we.run_command_via_webshell(
            "http://t.test/shell.php", "id", RaisingSession(), timeout=1.0
        )
        assert result["success"] is False
        assert result["error"] == "boom"


class TestInteractiveWebshell:
    def test_full_session(self, monkeypatch):
        answers = iter(["", "upload one", "upload /l /r", "id", "bad", "quit"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
        uploaded = []
        monkeypatch.setattr(
            we, "_upload_via_webshell",
            lambda ws, lp, rp, sess, timeout: uploaded.append((lp, rp)) or True,
        )

        def fake_run(ws, cmd, sess, timeout):
            if cmd == "id":
                return {"success": True, "output": "ok"}
            return {"success": False, "error": "failed"}

        monkeypatch.setattr(we, "run_command_via_webshell", fake_run)
        we.interactive_webshell("http://t.test/shell.php", HandlerSession(_raise_handler))
        assert uploaded == [("/l", "/r")]

    def test_eof_exits(self, monkeypatch):
        def raise_eof(prompt=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)
        we.interactive_webshell("http://t.test/shell.php", HandlerSession(_raise_handler))

    def test_keyboard_interrupt_exits(self, monkeypatch):
        def raise_interrupt(prompt=""):
            raise KeyboardInterrupt

        monkeypatch.setattr("builtins.input", raise_interrupt)
        we.interactive_webshell("http://t.test/shell.php", HandlerSession(_raise_handler))


class TestUploadExt:
    def test_verify_failure(self, monkeypatch, tmp_path):
        local = tmp_path / "pwn.bin"
        local.write_bytes(b"data")
        calls = []

        def fake_run(ws, cmd, sess, timeout):
            calls.append(cmd)
            if cmd.startswith("echo "):
                return {"success": True, "output": "done"}
            return {"success": False, "error": "no"}

        monkeypatch.setattr(we, "run_command_via_webshell", fake_run)
        ok = we._upload_via_webshell(
            "http://t.test/shell.php", str(local), "/tmp/pwn.bin",
            HandlerSession(_raise_handler), 1.0,
        )
        assert ok is False
        assert len(calls) == 2
