"""Offline coverage tests for Kali executor, interactive shell and responder kit.

Subprocess, SSH, sockets and time are fully mocked; no external activity.
Targeted modules: tools.kali_executor, tools.interactive_shell, tools.responder_kit.

Some tests intentionally pin current (defective) behaviour and are named
"...documented" to make the gap explicit.
"""

import base64
import builtins
import socket
import types

from tools import interactive_shell as ish
from tools import kali_executor as ke
from tools import responder_kit as rk

# ---------------------------------------------------------------------------
# kali_executor: shell detection and local execution
# ---------------------------------------------------------------------------


class TestNeedsShell:
    def test_plain_command_does_not_need_shell(self):
        assert ke._needs_shell("nmap -sV 10.0.0.1") is False

    def test_metacharacters_need_shell(self):
        for cmd in [
            "a | b",
            "a && b",
            "a; b",
            "a > f",
            "a < f",
            "`id`",
            "echo $HOME",
            "(x)",
            "a\nb",
            "a & b",
        ]:
            assert ke._needs_shell(cmd) is True, cmd


class TestRunLocal:
    def test_simple_command_runs_as_argv_without_shell(self, monkeypatch):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            return types.SimpleNamespace(returncode=0, stdout="out", stderr="")

        monkeypatch.setattr(ke.subprocess, "run", fake_run)
        out = ke._run_local("nmap -sV target", timeout=7)
        assert seen["cmd"] == ["nmap", "-sV", "target"]
        assert "shell" not in seen["kwargs"]
        assert seen["kwargs"]["timeout"] == 7
        assert out == {"success": True, "exit_code": 0, "stdout": "out", "stderr": ""}

    def test_shell_metacharacters_use_shell_string(self, monkeypatch):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            return types.SimpleNamespace(returncode=1, stdout="", stderr="err")

        monkeypatch.setattr(ke.subprocess, "run", fake_run)
        out = ke._run_local("cat a | grep b", timeout=5)
        assert seen["cmd"] == "cat a | grep b"
        assert seen["kwargs"]["shell"] is True
        assert out["success"] is False and out["exit_code"] == 1

    def test_timeout_maps_to_error_dict(self, monkeypatch):
        def fake_run(*_a, **_k):
            raise ke.subprocess.TimeoutExpired(cmd="x", timeout=1)

        monkeypatch.setattr(ke.subprocess, "run", fake_run)
        assert ke._run_local("ls") == {
            "success": False,
            "error": "Timeout",
            "stdout": "",
            "stderr": "",
        }

    def test_generic_exception_maps_to_error_dict(self, monkeypatch):
        def fake_run(*_a, **_k):
            raise OSError("no such binary")

        monkeypatch.setattr(ke.subprocess, "run", fake_run)
        assert ke._run_local("ls")["error"] == "no such binary"


# ---------------------------------------------------------------------------
# kali_executor: configuration and connection
# ---------------------------------------------------------------------------


class TestKaliConfig:
    def test_available_requires_host_and_paramiko(self, monkeypatch):
        monkeypatch.setattr(ke, "HAS_PARAMIKO", False)
        assert ke.KaliConfig(local=True).available is True
        assert bool(ke.KaliConfig(local=True)) is True
        assert ke.KaliConfig(host="10.0.0.1").available is False
        monkeypatch.setattr(ke, "HAS_PARAMIKO", True)
        assert ke.KaliConfig(host="10.0.0.1").available is True
        assert ke.KaliConfig().available is False


def _install_fake_paramiko(monkeypatch, box, connect_error=None):
    class FakeSSHClient:
        def __init__(self):
            self.policy = None
            self.connect_kwargs = None
            self.closed = False
            self.sftp = types.SimpleNamespace(closed=False, close=lambda: None)
            box.append(self)

        def set_missing_host_key_policy(self, policy):
            self.policy = policy

        def connect(self, **kwargs):
            if connect_error is not None:
                raise connect_error
            self.connect_kwargs = kwargs

        def open_sftp(self):
            return self.sftp

        def close(self):
            self.closed = True

    class FakeRSAKey:
        @staticmethod
        def from_private_key_file(path):
            return "KEY:" + path

    fake_module = types.SimpleNamespace(
        SSHClient=FakeSSHClient,
        AutoAddPolicy=lambda: "auto-policy",
        RSAKey=FakeRSAKey,
    )
    monkeypatch.setattr(ke, "paramiko", fake_module, raising=False)
    monkeypatch.setattr(ke, "HAS_PARAMIKO", True)


class TestKaliConnect:
    def test_local_connect_short_circuits(self):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        assert ex.connect() is True

    def test_no_host_returns_false(self):
        ex = ke.KaliExecutor(ke.KaliConfig())
        assert ex.connect() is False

    def test_missing_paramiko_returns_false(self, monkeypatch):
        monkeypatch.setattr(ke, "HAS_PARAMIKO", False)
        ex = ke.KaliExecutor(ke.KaliConfig(host="10.0.0.1"))
        assert ex.connect() is False

    def test_ssh_password_connect(self, monkeypatch):
        box = []
        _install_fake_paramiko(monkeypatch, box)
        ex = ke.KaliExecutor(
            ke.KaliConfig(host="10.0.0.1", port=2222, user="kali", password="pw", timeout=9)
        )
        assert ex.connect() is True
        client = box[0]
        assert client.policy == "auto-policy"
        assert client.connect_kwargs == {
            "hostname": "10.0.0.1",
            "port": 2222,
            "username": "kali",
            "timeout": 9,
            "password": "pw",
        }
        assert ex._sftp is client.sftp

    def test_ssh_key_connect_uses_pkey(self, monkeypatch):
        box = []
        _install_fake_paramiko(monkeypatch, box)
        ex = ke.KaliExecutor(ke.KaliConfig(host="h", key_file="k.pem", password="ignored"))
        assert ex.connect() is True
        kwargs = box[0].connect_kwargs
        assert kwargs["pkey"] == "KEY:k.pem"
        assert "password" not in kwargs

    def test_ssh_connect_failure_resets_client(self, monkeypatch):
        box = []
        _install_fake_paramiko(monkeypatch, box, connect_error=OSError("refused"))
        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        assert ex.connect() is False
        assert ex._client is None

    def test_disconnect_closes_sftp_and_client(self):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        closed = []
        ex._sftp = types.SimpleNamespace(close=lambda: closed.append("sftp"))
        ex._client = types.SimpleNamespace(close=lambda: closed.append("client"))
        ex.disconnect()
        assert closed == ["sftp", "client"]
        assert ex._client is None and ex._sftp is None
        ex.disconnect()

    def test_disconnect_swallows_close_errors(self):
        def boom():
            raise OSError("already gone")

        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        ex._sftp = types.SimpleNamespace(close=boom)
        ex._client = types.SimpleNamespace(close=boom)
        ex.disconnect()
        assert ex._client is None


# ---------------------------------------------------------------------------
# kali_executor: command execution
# ---------------------------------------------------------------------------


class TestKaliRun:
    def test_local_run_delegates_to_run_local(self, monkeypatch):
        seen = {}

        def fake_local(cmd, timeout=120):
            seen["cmd"] = cmd
            seen["timeout"] = timeout
            return {"success": True}

        monkeypatch.setattr(ke, "_run_local", fake_local)
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        assert ex.run("id", timeout=9)["success"] is True
        assert seen == {"cmd": "id", "timeout": 9}

    def test_run_without_connection_returns_error(self):
        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        out = ex.run("id")
        assert out == {
            "success": False,
            "error": "Not connected",
            "stdout": "",
            "stderr": "",
        }

    def test_ssh_run_decodes_streams_and_exit_code(self):
        class FakeChannel:
            def __init__(self, code):
                self._code = code

            def recv_exit_status(self):
                return self._code

        class FakeStream:
            def __init__(self, data=b"", code=0):
                self._data = data
                self.channel = FakeChannel(code)

            def read(self):
                return self._data

        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        ex._client = types.SimpleNamespace(
            exec_command=lambda cmd, timeout=None: (
                FakeStream(),
                FakeStream(b"out\n", 3),
                FakeStream(b"err\n", 0),
            )
        )
        out = ex.run("nmap", timeout=5)
        assert out == {"success": False, "exit_code": 3, "stdout": "out\n", "stderr": "err\n"}

    def test_ssh_run_success(self):
        class FakeStream:
            def __init__(self, data=b"", code=0):
                self._data = data
                self.channel = types.SimpleNamespace(recv_exit_status=lambda: code)

            def read(self):
                return self._data

        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        ex._client = types.SimpleNamespace(
            exec_command=lambda cmd, timeout=None: (
                FakeStream(),
                FakeStream(b"ok", 0),
                FakeStream(b"", 0),
            )
        )
        out = ex.run("id")
        assert out["success"] is True and out["exit_code"] == 0

    def test_ssh_run_exception_returns_error(self):
        def boom(_cmd, timeout=None):
            raise OSError("channel closed")

        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        ex._client = types.SimpleNamespace(exec_command=boom)
        out = ex.run("id")
        assert out["success"] is False and out["error"] == "channel closed"


# ---------------------------------------------------------------------------
# kali_executor: file helpers
# ---------------------------------------------------------------------------


class FakeRemoteFile:
    def __init__(self, data=""):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.data

    def write(self, text):
        self.data += text


class FakeSFTP:
    def __init__(self):
        self.files = {}
        self.fail_open = False

    def open(self, path, mode):
        if self.fail_open:
            raise OSError("permission denied")
        sftp = self
        if mode.startswith("w"):
            sftp.files[path] = ""

            class _Writer:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def write(self, text):
                    sftp.files[path] += text

            return _Writer()
        return FakeRemoteFile(sftp.files.get(path, "remote-content"))

    def stat(self, path):
        if path not in self.files:
            raise OSError("not found")
        return True

    def listdir(self, path):
        if path == "/bad":
            raise OSError("not found")
        return ["a", "b"]


class TestKaliFileHelpers:
    def test_local_write_and_read_roundtrip(self, tmp_path):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        target = tmp_path / "sub" / "f.txt"
        assert ex.write_file(str(target), "hello") is True
        assert target.read_text() == "hello"
        assert ex.read_file(str(target)) == "hello"

    def test_local_write_bare_filename_fails_documented(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        assert ex.write_file("plain.txt", "data") is False
        assert not (tmp_path / "plain.txt").exists()

    def test_local_write_into_file_path_fails(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        assert ex.write_file(str(blocker / "child.txt"), "data") is False

    def test_local_read_missing_returns_none(self, tmp_path):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        assert ex.read_file(str(tmp_path / "nope.txt")) is None

    def test_remote_write_and_read(self):
        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        ex._sftp = FakeSFTP()
        assert ex.write_file("/tmp/f", "abc") is True
        assert ex.read_file("/tmp/f") == "abc"

    def test_remote_write_error_returns_false(self):
        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        sftp = FakeSFTP()
        sftp.fail_open = True
        ex._sftp = sftp
        assert ex.write_file("/tmp/f", "abc") is False

    def test_remote_read_error_returns_none(self):
        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        sftp = FakeSFTP()
        sftp.fail_open = True
        ex._sftp = sftp
        assert ex.read_file("/tmp/f") is None

    def test_file_exists_local_and_remote(self, tmp_path):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        present = tmp_path / "yes.txt"
        present.write_text("x")
        assert ex.file_exists(str(present)) is True
        assert ex.file_exists(str(tmp_path / "no.txt")) is False
        ex2 = ke.KaliExecutor(ke.KaliConfig(host="h"))
        ex2._sftp = FakeSFTP()
        ex2._sftp.files["/tmp/f"] = FakeRemoteFile()
        assert ex2.file_exists("/tmp/f") is True
        assert ex2.file_exists("/tmp/other") is False

    def test_list_dir_local_and_remote(self, tmp_path):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        (tmp_path / "one.txt").write_text("x")
        assert ex.list_dir(str(tmp_path)) == ["one.txt"]
        assert ex.list_dir(str(tmp_path / "missing")) == []
        ex2 = ke.KaliExecutor(ke.KaliConfig(host="h"))
        ex2._sftp = FakeSFTP()
        assert ex2.list_dir("/ok") == ["a", "b"]
        assert ex2.list_dir("/bad") == []

    def test_read_file_lines(self, tmp_path):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        target = tmp_path / "lines.txt"
        target.write_text("a\nb\n")
        assert ex.read_file_lines(str(target)) == ["a", "b"]
        assert ex.read_file_lines(str(tmp_path / "missing.txt")) == []


class TestKaliToolDetection:
    def test_check_tool_requires_name_in_output(self, monkeypatch):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        calls = []

        def fake_run(cmd, timeout=120):
            calls.append(cmd)
            return {"success": True, "stdout": "sqlmap 1.7", "stderr": ""}

        monkeypatch.setattr(ex, "run", fake_run)
        assert ex.check_tool("sqlmap") is True
        assert "which sqlmap" in calls[0]

    def test_check_tool_version_without_name_reports_missing_documented(self, monkeypatch):
        ex = ke.KaliExecutor(ke.KaliConfig(local=True))
        monkeypatch.setattr(
            ex,
            "run",
            lambda cmd, timeout=120: {"success": True, "stdout": "1.7.2", "stderr": ""},
        )
        assert ex.check_tool("nmap") is False

    def test_detect_local_tools_uses_which_exit_and_output(self, monkeypatch):
        def fake_run(cmd, capture_output=True, text=True, timeout=5):
            tool = cmd[1]
            if tool == "nmap":
                return types.SimpleNamespace(returncode=0, stdout="/usr/bin/nmap\n")
            if tool == "ffuf":
                return types.SimpleNamespace(returncode=0, stdout="")
            raise FileNotFoundError("which not found")

        monkeypatch.setattr(ke.subprocess, "run", fake_run)
        monkeypatch.setattr(ke, "KALI_KNOWN_TOOLS", ["nmap", "ffuf", "missing"])
        assert ke.detect_local_tools() == {"nmap": True, "ffuf": False, "missing": False}


class TestKaliGlobals:
    def test_init_kali_without_host_does_not_connect(self, monkeypatch):
        monkeypatch.setattr(ke, "KALI_INSTANCE", None)
        ex = ke.init_kali()
        assert isinstance(ex, ke.KaliExecutor)
        assert ke.get_kali() is ex
        assert ke.is_available() is False

    def test_init_kali_with_host_connects(self, monkeypatch):
        box = []
        _install_fake_paramiko(monkeypatch, box)
        monkeypatch.setattr(ke, "KALI_INSTANCE", None)
        ex = ke.init_kali(host="10.0.0.1", password="pw")
        assert ex._client is box[0]
        assert ke.get_kali() is ex

    def test_is_available_without_instance(self, monkeypatch):
        monkeypatch.setattr(ke, "KALI_INSTANCE", None)
        assert ke.is_available() is False

    def test_init_kali_local_sets_tools(self, monkeypatch):
        monkeypatch.setattr(ke, "KALI_INSTANCE", None)
        monkeypatch.setattr(ke, "KALI_LOCAL_TOOLS", {})
        monkeypatch.setattr(ke, "detect_local_tools", lambda: {"nmap": True, "sqlmap": False})
        ex = ke.init_kali_local()
        assert ex.config.local is True
        assert ke.is_available() is True
        assert ke.has_tool("nmap") is True
        assert ke.has_tool("sqlmap") is False
        assert ke.has_tool("unknown") is False

    def test_has_tool_without_scan_returns_false(self, monkeypatch):
        monkeypatch.setattr(ke, "KALI_LOCAL_TOOLS", {})
        assert ke.has_tool("nmap") is False

    def test_is_available_requires_live_client(self, monkeypatch):
        ex = ke.KaliExecutor(ke.KaliConfig(host="h"))
        monkeypatch.setattr(ke, "KALI_INSTANCE", ex)
        assert ke.is_available() is False
        ex._client = object()
        assert ke.is_available() is True


# ---------------------------------------------------------------------------
# interactive_shell
# ---------------------------------------------------------------------------


class ScriptedExec:
    def __init__(self, responses):
        self.responses = list(responses)
        self.commands = []

    def __call__(self, cmd):
        self.commands.append(cmd)
        result = self.responses.pop(0) if self.responses else ""
        if isinstance(result, Exception):
            raise result
        return result


def _feed_input(monkeypatch, lines):
    iterator = iter(lines)

    def fake_input(_prompt=""):
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr(builtins, "input", fake_input)


class TestPTYShellBasics:
    def test_run_records_history_and_extracts_output(self):
        exec_cmd = ScriptedExec([{"output": "result"}])
        shell = ish.PTYShell(exec_cmd)
        assert shell._run("id") == "result"
        assert shell._history == ["id"]

    def test_run_handles_non_dict_and_missing_output(self):
        exec_cmd = ScriptedExec(["plain", {"other": 1}])
        shell = ish.PTYShell(exec_cmd)
        assert shell._run("a") == "plain"
        assert shell._run("b") == ""

    def test_detect_pty_true_and_false(self):
        assert ish.PTYShell(ScriptedExec(["pty_ok"]))._detect_pty() is True
        assert ish.PTYShell(ScriptedExec([""]))._detect_pty() is False


class TestUpgrade:
    def test_python_pty_path(self):
        shell = ish.PTYShell(ScriptedExec(["pty_ok"]))
        out = shell.upgrade()
        assert out["success"] is True and out["method"] == "python_pty"
        assert len(out["steps"]) == 4

    def test_script_pty_fallback(self):
        shell = ish.PTYShell(ScriptedExec(["", "FOUND"]))
        out = shell.upgrade()
        assert out["method"] == "script_pty" and out["success"] is True

    def test_socat_pty_fallback(self):
        shell = ish.PTYShell(ScriptedExec(["", "", "FOUND"]))
        out = shell.upgrade()
        assert out["method"] == "socat_pty" and "socat" in out["steps"][0]

    def test_no_pty_available(self):
        shell = ish.PTYShell(ScriptedExec(["", "", ""]))
        out = shell.upgrade()
        assert out == {"success": False, "method": None, "steps": []}


class TestDownload:
    def test_roundtrip(self):
        data = b"payload data 0123456789"
        encoded = base64.b64encode(data).decode()
        shell = ish.PTYShell(ScriptedExec([encoded + "\n"]))
        assert shell.download("/remote/f") == data

    def test_tiny_file_fails_documented(self):
        data = b"A" * 15
        assert len(base64.b64encode(data)) == 20
        shell = ish.PTYShell(ScriptedExec([base64.b64encode(data).decode()]))
        assert shell.download("/remote/small") is None

    def test_minimum_downloadable_size(self):
        data = b"B" * 16
        shell = ish.PTYShell(ScriptedExec([base64.b64encode(data).decode()]))
        assert shell.download("/remote/f") == data

    def test_invalid_base64_returns_none(self):
        shell = ish.PTYShell(ScriptedExec(["x" * 21]))
        assert shell.download("/remote/f") is None

    def test_empty_output_returns_none(self):
        shell = ish.PTYShell(ScriptedExec([""]))
        assert shell.download("/remote/f") is None


class TestUpload:
    def test_upload_success_with_size_verification(self, tmp_path):
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hello")
        exec_cmd = ScriptedExec(["UPLOAD_OK", "rwxrwxrwx 1 root root 5 Oct 11 file"])
        shell = ish.PTYShell(exec_cmd)
        assert shell.upload(str(local), "/remote/payload.bin") is True
        assert exec_cmd.commands[0].startswith("echo '")
        assert "base64 -d > '/remote/payload.bin'" in exec_cmd.commands[0]

    def test_upload_verification_missing_returns_false(self, tmp_path):
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hello")
        shell = ish.PTYShell(ScriptedExec(["UPLOAD_OK", "permission denied"]))
        assert shell.upload(str(local), "/remote/payload.bin") is False

    def test_upload_size_substring_verification_false_positive_documented(self, tmp_path):
        local = tmp_path / "payload.bin"
        local.write_bytes(b"abc")
        exec_cmd = ScriptedExec(["UPLOAD_OK", "Jan 11 03:00 /remote/payload.bin"])
        shell = ish.PTYShell(exec_cmd)
        assert shell.upload(str(local), "/remote/payload.bin") is True

    def test_upload_missing_local_file_returns_false(self, tmp_path):
        exec_cmd = ScriptedExec([])
        shell = ish.PTYShell(exec_cmd)
        assert shell.upload(str(tmp_path / "nope.bin"), "/remote/x") is False
        assert exec_cmd.commands == []


class TestPortForward:
    def test_builds_base64_launcher(self):
        shell = ish.PTYShell(ScriptedExec([""]))
        out = shell.port_forward(8080, "10.0.0.5", 80)
        assert out["forward_to"] == "10.0.0.5:80" and out["local_port"] == 8080
        encoded = out["command"].split("b64decode('")[1].split("')")[0]
        code = base64.b64decode(encoded).decode()
        assert "s.bind(('0.0.0.0',8080))" in code
        assert "t.connect(('10.0.0.5',80))" in code

    def test_reports_success_even_when_exec_failed_documented(self):
        shell = ish.PTYShell(ScriptedExec(["sh: nohup: not found"]))
        out = shell.port_forward(9090, "10.0.0.6", 443)
        assert out["success"] is True


class TestInteractive:
    def test_exit_immediately(self, monkeypatch):
        exec_cmd = ScriptedExec([])
        shell = ish.PTYShell(exec_cmd)
        _feed_input(monkeypatch, ["exit"])
        shell.interactive()
        assert exec_cmd.commands == []

    def test_eof_breaks_loop(self, monkeypatch):
        exec_cmd = ScriptedExec([])
        _feed_input(monkeypatch, [])
        ish.PTYShell(exec_cmd).interactive()
        assert exec_cmd.commands == []

    def test_empty_line_skipped_and_plain_command_printed(self, monkeypatch, capsys):
        exec_cmd = ScriptedExec(["uid=33(www-data)"])
        shell = ish.PTYShell(exec_cmd)
        _feed_input(monkeypatch, ["", "id", "quit"])
        shell.interactive()
        assert exec_cmd.commands == ["id"]
        assert "uid=33(www-data)" in capsys.readouterr().out

    def test_cd_updates_cwd(self, monkeypatch):
        exec_cmd = ScriptedExec(["/var/www"])
        shell = ish.PTYShell(exec_cmd)
        _feed_input(monkeypatch, ["cd /var/www", "exit"])
        shell.interactive()
        assert shell._cwd == "/var/www"
        assert exec_cmd.commands == ["cd /var/www && pwd"]

    def test_interactive_download_writes_file(self, monkeypatch, tmp_path, capsys):
        data = b"artifact-content-1234567890"
        exec_cmd = ScriptedExec([base64.b64encode(data).decode() + "\n"])
        shell = ish.PTYShell(exec_cmd)
        monkeypatch.chdir(tmp_path)
        _feed_input(monkeypatch, ["download /remote/flag.txt", "exit"])
        shell.interactive()
        assert (tmp_path / "flag.txt").read_bytes() == data
        assert "Downloaded" in capsys.readouterr().out

    def test_interactive_download_failure_message(self, monkeypatch, capsys):
        shell = ish.PTYShell(ScriptedExec([""]))
        _feed_input(monkeypatch, ["download /remote/missing", "exit"])
        shell.interactive()
        assert "Download failed" in capsys.readouterr().out

    def test_interactive_upload_messages(self, monkeypatch, capsys):
        shell = ish.PTYShell(ScriptedExec([]))
        monkeypatch.setattr(shell, "upload", lambda local, remote: True)
        _feed_input(monkeypatch, ["upload /local /remote", "exit"])
        shell.interactive()
        assert "Upload OK" in capsys.readouterr().out

        shell2 = ish.PTYShell(ScriptedExec([]))
        monkeypatch.setattr(shell2, "upload", lambda local, remote: False)
        _feed_input(monkeypatch, ["upload /local /remote", "exit"])
        shell2.interactive()
        assert "Upload failed" in capsys.readouterr().out

    def test_interactive_forward_requires_four_parts(self, monkeypatch, capsys):
        shell = ish.PTYShell(ScriptedExec([]))
        calls = []
        monkeypatch.setattr(
            shell,
            "port_forward",
            lambda lp, th, tp: (
                calls.append((lp, th, tp)) or {"local_port": lp, "forward_to": "%s:%d" % (th, tp)}
            ),
        )
        _feed_input(monkeypatch, ["forward 1080 10.0.0.5", "forward 1080 10.0.0.5 80", "exit"])
        shell.interactive()
        assert calls == [(1080, "10.0.0.5", 80)]
        assert "Port forward" in capsys.readouterr().out

    def test_interactive_upgrade_prints_steps(self, monkeypatch, capsys):
        shell = ish.PTYShell(ScriptedExec([]))
        monkeypatch.setattr(
            shell,
            "upgrade",
            lambda: {"success": True, "steps": ["step-one", "step-two"]},
        )
        _feed_input(monkeypatch, ["upgrade", "exit"])
        shell.interactive()
        out = capsys.readouterr().out
        assert "step-one" in out and "step-two" in out


# ---------------------------------------------------------------------------
# responder_kit
# ---------------------------------------------------------------------------


class FakeSocket:
    def __init__(self, packets=None):
        self.option_calls = []
        self.bound = None
        self.packets = list(packets or [])
        self.closed = False

    def setsockopt(self, level, option, value):
        self.option_calls.append((level, option, value))

    def bind(self, addr):
        self.bound = addr

    def recvfrom(self, _size):
        if self.packets:
            return self.packets.pop(0)
        raise OSError("socket closed")

    def close(self):
        self.closed = True


class RaisingCloseSocket(FakeSocket):
    def close(self):
        raise OSError("already closed")


class DummyThread:
    last = None

    def __init__(self, target=None, daemon=None):
        self.target = target
        self.daemon = daemon
        self.started = False
        DummyThread.last = self

    def start(self):
        self.started = True


def _socket_shim(factory):
    return types.SimpleNamespace(
        AF_INET=socket.AF_INET,
        SOCK_DGRAM=socket.SOCK_DGRAM,
        SOL_SOCKET=socket.SOL_SOCKET,
        SO_REUSEADDR=socket.SO_REUSEADDR,
        IPPROTO_IP=socket.IPPROTO_IP,
        IP_MULTICAST_TTL=socket.IP_MULTICAST_TTL,
        IP_ADD_MEMBERSHIP=socket.IP_ADD_MEMBERSHIP,
        inet_aton=socket.inet_aton,
        socket=factory,
    )


def make_llmnr_query(name):
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = bytearray()
    for label in name.split("."):
        question.append(len(label))
        question.extend(label.encode())
    question.append(0)
    question.extend(b"\x00\x20\x00\x01")
    return header + bytes(question)


class TestLLMNRPoisoner:
    def test_start_binds_port_and_joins_multicast(self, monkeypatch):
        socks = []

        def factory(*_args):
            sock = FakeSocket()
            socks.append(sock)
            return sock

        monkeypatch.setattr(rk, "socket", _socket_shim(factory))
        monkeypatch.setattr(rk.threading, "Thread", DummyThread)
        poisoner = rk.LLMNRPoisoner("10.0.0.9", "/tmp/hashes.txt")
        poisoner.start()
        assert poisoner._running is True
        assert len(socks) == 1
        sock = socks[0]
        assert sock.bound == ("10.0.0.9", rk.LLMNR_PORT)
        assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in sock.option_calls
        assert (socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2) in sock.option_calls
        mreq = socket.inet_aton(rk.LLMNR_MULTICAST) + socket.inet_aton("0.0.0.0")
        assert (socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq) in sock.option_calls
        assert DummyThread.last.target == poisoner._listen
        assert DummyThread.last.daemon is True
        assert DummyThread.last.started is True
        poisoner.start()
        assert len(socks) == 1

    def test_start_failure_is_silent(self, monkeypatch):
        def boom(*_args):
            raise OSError("address in use")

        monkeypatch.setattr(rk, "socket", _socket_shim(boom))
        poisoner = rk.LLMNRPoisoner()
        poisoner.start()
        assert poisoner._running is False
        assert poisoner._sock is None

    def test_stop_closes_socket(self):
        poisoner = rk.LLMNRPoisoner()
        sock = FakeSocket()
        poisoner._sock = sock
        poisoner._running = True
        poisoner.stop()
        assert sock.closed is True and poisoner._running is False
        poisoner.stop()

    def test_stop_swallows_close_error(self):
        poisoner = rk.LLMNRPoisoner()
        poisoner._sock = RaisingCloseSocket()
        poisoner._running = True
        poisoner.stop()
        assert poisoner._running is False

    def test_listen_captures_query(self):
        packet = make_llmnr_query("WPAD")
        poisoner = rk.LLMNRPoisoner()
        poisoner._sock = FakeSocket([(packet, ("192.168.1.5", 5355))])
        poisoner._running = True
        poisoner._listen()
        captured = poisoner.get_captured()
        assert len(captured) == 1
        entry = captured[0]
        assert entry["query"] == "WPAD"
        assert entry["source_ip"] == "192.168.1.5"
        assert entry["source_port"] == 5355
        assert entry["raw_size"] == len(packet)
        assert entry["timestamp"]

    def test_listener_death_keeps_running_flag_documented(self, monkeypatch):
        poisoner = rk.LLMNRPoisoner()
        poisoner._sock = FakeSocket([])
        poisoner._running = True
        poisoner._listen()
        assert poisoner._running is True
        started = []
        monkeypatch.setattr(rk, "socket", _socket_shim(lambda *a: started.append(1)))
        poisoner.start()
        assert started == []

    def test_multi_label_query(self):
        packet = make_llmnr_query("fileserver.corp.local")
        poisoner = rk.LLMNRPoisoner()
        poisoner._handle_packet(packet, ("10.0.0.2", 5355))
        assert poisoner.get_captured()[0]["query"] == "fileserver.corp.local"

    def test_short_packet_ignored(self):
        poisoner = rk.LLMNRPoisoner()
        poisoner._handle_packet(b"\x00" * 11, ("1.2.3.4", 1))
        assert poisoner.captured_hashes == []

    def test_zero_question_packet_ignored(self):
        poisoner = rk.LLMNRPoisoner()
        poisoner._handle_packet(b"\x00" * 12, ("1.2.3.4", 1))
        assert poisoner.captured_hashes == []

    def test_truncated_label_does_not_crash(self):
        packet = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xffab"
        poisoner = rk.LLMNRPoisoner()
        poisoner._handle_packet(packet, ("::1", 9999))
        assert poisoner.get_captured()[0]["query"] == "ab"

    def test_get_captured_returns_copy(self):
        poisoner = rk.LLMNRPoisoner()
        poisoner._handle_packet(make_llmnr_query("X"), ("1.1.1.1", 5355))
        snapshot = poisoner.get_captured()
        snapshot.append({"fake": True})
        assert len(poisoner.captured_hashes) == 1

    def test_capture_file_never_written_documented(self, tmp_path):
        target = tmp_path / "hashes.txt"
        poisoner = rk.LLMNRPoisoner(capture_file=str(target))
        poisoner._handle_packet(make_llmnr_query("WPAD"), ("1.1.1.1", 5355))
        assert poisoner.captured_hashes
        assert not target.exists()

    def test_handle_packet_exception_swallowed_silently(self, monkeypatch):
        class BoomDatetime:
            @staticmethod
            def utcnow():
                raise RuntimeError("clock broken")

        monkeypatch.setattr(rk, "datetime", BoomDatetime)
        poisoner = rk.LLMNRPoisoner()
        poisoner._handle_packet(make_llmnr_query("X"), ("1.1.1.1", 5355))
        assert poisoner.captured_hashes == []


class TestNBTNSPoisoner:
    def test_start_binds_and_threads(self, monkeypatch):
        socks = []

        def factory(*_args):
            sock = FakeSocket()
            socks.append(sock)
            return sock

        monkeypatch.setattr(rk, "socket", _socket_shim(factory))
        monkeypatch.setattr(rk.threading, "Thread", DummyThread)
        poisoner = rk.NBTNSPoisoner("10.0.0.9")
        poisoner.start()
        assert poisoner._running is True
        assert socks[0].bound == ("10.0.0.9", rk.NBT_NS_PORT)
        assert DummyThread.last.target == poisoner._listen
        poisoner.start()
        assert len(socks) == 1

    def test_start_failure_is_silent(self, monkeypatch):
        def boom(*_args):
            raise OSError("address in use")

        monkeypatch.setattr(rk, "socket", _socket_shim(boom))
        poisoner = rk.NBTNSPoisoner()
        poisoner.start()
        assert poisoner._running is False and poisoner._sock is None

    def test_listen_captures_packets(self):
        poisoner = rk.NBTNSPoisoner()
        poisoner._sock = FakeSocket(
            [
                (b"packet-one", ("10.0.0.3", 137)),
                (b"packet-two", ("10.0.0.4", 137)),
            ]
        )
        poisoner._running = True
        poisoner._listen()
        captured = poisoner.get_captured()
        assert len(captured) == 2
        assert captured[0]["type"] == "nbt_ns"
        assert captured[0]["source_ip"] == "10.0.0.3"
        assert captured[0]["raw_size"] == len(b"packet-one")

    def test_stop_and_copy(self):
        poisoner = rk.NBTNSPoisoner()
        poisoner._sock = FakeSocket()
        poisoner._running = True
        poisoner.stop()
        assert poisoner._running is False
        poisoner.captured.append({"x": 1})
        assert poisoner.get_captured() == [{"x": 1}]
        poisoner.captured.clear()

    def test_stop_swallows_close_error(self):
        poisoner = rk.NBTNSPoisoner()
        poisoner._sock = RaisingCloseSocket()
        poisoner._running = True
        poisoner.stop()
        assert poisoner._running is False


class RecordingPoisoner:
    def __init__(self):
        self.started = 0
        self.stopped = 0
        self.entries = []

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def get_captured(self):
        return list(self.entries)


class TestResponderKit:
    def test_creates_poisoners_with_listen_ip(self):
        kit = rk.ResponderKit("10.1.1.1")
        assert kit.llmnr.listen_ip == "10.1.1.1"
        assert kit.nbtns.listen_ip == "10.1.1.1"

    def test_start_stop_delegate(self):
        kit = rk.ResponderKit()
        kit.llmnr = RecordingPoisoner()
        kit.nbtns = RecordingPoisoner()
        kit.start()
        assert kit._running is True
        assert kit.llmnr.started == 1 and kit.nbtns.started == 1
        kit.stop()
        assert kit._running is False
        assert kit.llmnr.stopped == 1 and kit.nbtns.stopped == 1

    def test_get_results_trims_details_to_last_20(self):
        kit = rk.ResponderKit()
        kit.llmnr = RecordingPoisoner()
        kit.nbtns = RecordingPoisoner()
        kit.llmnr.entries = [{"i": i} for i in range(25)]
        kit.nbtns.entries = [{"j": j} for j in range(2)]
        out = kit.get_results()
        assert out["llmnr_queries"] == 25
        assert out["nbtns_packets"] == 2
        assert len(out["llmnr_details"]) == 20
        assert out["llmnr_details"][0]["i"] == 5
        assert out["nbtns_details"] == [{"j": 0}, {"j": 1}]

    def test_capture_for_duration_sleeps_then_returns(self, monkeypatch):
        kit = rk.ResponderKit()
        events = []
        monkeypatch.setattr(kit, "start", lambda: events.append("start"))
        monkeypatch.setattr(kit, "stop", lambda: events.append("stop"))
        monkeypatch.setattr(kit, "get_results", lambda: {"captured": True})
        slept = []
        monkeypatch.setattr(rk.time, "sleep", lambda duration: slept.append(duration))
        out = kit.capture_for_duration(7)
        assert slept == [7]
        assert events == ["start", "stop"]
        assert out == {"captured": True}

    def test_bind_failure_reports_zero_results_silently_documented(self, monkeypatch):
        def boom(*_args):
            raise OSError("address in use")

        monkeypatch.setattr(rk, "socket", _socket_shim(boom))
        kit = rk.ResponderKit()
        kit.start()
        assert kit._running is True
        assert kit.llmnr._running is False
        assert kit.nbtns._running is False
        assert kit.get_results() == {
            "llmnr_queries": 0,
            "nbtns_packets": 0,
            "llmnr_details": [],
            "nbtns_details": [],
        }
