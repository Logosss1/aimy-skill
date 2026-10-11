"""Coverage tests for tools/lateral_move.py, tools/ai_vuln_hunter.py,
tools/mobile_scanner.py and tools/cloud_pwn.py.

subprocess / ssh / cloud APIs are mocked; APK and IPA inputs are synthetic ZIP
archives built in tmp_path. No network, no external binaries.
"""

import base64
import subprocess
import zipfile
from types import SimpleNamespace
from unittest import mock

import pytest

from tools import ai_vuln_hunter as avh
from tools import cloud_pwn as cp
from tools import lateral_move as lm
from tools import mobile_scanner as ms

# ===========================================================================
# lateral_move
# ===========================================================================

RSA_KEY = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz\n"
           "-----END RSA PRIVATE KEY-----")


def make_exec(outputs, raise_for=()):
    def exec_fn(cmd):
        for needle, value in outputs.items():
            if needle in cmd:
                if needle in raise_for:
                    raise RuntimeError("exec boom")
                return {"output": value}
        return {"output": ""}

    return exec_fn


def test_steal_ssh_keys_finds_keys_and_hosts():
    exec_fn = make_exec({
        "known_hosts": ("github.com ssh-rsa AAAAB3Nza\n"
                        "# comment line\n"
                        "gitlab.com ssh-ed25519 BBBB\n"),
        "/root/.ssh/id_rsa": RSA_KEY,
        "/root/.ssh/id_ed25519": "",
    })
    r = lm.steal_ssh_keys(exec_fn)
    assert r["hosts"] == ["github.com", "gitlab.com"]
    assert len(r["keys"]) == 1
    key = r["keys"][0]
    assert key["path"] == "/root/.ssh/id_rsa"
    assert key["key_type"] == "rsa"
    assert key["base64"].endswith("...")
    assert r["success"] is True
    assert r["note"] == "Found 1 keys, 2 known hosts"


def test_steal_ssh_keys_wildcard_path_requires_ls_output():
    exec_fn = make_exec({
        "ls -la /home/": "",
        "/home/*/.ssh/id_rsa": RSA_KEY,
    })
    r = lm.steal_ssh_keys(exec_fn)
    assert r["keys"] == []
    assert r["success"] is False


def test_steal_ssh_keys_wildcard_path_with_output():
    exec_fn = make_exec({
        "ls -la /home/": "drwx------ 2 bob bob 4096 .ssh",
        "/home/*/.ssh/id_rsa": RSA_KEY,
    })
    r = lm.steal_ssh_keys(exec_fn)
    assert r["keys"][0]["path"] == "/home/*/.ssh/id_rsa"


def test_steal_ssh_keys_exec_errors_are_swallowed():
    def exec_fn(cmd):
        raise OSError("no shell")

    r = lm.steal_ssh_keys(exec_fn)
    assert r["success"] is False
    assert r["keys"] == []
    assert r["hosts"] == []


def test_steal_ssh_keys_accepts_plain_string_result():
    r = lm.steal_ssh_keys(
        lambda cmd: "host1 ssh-rsa AAAA" if "known_hosts" in cmd else "")
    assert "host1" in r["hosts"]


@pytest.mark.parametrize("text,expected", [
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "openssh"),
    ("-----BEGIN ED25519 PRIVATE KEY-----", "ed25519"),
    ("ecdsa-sha2-nistp256", "ecdsa"),
    ("-----BEGIN RSA PRIVATE KEY-----", "rsa"),
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp"),
    ("nothing here", "unknown"),
])
def test_detect_key_type(text, expected):
    assert lm._detect_key_type(text) == expected


def test_ssh_key_login_success(monkeypatch):
    run = mock.Mock(return_value=SimpleNamespace(
        returncode=0, stdout="host\nuid=0(root) gid=0(root)\nroot\n", stderr=""))
    monkeypatch.setattr(lm.subprocess, "run", run)
    monkeypatch.setattr(lm.os, "chmod", lambda *a: None)
    monkeypatch.setattr(lm.os, "unlink", lambda *a: None)
    mopen = mock.mock_open()
    monkeypatch.setattr("builtins.open", mopen)
    key_b64 = base64.b64encode(b"KEYDATA").decode()
    r = lm.ssh_key_login("10.0.0.5", "root", key_b64, port=2222)
    assert r["success"] is True
    assert r["host"] == "10.0.0.5"
    assert r["user"] == "root"
    assert "uid=0" in r["output"]
    cmd = run.call_args.args[0]
    assert cmd[0] == "ssh"
    assert "-i" in cmd
    assert "root@10.0.0.5" in cmd
    assert cmd[-1] == "hostname;id;whoami"
    assert run.call_args.kwargs["timeout"] == 15
    mopen().write.assert_called_once_with("KEYDATA")


def test_ssh_key_login_failure(monkeypatch):
    run = mock.Mock(return_value=SimpleNamespace(
        returncode=255, stdout="", stderr="Permission denied (publickey)"))
    monkeypatch.setattr(lm.subprocess, "run", run)
    monkeypatch.setattr(lm.os, "chmod", lambda *a: None)
    monkeypatch.setattr(lm.os, "unlink", lambda *a: None)
    monkeypatch.setattr("builtins.open", mock.mock_open())
    key_b64 = base64.b64encode(b"KEYDATA").decode()
    r = lm.ssh_key_login("10.0.0.5", "root", key_b64)
    assert r["success"] is False
    assert r["error"].startswith("Permission denied")


def test_ssh_key_login_timeout(monkeypatch):
    monkeypatch.setattr(lm.subprocess, "run",
                        mock.Mock(side_effect=subprocess.TimeoutExpired("ssh", 15)))
    monkeypatch.setattr(lm.os, "chmod", lambda *a: None)
    monkeypatch.setattr(lm.os, "unlink", lambda *a: None)
    monkeypatch.setattr("builtins.open", mock.mock_open())
    key_b64 = base64.b64encode(b"KEYDATA").decode()
    r = lm.ssh_key_login("10.0.0.5", "root", key_b64)
    assert r["error"] == "timeout"


def test_ssh_key_login_write_error(monkeypatch):
    monkeypatch.setattr("builtins.open",
                        mock.Mock(side_effect=PermissionError("read-only fs")))
    r = lm.ssh_key_login("10.0.0.5", "root", base64.b64encode(b"K").decode())
    assert "read-only fs" in r["error"]


def test_ssh_key_bruteforce_hosts_breaks_on_success(monkeypatch):
    calls = []

    def fake_login(host, user, key, port):
        calls.append((host, port))
        return {"success": host == "b" and port == 22}

    monkeypatch.setattr(lm, "ssh_key_login", fake_login)
    results = lm.ssh_key_bruteforce_hosts("key", "root",
                                          host_list=["a", "b", "c"], ports=[22, 2222])
    assert results == [{"success": True, "host": "b", "port": 22}]
    assert calls == [("a", 22), ("a", 2222), ("b", 22), ("c", 22), ("c", 2222)]


def test_ssh_key_bruteforce_defaults():
    assert lm.ssh_key_bruteforce_hosts("key") == []


def test_smb_exec_psexec_windows_branch(monkeypatch):
    run = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr(lm.subprocess, "run", run)
    monkeypatch.setattr(lm.os, "name", "nt")
    r = lm.smb_exec_psexec("10.0.0.5", "whoami", "bob", "pw", domain="CORP")
    assert r["success"] is True
    assert r["output"] == "ok"
    cmd = run.call_args.args[0]
    assert cmd[:2] == ["psexec", "\\\\10.0.0.5"]
    assert cmd[cmd.index("-u") + 1] == "CORP\\bob"
    assert cmd[cmd.index("-p") + 1] == "pw"
    assert r["method"] == "smb_psexec"


def test_smb_exec_psexec_windows_failure_output(monkeypatch):
    run = mock.Mock(return_value=SimpleNamespace(returncode=1, stdout="", stderr="denied"))
    monkeypatch.setattr(lm.subprocess, "run", run)
    monkeypatch.setattr(lm.os, "name", "nt")
    r = lm.smb_exec_psexec("10.0.0.5", "whoami", "bob", "pw")
    assert r["success"] is False
    assert r["output"] == "denied"


def test_smb_exec_psexec_windows_exception(monkeypatch):
    monkeypatch.setattr(lm.subprocess, "run", mock.Mock(side_effect=OSError("boom")))
    monkeypatch.setattr(lm.os, "name", "nt")
    r = lm.smb_exec_psexec("10.0.0.5", "whoami", "bob", "pw")
    assert r["error"] == "boom"


def test_smb_exec_psexec_posix_branch(monkeypatch):
    run = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="uid=0", stderr=""))
    monkeypatch.setattr(lm.subprocess, "run", run)
    monkeypatch.setattr(lm.os, "name", "posix")
    r = lm.smb_exec_psexec("10.0.0.5", "id", "bob", "pw", domain="CORP")
    assert r["success"] is True
    assert r["method"] == "impacket_psexec"
    assert run.call_args.args[0][0] == "impacket-psexec"
    assert run.call_args.args[0][1] == "CORP/bob:pw@10.0.0.5"


def test_smb_exec_psexec_posix_missing_impacket(monkeypatch):
    monkeypatch.setattr(lm.subprocess, "run", mock.Mock(side_effect=FileNotFoundError))
    monkeypatch.setattr(lm.os, "name", "posix")
    r = lm.smb_exec_psexec("10.0.0.5", "id", "bob", "pw")
    assert r["error"] == "impacket not installed"


def test_smb_exec_psexec_posix_generic_error(monkeypatch):
    monkeypatch.setattr(lm.subprocess, "run", mock.Mock(side_effect=OSError("exec boom")))
    monkeypatch.setattr(lm.os, "name", "posix")
    r = lm.smb_exec_psexec("10.0.0.5", "id", "bob", "pw")
    assert r["error"] == "exec boom"


def test_crack_ssh_passwords_finds_weak_password(monkeypatch):
    exec_fn = make_exec({"grep -E 'sh$'": "root\nadmin\n"})

    def fake_run(cmd, **kwargs):
        password = cmd[2]
        return SimpleNamespace(returncode=0 if password == "toor" else 1,
                               stdout="uid=0", stderr="")

    monkeypatch.setattr(lm.subprocess, "run", fake_run)
    r = lm.crack_ssh_passwords(exec_fn)
    assert r["success"] is True
    assert {"user": "root", "password": "toor"} in r["found"]
    assert {"user": "admin", "password": "toor"} in r["found"]


def test_crack_ssh_passwords_none_found(monkeypatch):
    exec_fn = make_exec({"grep -E 'sh$'": "root\n"})
    monkeypatch.setattr(lm.subprocess, "run",
                        mock.Mock(return_value=SimpleNamespace(returncode=1, stdout="", stderr="")))
    r = lm.crack_ssh_passwords(exec_fn, wordlist=["one", "two"])
    assert r["success"] is False
    assert r["found"] == []


def test_crack_ssh_passwords_exec_failure_falls_back_to_root(monkeypatch):
    def exec_fn(cmd):
        raise OSError("no shell")

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(lm.subprocess, "run", fake_run)
    lm.crack_ssh_passwords(exec_fn, wordlist=["x"])
    assert calls and calls[0][-2] == "root@localhost"


def test_crack_ssh_passwords_swallows_ssh_errors(monkeypatch):
    exec_fn = make_exec({"grep -E 'sh$'": "root\n"})
    monkeypatch.setattr(lm.subprocess, "run",
                        mock.Mock(side_effect=subprocess.TimeoutExpired("ssh", 8)))
    r = lm.crack_ssh_passwords(exec_fn, wordlist=["x", "y"])
    assert r["found"] == []


def test_enum_ssh_config():
    exec_fn = make_exec({
        "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes",
        "/root/.ssh/config": "",
    })
    r = lm.enum_ssh_config(exec_fn)
    assert r["success"] is True
    assert r["configs"] == [{
        "path": "/etc/ssh/sshd_config",
        "content": "PermitRootLogin yes\nPasswordAuthentication yes",
    }]


def test_enum_ssh_config_empty_and_errors():
    r = lm.enum_ssh_config(lambda cmd: {"output": ""})
    assert r["success"] is False
    assert r["configs"] == []

    def boom(cmd):
        raise OSError("no")

    assert lm.enum_ssh_config(boom)["configs"] == []


# ===========================================================================
# ai_vuln_hunter
# ===========================================================================

class FakeElapsed:
    def __init__(self, value):
        self._value = value

    def total_seconds(self):
        return self._value


class FakeHTTPResponse:
    def __init__(self, status=200, text="ok", elapsed=0.1, headers=None):
        self.status_code = status
        self.text = text
        self.elapsed = FakeElapsed(elapsed)
        self.headers = headers or {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def get(self, url, params=None, timeout=None):
        payload = list(params.values())[0] if params else None
        self.calls.append((url, payload, timeout))
        return self.responder(payload)


def test_deep_sample_endpoint_detects_anomalies():
    def responder(payload):
        if payload == "'":
            return FakeHTTPResponse(status=500, text="SQL syntax error near", elapsed=0.1)
        return FakeHTTPResponse(status=200, text="ok body", elapsed=0.1)

    sess = FakeSession(responder)
    gatherer = avh.IntelligenceGatherer(sess, timeout=3.0)
    sample = gatherer.deep_sample_endpoint("http://t/item", "id")
    assert sample["baseline"]["status"] == 200
    assert sample["baseline"]["headers"] == {"Content-Type": "text/html"}
    assert len(sample["responses"]) == 19  # baseline + 18 default mutants
    assert sess.calls[0] == ("http://t/item", "1", 3.0)
    anomalies = gatherer.report.anomaly_observations
    assert len(anomalies) == 1
    assert anomalies[0]["payload"] == "'"
    assert "status 200 -> 500" in anomalies[0]["description"]
    assert "server error" in anomalies[0]["description"]


def test_deep_sample_endpoint_baseline_error():
    def responder(payload):
        raise ConnectionError("down")

    gatherer = avh.IntelligenceGatherer(FakeSession(responder))
    sample = gatherer.deep_sample_endpoint("http://t/", "p")
    assert sample["error"] == "down"
    assert sample["responses"] == []


def test_deep_sample_endpoint_custom_mutants_and_mutant_error():
    def responder(payload):
        if payload == "boom":
            raise ConnectionError("nope")
        return FakeHTTPResponse()

    gatherer = avh.IntelligenceGatherer(FakeSession(responder))
    sample = gatherer.deep_sample_endpoint("http://t/", "p", mutant_payloads=["a", "boom"])
    assert len(sample["responses"]) == 2  # baseline + "a", "boom" raised


@pytest.mark.parametrize("baseline,response,expect", [
    ({"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     {"status": 500, "size": 100, "time": 0.1, "body_preview": "ok"},
     "status 200 -> 500"),
    ({"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     {"status": 200, "size": 300, "time": 0.1, "body_preview": "ok"},
     "size 100 -> 300 (3.0x)"),
    ({"status": 200, "size": 400, "time": 0.1, "body_preview": "ok"},
     {"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     "shrunk 0.2x"),
    ({"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     {"status": 200, "size": 100, "time": 5.0, "body_preview": "ok"},
     "slow (5.0s vs 0.1s baseline)"),
    ({"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     {"status": 503, "size": 100, "time": 0.1, "body_preview": "ok"},
     "server error"),
    ({"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     {"status": 200, "size": 100, "time": 0.1, "body_preview": "mySQL error"},
     "error_signal:SQL"),
    ({"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     {"status": 200, "size": 100, "time": 0.1, "body_preview": "ok"},
     None),
])
def test_compute_diff(baseline, response, expect):
    diff = avh.IntelligenceGatherer(None)._compute_diff(baseline, response)
    if expect is None:
        assert diff == {"anomaly": False, "reason": ""}
    else:
        assert diff["anomaly"] is True
        assert expect in diff["reason"]


def test_probe_mutation_matrix_groups():
    sess = FakeSession(lambda payload: FakeHTTPResponse())
    gatherer = avh.IntelligenceGatherer(sess)
    result = gatherer.probe_mutation_matrix("http://t/", "p")
    assert set(result["mutations"]) == {
        "type_coercion", "sql_prefix", "path_manipulation",
        "noop_payloads", "special_chars", "verb_tampering",
    }
    assert sum(len(v) for v in result["mutations"].values()) == 47
    assert gatherer.report.anomaly_observations == []


def test_probe_mutation_matrix_records_anomaly():
    def responder(payload):
        if payload == "true":
            return FakeHTTPResponse(status=500)
        return FakeHTTPResponse()

    gatherer = avh.IntelligenceGatherer(FakeSession(responder))
    result = gatherer.probe_mutation_matrix("http://t/", "p")
    assert gatherer.report.anomaly_observations
    anomaly = gatherer.report.anomaly_observations[0]
    assert anomaly["baseline_status"] == 200
    assert anomaly["response_status"] == 500
    assert result["mutations"]["type_coercion"][1]["anomaly"] is True


def test_probe_mutation_matrix_swallows_errors():
    def responder(payload):
        raise ConnectionError("x")

    gatherer = avh.IntelligenceGatherer(FakeSession(responder))
    result = gatherer.probe_mutation_matrix("http://t/", "p")
    assert all(group == [] for group in result["mutations"].values())


def test_deep_scan_endpoint_records_parameter_behavior():
    sess = FakeSession(lambda payload: FakeHTTPResponse())
    gatherer = avh.IntelligenceGatherer(sess)
    result = gatherer.deep_scan_endpoint("http://t/", "id")
    assert "deep_sample" in result and "mutation_matrix" in result
    assert list(gatherer.report.parameter_behavior) == ["http://t/?id"]
    assert len(gatherer.report.parameter_behavior["http://t/?id"]) == 1


def test_explore_skips_internal_findings():
    sess = FakeSession(lambda payload: FakeHTTPResponse())
    gatherer = avh.IntelligenceGatherer(sess)
    findings = {
        "__meta": {"url": "http://t/", "param": "x"},
        "sqli": {"url": "http://t/item", "param": "id"},
        "no_url": {"param": "id"},
    }
    result = gatherer.explore("http://t/", findings,
                              recon_data={"technologies": ["nginx", "php"]})
    assert result["deep_results_count"] == 1
    assert result["report"].target == "http://t/"
    assert result["report"].technology_stack == ["nginx", "php"]
    assert "=== TARGET INTELLIGENCE BRIEF ===" in result["brief"]
    assert "Tech: nginx, php" in result["brief"]


def test_generate_target_brief_wrapper():
    result = avh.generate_target_brief(FakeSession(lambda p: FakeHTTPResponse()),
                                       "http://t/", findings={})
    assert result["deep_results_count"] == 0
    assert result["report"].target == "http://t/"


def test_intel_report_brief_contents():
    report = avh.IntelReport(
        target="http://t/",
        technology_stack=["nginx"],
        discovered_endpoints=[
            {"status": 200, "path": "/a", "size": 100},
            {"status": 404, "path": "/missing", "size": 10},
        ],
        error_signatures=[{"pattern": "SQL error", "count": 3}],
        anomaly_observations=[{"description": "status changed"}],
        timing_profiles={"http://t/slow": 3.5, "http://t/fast": 0.1},
        parameter_behavior={"http://t/?id": [{}, {}]},
    )
    brief = report.brief()
    assert "Target: http://t/" in brief
    assert "Tech: nginx" in brief
    assert "Endpoints (1 interesting):" in brief
    assert "[200] /a (100 bytes)" in brief
    assert "SQL error (occurrences: 3)" in brief
    assert "Anomalies:" in brief
    assert "status changed" in brief
    assert "Slow endpoints:" in brief
    assert "http://t/slow: 3.5s" in brief
    assert "Parameters tested: http://t/?id(2)" in brief


def test_intel_report_brief_empty():
    brief = avh.IntelReport().brief()
    assert brief == "=== TARGET INTELLIGENCE BRIEF ===\nTarget: "


# ===========================================================================
# mobile_scanner
# ===========================================================================

ANDROID_MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
    '<application android:allowBackup="true" android:debuggable="true" '
    'android:usesCleartextTraffic="true">'
    '<activity android:exported="true"/>'
    '<service android:exported="true"/>'
    '<uses-permission android:name="android.permission.CAMERA"/>'
    '<uses-permission android:name="android.permission.READ_SMS"/>'
    'setJavaScriptEnabled'
    '</application></manifest>'
)


def build_apk(path, manifest=ANDROID_MANIFEST, dex_count=1, with_nsc=True):
    with zipfile.ZipFile(str(path), "w") as zf:
        if manifest is not None:
            zf.writestr("AndroidManifest.xml", manifest)
        for i in range(dex_count):
            zf.writestr("classes%d.dex" % i, "dex")
        if with_nsc:
            zf.writestr("res/xml/network_security_config.xml", "<x/>")
        zf.writestr("res/raw/data.txt", "data")
    return str(path)


def test_android_scan_full_findings(tmp_path):
    apk = build_apk(tmp_path / "app.apk", dex_count=4)
    result = ms.scan_android(apk)
    assert result["apk_path"] == apk
    assert result["dex_count"] == 4
    assert result["resource_count"] == 2
    categories = {f["category"] for f in result["findings"]}
    assert {"backup", "debug", "components", "network", "permissions",
            "webview", "obfuscation"} <= categories
    assert result["total_findings"] == len(result["findings"])
    assert result["by_severity"]["high"] >= 2
    backup = [f for f in result["findings"] if f["category"] == "backup"][0]
    assert backup["cwe"] == "CWE-312"
    components = [f for f in result["findings"] if f["category"] == "components"][0]
    assert components["title"] == "2 Exported Components"
    perms = [f for f in result["findings"] if f["category"] == "permissions"][0]
    assert "CAMERA" in perms["title"]


def test_android_scan_missing_manifest(tmp_path):
    apk = build_apk(tmp_path / "app.apk", manifest=None)
    result = ms.scan_android(apk)
    titles = [f["title"] for f in result["findings"]]
    assert "AndroidManifest.xml not readable" in titles


def test_android_scan_network_security_info(tmp_path):
    manifest = '<manifest><application/></manifest>'
    apk = build_apk(tmp_path / "app.apk", manifest=manifest, with_nsc=False)
    result = ms.scan_android(apk)
    titles = [f["title"] for f in result["findings"]]
    assert "No Network Security Config" in titles


def test_android_scan_manifest_declares_nsc(tmp_path):
    manifest = '<manifest><application android:networkSecurityConfig="@xml/nsc"/></manifest>'
    apk = build_apk(tmp_path / "app.apk", manifest=manifest, with_nsc=False)
    result = ms.scan_android(apk)
    titles = [f["title"] for f in result["findings"]]
    assert "No Network Security Config" not in titles


def test_android_scan_not_found(tmp_path):
    result = ms.scan_android(str(tmp_path / "missing.apk"))
    assert "APK not found" in result["error"]


def test_android_scan_invalid_zip(tmp_path):
    p = tmp_path / "bad.apk"
    p.write_text("not a zip")
    result = ms.scan_android(str(p))
    assert result["error"] == "Invalid APK file"


def test_android_scan_plain_http_only(tmp_path):
    manifest = '<manifest><application/></manifest>'
    apk = build_apk(tmp_path / "app.apk", manifest=manifest)
    result = ms.scan_android(apk)
    titles = [f["title"] for f in result["findings"]]
    assert "Plain HTTP Usage" not in titles


IOS_PLIST = (
    "<plist>NSAppTransportSecurity NSAllowsArbitraryLoads=true UIWebView</plist>"
)


def build_ipa(path, plist=IOS_PLIST, frameworks=("JSPatch", "SSLKillSwitch")):
    with zipfile.ZipFile(str(path), "w") as zf:
        if plist is not None:
            zf.writestr("Payload/App.app/Info.plist", plist)
        for fw in frameworks:
            zf.writestr("Payload/App.app/Frameworks/%s.framework/%s" % (fw, fw), "bin")
    return str(path)


def test_ios_scan_full_findings(tmp_path):
    ipa = build_ipa(tmp_path / "app.ipa")
    result = ms.scan_ios(ipa)
    assert result["framework_count"] == 2
    titles = [f["title"] for f in result["findings"]]
    assert "ATS Disabled (NSAllowsArbitraryLoads=true)" in titles
    assert "No File Protection" in titles
    assert "JSPatch Detected" in titles
    assert "SSLKillSwitch Detected" in titles
    assert "UIWebView Usage" in titles
    assert result["total_findings"] == 5


def test_ios_scan_clean_plist(tmp_path):
    ipa = build_ipa(tmp_path / "app.ipa", plist="<plist><dict/></plist>", frameworks=())
    result = ms.scan_ios(ipa)
    titles = [f["title"] for f in result["findings"]]
    assert titles == ["No File Protection"]
    assert result["framework_count"] == 0


def test_ios_scan_ats_without_arbitrary_loads(tmp_path):
    plist = ("<plist><dict><key>NSAppTransportSecurity</key><dict>"
             "<key>NSAllowsArbitraryLoads</key><false/></dict></dict></plist>")
    ipa = build_ipa(tmp_path / "app.ipa", plist=plist, frameworks=())
    result = ms.scan_ios(ipa)
    titles = [f["title"] for f in result["findings"]]
    assert "ATS Disabled (NSAllowsArbitraryLoads=true)" not in titles


def test_ios_scan_not_found(tmp_path):
    result = ms.scan_ios(str(tmp_path / "missing.ipa"))
    assert "IPA not found" in result["error"]


def test_ios_scan_invalid_zip(tmp_path):
    p = tmp_path / "bad.ipa"
    p.write_text("not a zip")
    result = ms.scan_ios(str(p))
    assert result["error"] == "Invalid IPA file"


class FakeZip:
    """ZipFile stand-in whose entries raise on read()."""

    def __init__(self, names):
        self._names = names

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def namelist(self):
        return list(self._names)

    def read(self, name):
        raise OSError("corrupt entry: %s" % name)


def test_android_scan_unreadable_manifest(monkeypatch, tmp_path):
    p = tmp_path / "app.apk"
    p.write_bytes(b"placeholder")
    monkeypatch.setattr(ms.zipfile, "ZipFile",
                        lambda path, mode: FakeZip(["AndroidManifest.xml"]))
    result = ms.scan_android(str(p))
    titles = [f["title"] for f in result["findings"]]
    assert "AndroidManifest.xml not readable" in titles


def test_ios_scan_unreadable_plist(monkeypatch, tmp_path):
    p = tmp_path / "app.ipa"
    p.write_bytes(b"placeholder")
    monkeypatch.setattr(ms.zipfile, "ZipFile",
                        lambda path, mode: FakeZip(["Payload/App.app/Info.plist"]))
    result = ms.scan_ios(str(p))
    assert result["total_findings"] == 1
    assert result["findings"][0]["title"] == "No File Protection"


# ===========================================================================
# cloud_pwn
# ===========================================================================

def test_parse_aws_credentials_space_separated_format():
    text = ("AccessKeyId AKIAIOSFODNN7EXAMPLE SecretAccessKey wJalrXUtnFEMI "
            "SessionToken FwoGZXIvYXdz Region us-west-2")
    creds = cp.parse_aws_credentials(text)
    assert creds == {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI",
        "session_token": "FwoGZXIvYXdz",
        "region": "us-west-2",
    }


def test_parse_aws_role_arn():
    creds = cp.parse_aws_credentials(
        "role: arn:aws:iam::123456789012:role/AdminAccess please")
    assert creds["role_arn"] == "arn:aws:iam::123456789012:role/AdminAccess"


def test_parse_aws_colon_space_separator():
    # 修复: 分隔符 (: 空格) 被消费, 取到真正的值
    creds = cp.parse_aws_credentials("AccessKeyId: AKIAIOSFODNN7EXAMPLE, Region: us-east-1")
    assert creds["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
    assert creds["region"] == "us-east-1"


def test_parse_aws_equals_separator():
    # 修复: 无空格逗号分隔格式也能正确截断
    creds = cp.parse_aws_credentials("AccessKeyId=AKIA,Region=us-west-2")
    assert creds["access_key_id"] == "AKIA"
    assert creds["region"] == "us-west-2"


def test_parse_gcp_credentials_equals():
    # 修复: 贪婪截断到空白/分隔符, 不再只取 1 个字符
    creds = cp.parse_gcp_credentials("access_token=ya29token123 project_id=corp-proj")
    assert creds["access_token"] == "ya29token123"
    assert creds["project_id"] == "corp-proj"


def test_parse_azure_credentials_equals():
    creds = cp.parse_azure_credentials("access_token=eyJhbGci tenant_id=ten-1234")
    assert creds["access_token"] == "eyJhbGci"
    assert creds["tenant_id"] == "ten-1234"


def test_cloud_regex_constants():
    assert cp.AWS_ROLE_ARN_RE.search("x arn:aws:iam::1:role/r y").group(0) == "arn:aws:iam::1:role/r"
    assert cp.SUBNET_RE.search("in subnet-ab12cd here").group(0) == "subnet-ab12cd"
    assert cp.VPC_RE.search("vpc-0abc123").group(0) == "vpc-0abc123"
    assert cp.AMI_RE.search("ami-deadbeef").group(0) == "ami-deadbeef"
    assert cp.INSTANCE_ID_RE.search("i-0abcdef12").group(0) == "i-0abcdef12"
    assert cp.S3_BUCKET_RE.search("mybucket.s3.amazonaws.com").group(0) == \
        "mybucket.s3.amazonaws.com"


def test_exploit_aws_missing_credentials():
    result = cp.CloudPwn().exploit_aws({})
    assert result["success"] is False
    assert result["error"] == "Missing AWS access key or secret key"


def test_exploit_aws_success(monkeypatch):
    run = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="{}", stderr=""))
    monkeypatch.setattr(cp.subprocess, "run", run)
    creds = {"access_key_id": "AKIA1", "secret_access_key": "SEC1",
             "session_token": "TOK1", "region": "eu-west-1"}
    result = cp.CloudPwn().exploit_aws(creds)
    assert result["success"] is True
    assert len(result["actions"]) == 6
    assert result["actions"][0]["check"] == "sts_get_caller_identity"
    env = run.call_args.kwargs["env"]
    assert env["AWS_ACCESS_KEY_ID"] == "AKIA1"
    assert env["AWS_SECRET_ACCESS_KEY"] == "SEC1"
    assert env["AWS_SESSION_TOKEN"] == "TOK1"
    assert env["AWS_DEFAULT_REGION"] == "eu-west-1"
    assert run.call_args.kwargs["timeout"] == 30


def test_exploit_aws_skips_failed_checks(monkeypatch):
    monkeypatch.setattr(cp.subprocess, "run",
                        mock.Mock(return_value=SimpleNamespace(returncode=1,
                                                              stdout="err", stderr="")))
    result = cp.CloudPwn().exploit_aws(
        {"access_key_id": "A", "secret_access_key": "S"})
    assert result["success"] is False
    assert result["actions"] == []


def test_exploit_aws_timeout_is_swallowed(monkeypatch):
    monkeypatch.setattr(cp.subprocess, "run",
                        mock.Mock(side_effect=subprocess.TimeoutExpired("aws", 30)))
    result = cp.CloudPwn().exploit_aws(
        {"access_key_id": "A", "secret_access_key": "S"})
    assert result["success"] is False
    assert result["actions"] == []


def test_exploit_aws_generic_error_is_swallowed(monkeypatch):
    monkeypatch.setattr(cp.subprocess, "run", mock.Mock(side_effect=OSError("no aws cli")))
    result = cp.CloudPwn().exploit_aws(
        {"access_key_id": "A", "secret_access_key": "S"})
    assert result["success"] is False


class FakeCloudResponse:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data if data is not None else {}

    def json(self):
        return self._data


def test_exploit_gcp_missing_token():
    result = cp.CloudPwn().exploit_gcp({})
    assert result["error"] == "Missing GCP access token"


def test_exploit_gcp_success():
    pwn = cp.CloudPwn()
    pwn.session = mock.Mock()
    pwn.session.get.return_value = FakeCloudResponse(200, {"items": [{"name": "vm1"}]})
    result = pwn.exploit_gcp({"access_token": "tok", "project_id": "proj"})
    assert result["success"] is True
    assert len(result["actions"]) == 3
    assert "proj" in pwn.session.get.call_args.args[0]
    assert pwn.session.get.call_args.kwargs["headers"] == {"Authorization": "Bearer tok"}


def test_exploit_gcp_non_200():
    pwn = cp.CloudPwn()
    pwn.session = mock.Mock()
    pwn.session.get.return_value = FakeCloudResponse(403, {})
    result = pwn.exploit_gcp({"access_token": "tok"})
    assert result["success"] is False
    assert result["actions"] == []


def test_exploit_gcp_request_error():
    pwn = cp.CloudPwn()
    pwn.session = mock.Mock()
    pwn.session.get.side_effect = OSError("offline")
    result = pwn.exploit_gcp({"access_token": "tok"})
    assert result["success"] is False


def test_exploit_azure_missing_token():
    result = cp.CloudPwn().exploit_azure({})
    assert result["error"] == "Missing Azure access token"


def test_exploit_azure_success():
    pwn = cp.CloudPwn()
    pwn.session = mock.Mock()
    pwn.session.get.return_value = FakeCloudResponse(200, {"value": ["sub1"]})
    result = pwn.exploit_azure({"access_token": "tok"})
    assert result["success"] is True
    assert [a["check"] for a in result["actions"]] == ["list_subscriptions", "list_vms"]
    assert "Bearer tok" in pwn.session.get.call_args.kwargs["headers"]["Authorization"]


def test_exploit_azure_request_error():
    pwn = cp.CloudPwn()
    pwn.session = mock.Mock()
    pwn.session.get.side_effect = OSError("offline")
    result = pwn.exploit_azure({"access_token": "tok"})
    assert result["success"] is False


def test_run_prefers_aws(monkeypatch):
    pwn = cp.CloudPwn()
    monkeypatch.setattr(pwn, "exploit_aws", mock.Mock(return_value={
        "provider": "aws", "success": True, "actions": []}))
    text = "AccessKeyId " + "A" * 30 + " SecretAccessKey SECRETVALUE1234567890"
    result = pwn.run(text)
    assert result["provider"] == "aws"
    assert result["raw_creds"]["access_key_id"].endswith("...")
    assert len(result["raw_creds"]["access_key_id"]) == 23
    assert result["raw_creds"]["secret_access_key"].endswith("...")


def test_run_falls_back_to_gcp(monkeypatch):
    pwn = cp.CloudPwn()
    monkeypatch.setattr(pwn, "exploit_gcp", mock.Mock(return_value={
        "provider": "gcp", "success": True, "actions": []}))
    result = pwn.run("access_token=ya29.token.value")
    assert result["provider"] == "gcp"
    assert "raw_creds" in result


def test_run_falls_back_to_azure(monkeypatch):
    pwn = cp.CloudPwn()
    # any "access_token=..." text is captured by the (broken) GCP parser first,
    # so the GCP parse must be forced empty to reach the Azure branch
    monkeypatch.setattr(cp, "parse_gcp_credentials", lambda text: {})
    monkeypatch.setattr(pwn, "exploit_azure", mock.Mock(return_value={
        "provider": "azure", "success": True, "actions": []}))
    result = pwn.run("access_token=eyJhbGciOiJSUzI1NiIs")
    assert result["provider"] == "azure"


def test_run_jwt_token_routed_to_azure(monkeypatch):
    # 修复: JWT 形式 (eyJ...) 的 access_token 路由到 Azure 分支
    pwn = cp.CloudPwn()
    monkeypatch.setattr(pwn, "exploit_gcp", mock.Mock(return_value={
        "provider": "gcp", "success": True, "actions": []}))
    monkeypatch.setattr(pwn, "exploit_azure", mock.Mock(return_value={
        "provider": "azure", "success": True, "actions": []}))
    result = pwn.run("access_token=eyJhbGciOiJSUzI1NiIs")
    assert result["provider"] == "azure"
    pwn.exploit_azure.assert_called_once()
    pwn.exploit_gcp.assert_not_called()


def test_run_project_id_routed_to_gcp(monkeypatch):
    pwn = cp.CloudPwn()
    monkeypatch.setattr(pwn, "exploit_gcp", mock.Mock(return_value={
        "provider": "gcp", "success": True, "actions": []}))
    monkeypatch.setattr(pwn, "exploit_azure", mock.Mock(return_value={
        "provider": "azure", "success": True, "actions": []}))
    result = pwn.run("access_token=ya29abc project_id=corp-proj")
    assert result["provider"] == "gcp"


def test_run_no_credentials():
    result = cp.CloudPwn().run("nothing useful here")
    assert result["provider"] == "unknown"
    assert result["success"] is False
    assert result["error"] == "No usable cloud credentials found"
    hinted = cp.CloudPwn().run("nothing", cloud_hint="gcp")
    assert hinted["provider"] == "gcp"


def test_check_wrapper():
    result = cp.check("no creds at all", cloud_hint="aws")
    assert result["provider"] == "aws"
    assert result["success"] is False
