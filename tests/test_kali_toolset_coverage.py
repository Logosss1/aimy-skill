"""Coverage tests for tools/kali_toolset.py.

All Kali/SSH interactions are mocked: get_kali() is replaced by an in-memory
fake executor and has_tool() is patched. No subprocess/WSL/network is used.
"""

import shlex
from unittest import mock

import pytest

from tools import kali_toolset as kt


class FakeKali:
    """In-memory stand-in for tools.kali_executor.KaliExecutor."""

    def __init__(self, tool_checks=None):
        self.calls = []
        self.queue = []
        self.file_lines = {}
        self.any_log_lines = []
        self.written = {}
        self.tool_checks = tool_checks or {}

    def run(self, cmd, timeout=120):
        self.calls.append({"cmd": cmd, "timeout": timeout})
        if self.queue:
            return self.queue.pop(0)
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    def check_tool(self, tool):
        return self.tool_checks.get(tool, False)

    def read_file_lines(self, path):
        return self.file_lines.get(path) or self.any_log_lines

    def write_file(self, path, content):
        self.written[path] = content
        return True


@pytest.fixture
def kali(monkeypatch):
    fk = FakeKali()
    monkeypatch.setattr(kt, "get_kali", lambda: fk)
    monkeypatch.setattr(kt, "has_tool", lambda name: True)
    return fk


def _no_kali(monkeypatch, missing=False):
    monkeypatch.setattr(kt, "get_kali", lambda: FakeKali() if missing else None)
    if missing:
        monkeypatch.setattr(kt, "has_tool", lambda name: False)


ALL_WRAPPERS = [
    ("sqlmap_detect", lambda: kt.sqlmap_detect("http://t/", "p"), "vulnerable"),
    ("sqlmap_extract", lambda: kt.sqlmap_extract("http://t/", "p"), "success"),
    ("nmap_scan", lambda: kt.nmap_scan("t"), "success"),
    ("ffuf_discover", lambda: kt.ffuf_discover("http://t/"), "success"),
    ("nuclei_scan", lambda: kt.nuclei_scan("http://t/"), "success"),
    ("hydra_brute", lambda: kt.hydra_brute("t"), "success"),
    ("nikto_scan", lambda: kt.nikto_scan("http://t/"), "success"),
    ("gobuster_discover", lambda: kt.gobuster_discover("http://t/"), "success"),
    ("wpscan_scan", lambda: kt.wpscan_scan("http://t/"), "success"),
    ("metasploit_run", lambda: kt.metasploit_run("use x"), "success"),
    ("whatweb_identify", lambda: kt.whatweb_identify("http://t/"), "success"),
]


@pytest.mark.parametrize("name,func,key", ALL_WRAPPERS, ids=[c[0] for c in ALL_WRAPPERS])
def test_no_kali_returns_error(monkeypatch, name, func, key):
    _no_kali(monkeypatch)
    r = func()
    assert r["error"] == "Kali not connected"


CHECKED_TOOL_WRAPPERS = [c for c in ALL_WRAPPERS if c[0] != "sqlmap_extract"]


@pytest.mark.parametrize(
    "name,func,key", CHECKED_TOOL_WRAPPERS, ids=[c[0] for c in CHECKED_TOOL_WRAPPERS]
)
def test_tool_missing_returns_error(monkeypatch, name, func, key):
    _no_kali(monkeypatch, missing=True)
    r = func()
    assert "not found on Kali" in r["error"]


def test_check_tool_fallback_when_has_tool_false(monkeypatch):
    fk = FakeKali(tool_checks={"sqlmap": True})
    monkeypatch.setattr(kt, "get_kali", lambda: fk)
    monkeypatch.setattr(kt, "has_tool", lambda name: False)
    kt.sqlmap_detect("http://t/", "p")
    assert fk.calls, "run() should be reached through check_tool fallback"


# ---------------------------------------------------------------------------
# sqlmap
# ---------------------------------------------------------------------------

SQLMAP_META_OUTPUT = (
    "sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests\n"
    "target is vulnerable\n"
    "web application technology: Apache 2.4.41\n"
    "Parameter: q (GET)\n"
    "    Type: boolean-based blind\n"
    "[12:00:01] [INFO] table 'app'.'users'\n"
    "+----+\n"
    "| id |\n"
    "+----+\n"
    "| 1  |\n"
    "+----+\n"
)


def test_sqlmap_detect_command_construction(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    url = "http://t.example/item?id=1"
    kt.sqlmap_detect(url, "q", dbms="mysql")
    cmd = kali.calls[0]["cmd"]
    assert "-u %s?%s=1" % (shlex.quote(url), shlex.quote("q")) in cmd
    assert "--batch" in cmd
    assert "--level=3 --risk=2" in cmd
    assert "--random-agent --flush-session" in cmd
    assert "--dbms=mysql" in cmd
    assert cmd.endswith("2>&1")
    assert kali.calls[0]["timeout"] == 300


def test_sqlmap_detect_not_injectable_short_circuit(kali):
    kali.queue = [
        {
            "success": True,
            "stdout": "all tested parameters do not appear to be injectable ... not injectable",
        }
    ]
    r = kt.sqlmap_detect("http://t/", "p")
    assert r["vulnerable"] is False
    assert r["note"] == "sqlmap: not injectable"


def test_sqlmap_detect_vulnerable_parses_metadata(kali):
    kali.queue = [{"success": True, "stdout": SQLMAP_META_OUTPUT}]
    r = kt.sqlmap_detect("http://t/", "q")
    assert r["vulnerable"] is True
    assert r["dbms"] == "Apache 2.4.41"
    assert r["technique"] == "boolean-based blind"
    assert r["injected_param"] == "q"
    assert r["injection_type"] == "GET"
    assert r["data"]["app.users"] == [" id ", " 1  "]
    assert r["tool"] == "sqlmap"
    assert r["error"] is None


def test_sqlmap_detect_reads_retrieved_values_from_log(kali):
    kali.queue = [{"success": True, "stdout": "is vulnerable\n"}]
    kali.any_log_lines = [
        "[12:00:02] [INFO] retrieved: 'admin'",
        "[12:00:03] [INFO] retrieved: 's3cret'",
    ]
    r = kt.sqlmap_detect("http://t/", "p")
    assert r["data"]["retrieved"] == ["admin", "s3cret"]


def test_sqlmap_detect_vulnerable_without_data_adds_note(kali):
    kali.queue = [{"success": True, "stdout": "the parameter is vulnerable\n"}]
    r = kt.sqlmap_detect("http://t/", "p")
    assert "note" in r["data"]
    assert "sqlmap_extract()" in r["data"]["note"]


def test_sqlmap_detect_raw_output_truncated(kali):
    kali.queue = [{"success": True, "stdout": "A" * 5000}]
    r = kt.sqlmap_detect("http://t/", "p")
    assert len(r["raw_output"]) == 2000


def test_sqlmap_detect_elapsed_measured(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    r = kt.sqlmap_detect("http://t/", "p")
    assert isinstance(r["elapsed"], float)


EXTRACT_DBS_OUT = "[*] information_schema\n[*] app\n[*] *\n"
EXTRACT_TABLES_OUT = "+-------+\n| users |\n| orders |\n+-------+\n"
EXTRACT_DUMP_OUT = "Table: users\n[2 entries]\n+----+\n| a |\n| b |\n+----+\n"


def test_sqlmap_extract_full_flow(kali):
    kali.queue = [
        {"success": True, "stdout": EXTRACT_DBS_OUT},
        {"success": True, "stdout": EXTRACT_TABLES_OUT},
        {"success": True, "stdout": EXTRACT_DUMP_OUT},
    ]
    r = kt.sqlmap_extract("http://t/", "p", dbms="mysql")
    assert r["success"] is True
    assert r["data"]["databases"] == ["information_schema", "app"]
    assert r["data"]["tables"] == ["users", "orders"]
    assert r["data"]["dump_users"] == [" a ", " b "]
    assert len(kali.calls) == 3
    assert "--dbs 2>&1" in kali.calls[0]["cmd"]
    assert "--current-db --tables 2>&1" in kali.calls[1]["cmd"]
    assert "--dump-all" in kali.calls[2]["cmd"]
    assert "--dbms=mysql" in kali.calls[0]["cmd"]
    assert kali.calls[2]["timeout"] == 1800


def test_sqlmap_extract_with_explicit_queries(kali):
    # 修复: 传入的 queries 现在真正拼进 sqlmap 命令并返回原始输出
    kali.queue = [{"success": True, "stdout": "current user: root@localhost"}]
    r = kt.sqlmap_extract("http://t/", "p", queries=["--current-user"])
    assert r["success"] is True
    assert r["stdout"] == "current user: root@localhost"
    assert len(kali.calls) == 1
    assert "--current-user" in kali.calls[0]["cmd"]


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

NMAP_OUT = (
    "Host: 10.0.0.5 (target.local)\tStatus: Up\n"
    "Host: 10.0.0.5 (target.local)\tPorts: 22/open/tcp//ssh///, 3306/open/tcp//mysql///\t"
    "Ignored State: closed (998)\n"
    "OS: Linux 5.4 - 5.15\n"
)


def test_nmap_fast_command_and_parse(kali):
    kali.queue = [{"success": True, "stdout": NMAP_OUT}]
    r = kt.nmap_scan("target.local")
    cmd = kali.calls[0]["cmd"]
    assert cmd == "nmap -T4 -F --open -oG - target.local 2>&1"
    assert r["ports"] == [
        {"port": 22, "state": "open", "protocol": "tcp"},
        {"port": 3306, "state": "open", "protocol": "tcp"},
    ]
    assert r["count"] == 2
    assert r["os"] == "Linux 5.4 - 5.15"
    assert r["success"] is True


def test_nmap_full_service_scan_command(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    kt.nmap_scan("10.0.0.5", ports="1-100", fast=False)
    cmd = kali.calls[0]["cmd"]
    assert cmd == "nmap -sV -sC -p 1-100 --open -oG - 10.0.0.5 2>&1"


def test_nmap_parses_open_and_filtered_states(kali):
    kali.queue = [
        {
            "success": True,
            "stdout": "Host: x\tPorts: 443/open/tcp//https///, 123/filtered/tcp///\n" + "B" * 5000,
        }
    ]
    r = kt.nmap_scan("x")
    assert r["ports"] == [
        {"port": 443, "state": "open", "protocol": "tcp"},
        {"port": 123, "state": "filtered", "protocol": "tcp"},
    ]
    assert len(r["raw"]) == 2000


def test_nmap_open_filtered_state_matched(kali):
    # 修复: open|filtered 组合状态现在能被逐 token 正则识别
    kali.queue = [{"success": True, "stdout": "Host: x\tPorts: 443/open|filtered/tcp///\n"}]
    r = kt.nmap_scan("x")
    assert r["ports"] == [{"port": 443, "state": "open|filtered", "protocol": "tcp"}]


def test_nmap_quotes_dangerous_target(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    kt.nmap_scan("10.0.0.5; rm -rf /")
    assert "10.0.0.5; rm -rf /" in kali.calls[0]["cmd"]
    assert kali.calls[0]["cmd"].count("'") >= 2


# ---------------------------------------------------------------------------
# ffuf / nuclei / hydra / nikto / gobuster / wpscan
# ---------------------------------------------------------------------------


def test_ffuf_json_results(kali):
    payload = (
        '{"results": [{"input": {"FUZZ": "admin"}, "status": 200, "length": 42},'
        ' {"input": {"FUZZ": "api"}, "status": 301, "length": 0}]}'
    )
    kali.queue = [{"success": True, "stdout": payload}]
    r = kt.ffuf_discover("http://t/", extensions="php,bak")
    cmd = kali.calls[0]["cmd"]
    assert "http://t/FUZZ" in cmd
    assert "-fc 404" in cmd
    assert "-e php,bak" in cmd
    assert "cat /tmp/ffuf_out.json" in cmd
    assert r["paths"] == [
        {"path": "admin", "status": 200, "size": 42},
        {"path": "api", "status": 301, "size": 0},
    ]
    assert r["count"] == 2


def test_ffuf_non_json_fallback(kali):
    kali.queue = [{"success": True, "stdout": "FUZZ: /admin\njunk\nFUZZ: /api\n"}]
    r = kt.ffuf_discover("http://t/")
    assert r["paths"] == [{"path": "/admin"}, {"path": "/api"}]


def test_nuclei_jsonl_findings(kali):
    lines = [
        '{"template-id": "CVE-2021-1", "info": {"name": "RCE", "severity": "critical"},'
        ' "matched-at": "http://t/x", "type": "http"}',
        "",
        "not json at all",
    ]
    kali.queue = [{"success": True, "stdout": "\n".join(lines)}]
    r = kt.nuclei_scan("http://t/")
    assert r["findings"] == [
        {
            "template": "CVE-2021-1",
            "name": "RCE",
            "severity": "critical",
            "matched": "http://t/x",
            "type": "http",
        }
    ]
    assert r["count"] == 1


def test_nuclei_templates_override_severity(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    kt.nuclei_scan("http://t/", severity="high", templates="cves/")
    cmd = kali.calls[0]["cmd"]
    assert "-t cves/" in cmd
    assert "-severity" not in cmd


def test_hydra_userlist_command(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    kt.hydra_brute("10.0.0.5", service="ssh", threads=8)
    cmd = kali.calls[0]["cmd"]
    assert "hydra -L " in cmd
    assert "-P " in cmd
    assert "10.0.0.5 ssh -t 8" in cmd
    assert "-s " not in cmd


def test_hydra_single_user_with_port(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    kt.hydra_brute("10.0.0.5", service="ftp", user="root", port=2121)
    cmd = kali.calls[0]["cmd"]
    assert "hydra -l root" in cmd
    assert "-s 2121" in cmd
    assert "ftp" in cmd


def test_hydra_parses_credentials(kali):
    kali.queue = [
        {
            "success": False,
            "stdout": "[2222][ftp] host: 10.0.0.5   login: root   password: toor\n",
        }
    ]
    r = kt.hydra_brute("10.0.0.5")
    assert r["credentials"] == [
        {
            "port": 2222,
            "service": "ftp",
            "username": "root",
            "password": "toor",
        }
    ]
    assert r["success"] is True
    assert r["count"] == 1


def test_hydra_success_reflects_run_without_credentials(kali):
    kali.queue = [{"success": True, "stdout": "no creds here\n"}]
    r = kt.hydra_brute("10.0.0.5")
    assert r["success"] is True
    assert r["credentials"] == []


def test_nikto_json_list(kali):
    payload = (
        '[{"id": "999103", "method": "GET", "url": "/admin/", "msg": "Directory indexing found"}]'
    )
    kali.queue = [{"success": True, "stdout": payload}]
    r = kt.nikto_scan("http://t/", max_time=30, ssl=True)
    assert "-ssl" in kali.calls[0]["cmd"]
    assert "-maxtime 30" in kali.calls[0]["cmd"]
    assert kali.calls[0]["timeout"] == 60
    assert r["findings"] == [
        {
            "id": "999103",
            "method": "GET",
            "url": "/admin/",
            "description": "Directory indexing found",
        }
    ]


def test_nikto_text_fallback(kali):
    kali.queue = [{"success": True, "stdout": "+ OSVDB-3092: /admin/: dir listing\njunk\n"}]
    r = kt.nikto_scan("http://t/")
    assert r["findings"] == [{"id": "OSVDB-3092", "description": "/admin/: dir listing"}]
    assert " -ssl" not in kali.calls[0]["cmd"]


def test_gobuster_parse_status_lines(kali):
    stdout = "/admin (Status: 301)\n/robots.txt (Status: 200)\nnoise\n"
    kali.queue = [{"success": True, "stdout": stdout}]
    r = kt.gobuster_discover("http://t/", extensions="php", threads=10)
    assert "-x php" in kali.calls[0]["cmd"]
    assert "-t 10" in kali.calls[0]["cmd"]
    assert r["paths"] == [
        {"path": "/admin", "status": 301},
        {"path": "/robots.txt", "status": 200},
    ]


def test_gobuster_without_extensions(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    kt.gobuster_discover("http://t/", extensions="")
    assert "-x " not in kali.calls[0]["cmd"]


def test_wpscan_json_findings(kali):
    payload = (
        '{"findings": [{"type": "plugin", "title": "XSS in Plugin",'
        ' "severity": "high", "fixed_in": "1.2.3"}]}'
    )
    kali.queue = [{"success": True, "stdout": payload}]
    r = kt.wpscan_scan("http://t/", enumerate_all=True, api_token="tok123")
    cmd = kali.calls[0]["cmd"]
    assert "--enumerate ap,at,tt,cb,dbe,u,m" in cmd
    assert "--api-token tok123" in cmd
    assert r["vulnerabilities"] == [
        {
            "type": "plugin",
            "title": "XSS in Plugin",
            "severity": "high",
            "fixed_in": "1.2.3",
        }
    ]


def test_wpscan_text_fallback_and_no_enumerate(kali):
    kali.queue = [{"success": True, "stdout": "[!] WordPress 5.0 detected\n"}]
    r = kt.wpscan_scan("http://t/", enumerate_all=False, api_token="")
    assert "--enumerate" not in kali.calls[0]["cmd"]
    assert "--api-token" not in kali.calls[0]["cmd"]
    assert r["vulnerabilities"] == [{"description": "WordPress 5.0 detected"}]


# ---------------------------------------------------------------------------
# metasploit
# ---------------------------------------------------------------------------


def test_metasploit_run_builds_rc_file_and_cleans_up(kali):
    kali.queue = [
        {"success": True, "exit_code": 0, "stdout": "ok", "stderr": ""},
        {"success": True, "exit_code": 0, "stdout": "", "stderr": ""},
    ]
    r = kt.metasploit_run(
        "use exploit/x",
        payload="reverse_tcp",
        lhost="10.0.0.1",
        lport=4444,
        rhost="10.0.0.9",
        rport=8080,
    )
    rc_path = list(kali.written)[0]
    rc = kali.written[rc_path]
    assert rc_path.startswith("/tmp/aimy_msf_") and rc_path.endswith(".rc")
    assert rc.startswith("use exploit/x\n")
    assert "set PAYLOAD reverse_tcp" in rc
    assert "set LHOST 10.0.0.1" in rc
    assert "set LPORT 4444" in rc
    assert "set RHOSTS 10.0.0.9" in rc
    assert "set RPORT 8080" in rc
    assert rc.endswith("exit\n")
    assert "msfconsole -q -r" in kali.calls[0]["cmd"]
    assert kali.calls[1]["cmd"].startswith("rm -f ")
    assert r["success"] is True
    assert r["exit_code"] == 0
    assert r["stdout"] == "ok"


def test_metasploit_run_defaults_always_set_lport_rport(kali):
    kali.queue = [
        {"success": True, "exit_code": 0, "stdout": "", "stderr": ""},
        {"success": True, "exit_code": 0, "stdout": "", "stderr": ""},
    ]
    kt.metasploit_run("use exploit/x")
    rc = list(kali.written.values())[0]
    assert "set LPORT 4444" in rc
    assert "set RPORT 80" in rc
    assert "set PAYLOAD" not in rc
    assert "set LHOST" not in rc


def test_metasploit_exploit_builds_script(monkeypatch):
    captured = {}

    def fake_run(resource_script, payload="", lhost="", lport=4444, rhost="", rport=80):
        captured["rc"] = resource_script
        captured["kwargs"] = {
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "rhost": rhost,
            "rport": rport,
        }
        return {"success": True}

    monkeypatch.setattr(kt, "metasploit_run", fake_run)
    kt.metasploit_exploit(
        "exploit/multi/http/x",
        "10.0.0.9",
        rport=8443,
        payload="windows/meterpreter",
        lhost="10.0.0.1",
        lport=5555,
        ssl=True,
    )
    rc = captured["rc"]
    assert rc.splitlines()[0] == "use exploit/multi/http/x"
    assert "set RHOSTS 10.0.0.9" in rc
    assert "set RPORT 8443" in rc
    assert "set LHOST 10.0.0.1" in rc
    assert "set LPORT 5555" in rc
    assert "set SSL true" in rc
    assert "set ExitOnSession false" in rc
    assert "run -j" in rc
    assert captured["kwargs"] == {
        "payload": "windows/meterpreter",
        "lhost": "10.0.0.1",
        "lport": 5555,
        "rhost": "10.0.0.9",
        "rport": 8443,
    }


def test_metasploit_exploit_without_lhost_lport(monkeypatch):
    captured = {}

    def fake_run(resource_script, **kwargs):
        captured["rc"] = resource_script
        return {"success": True}

    monkeypatch.setattr(kt, "metasploit_run", fake_run)
    kt.metasploit_exploit("aux/x", "10.0.0.9", lhost="", lport=0, ssl=False)
    rc = captured["rc"]
    assert "set LHOST" not in rc
    assert "set LPORT" not in rc
    assert "set SSL" not in rc


# ---------------------------------------------------------------------------
# autoexploit
# ---------------------------------------------------------------------------


def test_autoexploit_sqli(monkeypatch):
    m = mock.Mock(return_value={"vulnerable": True, "data": {"users": ["a"]}})
    monkeypatch.setattr(kt, "sqlmap_detect", m)
    r = kt.autoexploit("http://t/?id=1", "sqli", param="id", extra={"dbms": "mysql"})
    assert r["success"] is True
    assert r["data"] == {"users": ["a"]}
    assert "sqlmap" in r["exploits"]
    assert m.call_args.kwargs["dbms"] == "mysql"


def test_autoexploit_sqli_without_extra(monkeypatch):
    m = mock.Mock(return_value={"vulnerable": False, "data": {}})
    monkeypatch.setattr(kt, "sqlmap_detect", m)
    r = kt.autoexploit("http://t/", "sqli")
    assert "success" not in r
    assert m.call_args.kwargs["dbms"] is None


def test_autoexploit_http_uses_nikto(monkeypatch):
    monkeypatch.setattr(kt, "nikto_scan", mock.Mock(return_value={"findings": [1]}))
    r = kt.autoexploit("http://t/", "http")
    assert r["success"] is True
    assert "nikto" in r["exploits"]


def test_autoexploit_service_uses_hydra(monkeypatch):
    m = mock.Mock(return_value={"credentials": [{"user": "root"}]})
    monkeypatch.setattr(kt, "hydra_brute", m)
    r = kt.autoexploit(
        "http://t/", "service", extra={"service": "ftp", "user": "root", "target": "10.0.0.5"}
    )
    assert r["success"] is True
    assert r["credentials"] == [{"user": "root"}]
    assert m.call_args.kwargs["service"] == "ftp"
    assert m.call_args.args[0] == "10.0.0.5"


def test_autoexploit_wordpress(monkeypatch):
    monkeypatch.setattr(kt, "wpscan_scan", mock.Mock(return_value={"vulnerabilities": [1]}))
    r = kt.autoexploit("http://t/", "wordpress")
    assert r["success"] is True
    assert "wpscan" in r["exploits"]


@pytest.mark.parametrize(
    "url,expected_host,expected_port",
    [
        ("http://target.com/x", "target.com", 80),
        ("https://target.com/x", "target.com", 443),
        ("https://target.com:8443/x", "target.com", 8443),
    ],
)
def test_autoexploit_cmdi_metasploit_url_mapping(monkeypatch, url, expected_host, expected_port):
    m = mock.Mock(return_value={"success": True})
    monkeypatch.setattr(kt, "metasploit_exploit", m)
    r = kt.autoexploit(url, "cmdi")
    assert r["success"] is True
    assert m.call_args.args[1] == expected_host
    assert m.call_args.args[2] == expected_port


def test_autoexploit_lfi_module(monkeypatch):
    m = mock.Mock(return_value={"success": False})
    monkeypatch.setattr(kt, "metasploit_exploit", m)
    kt.autoexploit("http://t/", "lfi")
    assert m.call_args.args[0] == "exploit/unix/webapp/local_file_include"


def test_autoexploit_unknown_type():
    r = kt.autoexploit("http://t/", "nope")
    assert r["success"] is False
    assert "Unknown vulnerability type: nope" == r["error"]


# ---------------------------------------------------------------------------
# whatweb
# ---------------------------------------------------------------------------


def test_whatweb_extracts_technologies(kali):
    kali.queue = [{"success": True, "stdout": "WordPress[5.8], Apache[2.4.41]\n"}]
    r = kt.whatweb_identify("http://t/")
    assert r["technologies"] == ["WordPress", "Apache"]
    assert "whatweb -a 3 --color=never" in kali.calls[0]["cmd"]
    assert kali.calls[0]["timeout"] == 60


def test_whatweb_no_technologies(kali):
    kali.queue = [{"success": True, "stdout": "no brackets here\n"}]
    r = kt.whatweb_identify("http://t/")
    assert r["technologies"] == []


# ---------------------------------------------------------------------------
# misc structural checks
# ---------------------------------------------------------------------------


def test_kali_exploit_map_contents():
    assert kt.KALI_EXPLOIT_MAP["sqli"]["func"] == "sqlmap_detect"
    assert kt.KALI_EXPLOIT_MAP["http"]["tool"] == "nikto"
    assert kt.KALI_EXPLOIT_MAP["wordpress"]["tool"] == "wpscan"


def test_sqlmap_output_dir_constant():
    assert kt.SQLMAP_OUTPUT_DIR == "/tmp/aimy_sqlmap"


def test_uuid_tag_used_for_output_dir(kali):
    kali.queue = [{"success": True, "stdout": ""}]
    kt.sqlmap_detect("http://t/", "p")
    cmd = kali.calls[0]["cmd"]
    assert "--output-dir=/tmp/aimy_sqlmap/" in cmd
