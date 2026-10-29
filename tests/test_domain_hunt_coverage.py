"""Coverage tests for tools/domain_hunt.py.

ldap3 / impacket are replaced with in-memory fakes, sockets are patched and
run_kali_cmd is mocked. Nothing touches the network or a real Kali host.
"""

import sys
import types

import pytest

from tools import domain_hunt as dh
from tools import kali_executor as ke


@pytest.fixture
def fake_kali_cmd(monkeypatch):
    """把 kali_executor.get_kali 替换为内存假执行器并记录命令."""
    calls = []

    class FakeKali:
        def run(self, cmd, timeout=120):
            calls.append(cmd)
            return {"success": True, "stdout": "srv"}

    monkeypatch.setattr(ke, "get_kali", lambda: FakeKali())
    return calls


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class ServerInfo:
    naming_contexts = ["DC=corp,DC=local"]
    other = {"defaultNamingContext": ["DC=corp,DC=local"]}

    def __str__(self):
        return "server-info"


class Attr:
    def __init__(self, value):
        self.value = value


class LdapEntry:
    def __init__(self, dn, attrs):
        self.entry_dn = dn
        self.entry_attributes = list(attrs)
        self._attrs = attrs

    def __getitem__(self, key):
        return self._attrs[key]


def make_ldap3(bind=True, entries=None, search_error=None, raise_on_connect=False):
    mod = types.ModuleType("ldap3")
    mod.ALL = object()
    mod.NTLM = object()
    state = {"conns": []}

    class Server:
        def __init__(self, host, port=389, get_info=None):
            if raise_on_connect:
                raise RuntimeError("ldap down")
            self.host = host
            self.port = port
            self.info = ServerInfo()

    class Connection:
        def __init__(
            self, server, user=None, password=None, receive_timeout=None, authentication=None
        ):
            if raise_on_connect:
                raise RuntimeError("ldap down")
            self.server = server
            self.user = user
            self.password = password
            self.authentication = authentication
            self.entries = list(entries or [])
            self.unbound = False
            state["conns"].append(self)

        def bind(self):
            return bind

        def unbind(self):
            self.unbound = True

        def search(self, *args, **kwargs):
            if search_error:
                raise search_error
            self.search_args = (args, kwargs)

    mod.Server = Server
    mod.Connection = Connection
    return mod, state


def install_fake_impacket(monkeypatch, send_impl):
    constants = types.ModuleType("impacket.krb5.constants")
    constants.PrincipalNameType = types.SimpleNamespace(NT_PRINCIPAL=types.SimpleNamespace(value=1))

    class KerberosError(Exception):
        def __init__(self, code):
            super().__init__("krb %d" % code)
            self._code = code

        def getErrorCode(self):  # noqa: N802 - mirrors impacket's API
            return self._code

    kerberosv5 = types.ModuleType("impacket.krb5.kerberosv5")
    kerberosv5.KerberosError = KerberosError
    kerberosv5.sendKerberos = send_impl

    krb5_types = types.ModuleType("impacket.krb5.types")
    krb5_types.PrincipalName = lambda ptype, name: name

    krb5 = types.ModuleType("impacket.krb5")
    impacket = types.ModuleType("impacket")
    monkeypatch.setitem(sys.modules, "impacket", impacket)
    monkeypatch.setitem(sys.modules, "impacket.krb5", krb5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.constants", constants)
    monkeypatch.setitem(sys.modules, "impacket.krb5.kerberosv5", kerberosv5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.types", krb5_types)
    monkeypatch.setattr(dh, "HAVE_IMPACKET", True)
    return KerberosError


def make_socket_factory(resp=b"", connect_error=None, recv_error=None):
    class FakeSocket:
        instances = []

        def __init__(self, *args, **kwargs):
            self.sent = []
            self.closed = False
            self.timeout = None
            FakeSocket.instances.append(self)

        def settimeout(self, value):
            self.timeout = value

        def connect(self, addr):
            if connect_error:
                raise connect_error
            self.addr = addr

        def send(self, data):
            self.sent.append(data)

        def recv(self, n):
            if recv_error:
                raise recv_error
            return resp

        def close(self):
            self.closed = True

    return FakeSocket


# ---------------------------------------------------------------------------
# constants / flags
# ---------------------------------------------------------------------------


def test_constants():
    assert dh.ASREP_ENCRYPTION_TYPES[23] == "rc4"
    assert dh.ASREP_ENCRYPTION_TYPES[17] == "aes128"
    assert dh.ASREP_ENCRYPTION_TYPES[18] == "aes256"


# ---------------------------------------------------------------------------
# enum_dc
# ---------------------------------------------------------------------------


def test_enum_dc_without_kali_uses_socket(monkeypatch):
    # 修复后不再依赖不存在的 run_kali_cmd; Kali 不可用时走 socket 兜底
    monkeypatch.setattr(dh, "HAVE_LDAP3", False)
    monkeypatch.setattr(ke, "get_kali", lambda: None)
    monkeypatch.setattr(
        dh.socket, "getaddrinfo", lambda *a: [("AF_INET", 1, 6, "", ("10.0.0.1", 389))]
    )
    r = dh.enum_dc("corp.local", "10.0.0.10")
    assert r["dns"]["ldap_srv"] == [("AF_INET", 1, 6, "", ("10.0.0.1", 389))]


def test_enum_dc_dns_success(fake_kali_cmd, monkeypatch):
    monkeypatch.setattr(dh, "HAVE_LDAP3", False)
    r = dh.enum_dc("corp.local", "10.0.0.10")
    assert r["dns"]["ldap_srv"] == "srv"
    assert fake_kali_cmd[0] == "nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local 10.0.0.10"


def test_enum_dc_dns_success_without_dc_ip(fake_kali_cmd, monkeypatch):
    monkeypatch.setattr(dh, "HAVE_LDAP3", False)
    dh.enum_dc("corp.local")
    assert fake_kali_cmd[0] == "nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local"


def test_enum_dc_socket_fallback(monkeypatch):
    monkeypatch.setattr(dh, "HAVE_LDAP3", False)
    monkeypatch.setattr(
        dh.socket, "getaddrinfo", lambda *a: [("AF_INET", 1, 6, "", ("10.0.0.1", 389))]
    )
    monkeypatch.setattr(ke, "get_kali", lambda: None)
    r = dh.enum_dc("corp.local")
    assert r["dns"]["ldap_srv"] == [("AF_INET", 1, 6, "", ("10.0.0.1", 389))]


def test_enum_dc_socket_failure(monkeypatch, fake_kali_cmd):
    monkeypatch.setattr(dh, "HAVE_LDAP3", False)

    def boom(*a):
        raise OSError("no dns")

    monkeypatch.setattr(dh.socket, "getaddrinfo", boom)
    monkeypatch.setattr(ke, "get_kali", lambda: None)
    r = dh.enum_dc("corp.local")
    assert "no dns" in r["dns"]["error"]


def test_enum_dc_ldap_success(fake_kali_cmd, monkeypatch):
    mod, state = make_ldap3(bind=True)
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.enum_dc("corp.local", "10.0.0.10")
    assert r["ldap"]["server_info"] == "server-info"
    assert r["ldap"]["naming_contexts"] == ["DC=corp,DC=local"]
    assert r["ldap"]["domain_dn"] == "DC=corp,DC=local"
    assert state["conns"][0].unbound is True


def test_enum_dc_ldap_bind_failure(fake_kali_cmd, monkeypatch):
    mod, _ = make_ldap3(bind=False)
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.enum_dc("corp.local", "10.0.0.10")
    assert r["ldap"] == {}


def test_enum_dc_ldap_exception(fake_kali_cmd, monkeypatch):
    mod, _ = make_ldap3(raise_on_connect=True)
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.enum_dc("corp.local", "10.0.0.10")
    assert r["ldap"]["error"] == "ldap down"


# ---------------------------------------------------------------------------
# ldap_anonymous_enum
# ---------------------------------------------------------------------------


def test_ldap_anonymous_enum_without_ldap3(monkeypatch):
    monkeypatch.setattr(dh, "HAVE_LDAP3", False)
    r = dh.ldap_anonymous_enum("10.0.0.10")
    assert r["error"] == "ldap3 not available"
    assert r["entries"] == []


def test_ldap_anonymous_enum_success(monkeypatch):
    entry = LdapEntry(
        "CN=alice,DC=corp",
        {
            "sAMAccountName": Attr("alice"),
            "objectClass": Attr(["user", "person"]),
            "description": "plain text",
        },
    )
    mod, _ = make_ldap3(bind=True, entries=[entry])
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.ldap_anonymous_enum("10.0.0.10")
    assert r["success"] is True
    assert r["base_dn"] == "DC=corp,DC=local"
    assert r["entries"] == [
        {
            "dn": "CN=alice,DC=corp",
            "sAMAccountName": "alice",
            "objectClass": "['user', 'person']",
            "description": "plain text",
        }
    ]


def test_ldap_anonymous_enum_explicit_base_dn(monkeypatch):
    mod, _ = make_ldap3(bind=True, entries=[])
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.ldap_anonymous_enum("10.0.0.10", base_dn="DC=x,DC=y")
    assert r["base_dn"] == "DC=x,DC=y"
    assert r["success"] is True


def test_ldap_anonymous_enum_bind_failure(monkeypatch):
    mod, _ = make_ldap3(bind=False)
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.ldap_anonymous_enum("10.0.0.10")
    assert r["error"] == "bind failed"


def test_ldap_anonymous_enum_no_base_dn(monkeypatch):
    mod, _ = make_ldap3(bind=True)
    mod.Server = type(
        "Server",
        (),
        {
            "__init__": lambda self, *a, **k: setattr(
                self,
                "info",
                types.SimpleNamespace(naming_contexts=[], other={"defaultNamingContext": [""]}),
            ),
        },
    )
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.ldap_anonymous_enum("10.0.0.10")
    assert r["error"] == "no base DN"


def test_ldap_anonymous_enum_search_error(monkeypatch):
    mod, _ = make_ldap3(bind=True, search_error=RuntimeError("bad filter"))
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.ldap_anonymous_enum("10.0.0.10")
    assert r["error"] == "search: bad filter"


def test_ldap_anonymous_enum_connection_error(monkeypatch):
    mod, _ = make_ldap3(raise_on_connect=True)
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.ldap_anonymous_enum("10.0.0.10")
    assert r["error"] == "ldap down"


# ---------------------------------------------------------------------------
# asrep_roast
# ---------------------------------------------------------------------------


def test_asrep_roast_without_impacket(monkeypatch):
    monkeypatch.setattr(dh, "HAVE_IMPACKET", False)
    r = dh.asrep_roast("10.0.0.10", "corp.local", ["alice"])
    assert r["error"] == "impacket required for AS-REP roasting"


def test_asrep_roast_finds_roastable_users(monkeypatch):
    classes = {}

    def send_impl(*args, **kwargs):
        username = args[11]
        if username == "vuln":
            return (None, None, types.SimpleNamespace(contents=b"KEYBYTES"), None)
        if username == "nochange":
            raise classes["error"](0x12)
        if username == "kerr":
            raise classes["error"](0x1F)
        raise ValueError("boom")

    classes["error"] = install_fake_impacket(monkeypatch, send_impl)
    r = dh.asrep_roast("10.0.0.10", "corp.local", ["vuln", "nochange", "kerr", "explode"])
    assert r["success"] is True
    assert len(r["asrep_users"]) == 1
    user = r["asrep_users"][0]
    assert user["username"] == "vuln"
    assert user["hash"].startswith("vuln:$krb5asrep$23@CORP.LOCAL:")
    assert "KEYBYTES" not in user["hash"]  # base64 encoded


def test_asrep_roast_key_without_contents(monkeypatch):
    def send_impl(*args, **kwargs):
        return (None, None, "rawkey", None)

    install_fake_impacket(monkeypatch, send_impl)
    r = dh.asrep_roast("10.0.0.10", "corp.local", ["alice"])
    assert r["asrep_users"][0]["hash"].endswith(":rawkey")


def test_asrep_roast_outer_exception(monkeypatch):
    def send_impl(*args, **kwargs):
        raise RuntimeError("nope")

    install_fake_impacket(monkeypatch, send_impl)
    monkeypatch.delattr(sys.modules["impacket.krb5.types"], "PrincipalName")
    r = dh.asrep_roast("10.0.0.10", "corp.local", ["alice"])
    assert r["success"] is False
    assert r["asrep_users"] == []
    assert "PrincipalName" in r["error"]


# ---------------------------------------------------------------------------
# kerberoast
# ---------------------------------------------------------------------------


def test_kerberoast_without_ldap3(monkeypatch):
    monkeypatch.setattr(dh, "HAVE_LDAP3", False)
    r = dh.kerberoast("10.0.0.10", "corp.local", "bob", "pw")
    assert r["error"] == "ldap3 required for SPN enumeration"
    assert r["commands"] == ["impacket-GetUserSPNs -request -dc-ip 10.0.0.10 corp.local/bob:pw"]


def test_kerberoast_finds_spns(monkeypatch):
    entry = types.SimpleNamespace(
        servicePrincipalName=types.SimpleNamespace(
            values=["MSSQLSvc/db.corp.local:1433", b"HTTP/web.corp.local"]
        ),
        sAMAccountName=types.SimpleNamespace(value="svc_sql"),
    )
    mod, state = make_ldap3(bind=True, entries=[entry])
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.kerberoast("10.0.0.10", "corp.local", "bob", "pw")
    assert r["success"] is True
    assert [h["spn"] for h in r["tgs_hashes"]] == [
        "MSSQLSvc/db.corp.local:1433",
        "HTTP/web.corp.local",
    ]
    assert r["tgs_hashes"][0]["user"] == "svc_sql"
    assert r["tgs_hashes"][0]["hash_cmd"].endswith("corp.local/bob:pw")
    assert state["conns"][0].user == "corp.local\\bob"
    assert state["conns"][0].unbound is True


def test_kerberoast_entry_without_spn_attribute(monkeypatch):
    # 修复: 缺 servicePrincipalName 属性的条目被安全跳过, 不再中断枚举
    entry = types.SimpleNamespace(sAMAccountName=types.SimpleNamespace(value="x"))
    mod, _ = make_ldap3(bind=True, entries=[entry])
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.kerberoast("10.0.0.10", "corp.local", "bob", "pw")
    assert r["success"] is True
    assert r["tgs_hashes"] == []


def test_kerberoast_bind_failure(monkeypatch):
    mod, _ = make_ldap3(bind=False)
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.kerberoast("10.0.0.10", "corp.local", "bob", "pw")
    assert r["success"] is False


def test_kerberoast_connection_error(monkeypatch):
    mod, _ = make_ldap3(raise_on_connect=True)
    monkeypatch.setattr(dh, "ldap3", mod, raising=False)
    monkeypatch.setattr(dh, "HAVE_LDAP3", True)
    r = dh.kerberoast("10.0.0.10", "corp.local", "bob", "pw")
    assert r["error"] == "ldap down"


# ---------------------------------------------------------------------------
# smb_enum
# ---------------------------------------------------------------------------


class FakeSMBConnection:
    instances = []

    def __init__(self, target, name, *args, **kwargs):
        self.target = target
        self.signing = True
        self.fail_login = False
        self.login_calls = []
        self.logged_off = False
        self.shares = ["ADMIN$", "C$"]
        FakeSMBConnection.instances.append(self)

    def isSigningRequired(self):  # noqa: N802 - mirrors impacket's API
        return self.signing

    def login(self, user, password, domain=None):
        self.login_calls.append((user, password, domain))
        if self.fail_login:
            raise RuntimeError("denied")

    def listShares(self):  # noqa: N802 - mirrors impacket's API
        return self.shares

    def logoff(self):
        self.logged_off = True


@pytest.fixture
def smb(monkeypatch):
    FakeSMBConnection.instances = []
    monkeypatch.setattr(dh, "SMBConnection", FakeSMBConnection, raising=False)
    monkeypatch.setattr(dh, "HAVE_IMPACKET", True)
    return FakeSMBConnection


def test_smb_enum_without_impacket(monkeypatch):
    monkeypatch.setattr(dh, "HAVE_IMPACKET", False)
    r = dh.smb_enum("10.0.0.10")
    assert r["error"] == "impacket required"


def test_smb_enum_null_session(smb):
    r = dh.smb_enum("10.0.0.10")
    conn = smb.instances[0]
    assert r["null_session"] is True
    assert r["signing"] is True
    assert r["shares"] == ["ADMIN$", "C$"]
    assert r["success"] is True
    assert conn.login_calls == [("", "", None)]
    assert conn.logged_off is True


def test_smb_enum_credentials_with_domain(smb):
    r = dh.smb_enum("10.0.0.10", username="bob", password="pw", domain="CORP")
    assert smb.instances[0].login_calls == [("bob", "pw", "CORP")]
    assert r["null_session"] is False
    assert r["shares"] == ["ADMIN$", "C$"]


def test_smb_enum_credentials_default_domain(smb):
    dh.smb_enum("10.0.0.10", username="bob", password="pw")
    assert smb.instances[0].login_calls == [("bob", "pw", None)]


def test_smb_enum_login_failure_still_success(smb):
    original_init = smb.__init__

    def patched(self, *a, **k):
        original_init(self, *a, **k)
        self.fail_login = True

    smb.__init__ = patched
    try:
        r = dh.smb_enum("10.0.0.10", username="bob", password="bad")
    finally:
        smb.__init__ = original_init
    assert r["error"] == "denied"
    assert r["success"] is True


def test_smb_enum_signing_not_required(smb, monkeypatch):
    original_init = smb.__init__

    def patched(self, *a, **k):
        original_init(self, *a, **k)
        self.signing = False

    monkeypatch.setattr(smb, "__init__", patched)
    r = dh.smb_enum("10.0.0.10")
    assert r["signing"] is False


def test_smb_enum_connection_error(monkeypatch):
    class RaisingSMB:
        def __init__(self, *a, **k):
            raise OSError("smb down")

    monkeypatch.setattr(dh, "SMBConnection", RaisingSMB, raising=False)
    monkeypatch.setattr(dh, "HAVE_IMPACKET", True)
    r = dh.smb_enum("10.0.0.10")
    assert r["success"] is False
    assert r["error"] == "smb down"


# ---------------------------------------------------------------------------
# bloodhound / adcs / gpp
# ---------------------------------------------------------------------------


def test_bloodhound_collect_command():
    r = dh.bloodhound_collect("10.0.0.10", "corp.local", "bob", "pw")
    assert r["success"] is True
    assert r["commands"] == [
        "bloodhound-python -d corp.local -u bob -p 'pw' -dc 10.0.0.10 -c All -ns 10.0.0.10"
    ]
    assert r["output_file"] == "corp.local_bloodhound.zip"


def test_adcs_scan_without_kali(monkeypatch):
    monkeypatch.setattr(ke, "get_kali", lambda: None)
    r = dh.adcs_scan("10.0.0.10", "corp.local")
    assert r["success"] is False
    assert r["note"] == "Kali not connected"


def test_adcs_scan_success(monkeypatch):
    class FakeKali:
        def run(self, cmd, timeout=120):
            return {"success": True, "stdout": "CA Name: corp-CA"}

    monkeypatch.setattr(ke, "get_kali", lambda: FakeKali())
    r = dh.adcs_scan("10.0.0.10", "corp.local")
    assert r["success"] is True
    assert r["raw_output"] == "CA Name: corp-CA"


def test_adcs_scan_fallback(monkeypatch):
    class FakeKali:
        def run(self, cmd, timeout=120):
            return {"success": True, "stdout": "no_adcs_tool"}

    monkeypatch.setattr(ke, "get_kali", lambda: FakeKali())
    r = dh.adcs_scan("10.0.0.10", "corp.local")
    assert r["success"] is False
    assert len(r["commands"]) == 2
    assert r["commands"][0].startswith("certipy find")


def test_check_gpp_password_without_impacket(monkeypatch):
    monkeypatch.setattr(dh, "HAVE_IMPACKET", False)
    r = dh.check_gpp_password("10.0.0.10")
    assert r["success"] is False
    assert len(r["commands"]) == 2
    assert "USER:PASS" in r["commands"][0]


def test_check_gpp_password_with_impacket(monkeypatch):
    monkeypatch.setattr(dh, "HAVE_IMPACKET", True)
    r = dh.check_gpp_password("10.0.0.10", "bob", "pw")
    assert r["success"] is False
    assert r["commands"] == ["impacket-Get-GPPPassword -dc-ip 10.0.0.10 DOMAIN/bob:pw"]


def test_check_gpp_password_format_error(monkeypatch):
    class BadStr:
        def __str__(self):
            raise RuntimeError("bad target")

    monkeypatch.setattr(dh, "HAVE_IMPACKET", True)
    r = dh.check_gpp_password(BadStr())
    assert r["error"] == "bad target"


# ---------------------------------------------------------------------------
# socket based probes
# ---------------------------------------------------------------------------


def test_check_ms17_010_vulnerable(monkeypatch):
    factory = make_socket_factory(resp=b"\x00" * 12)
    monkeypatch.setattr(dh.socket, "socket", factory)
    r = dh.check_ms17_010("10.0.0.10")
    assert r["port_open"] is True
    assert r["vulnerable"] is True
    assert factory.instances[0].closed is True


def test_check_ms17_010_not_vulnerable(monkeypatch):
    factory = make_socket_factory(resp=b"\x00\x00")
    monkeypatch.setattr(dh.socket, "socket", factory)
    r = dh.check_ms17_010("10.0.0.10")
    assert r["port_open"] is True
    assert r["vulnerable"] is False


def test_check_ms17_010_connection_error(monkeypatch):
    factory = make_socket_factory(connect_error=OSError("refused"))
    monkeypatch.setattr(dh.socket, "socket", factory)
    r = dh.check_ms17_010("10.0.0.10")
    assert r["port_open"] is False
    assert r["error"] == "refused"


def test_check_zerologon_checked(monkeypatch):
    factory = make_socket_factory()
    monkeypatch.setattr(dh.socket, "socket", factory)
    r = dh.check_zerologon("10.0.0.10")
    assert r["checked"] is True
    assert r["vulnerable"] is False
    assert len(r["commands"]) == 3
    assert factory.instances[0].closed is True


def test_check_zerologon_unreachable(monkeypatch):
    factory = make_socket_factory(connect_error=OSError("timeout"))
    monkeypatch.setattr(dh.socket, "socket", factory)
    r = dh.check_zerologon("10.0.0.10")
    assert r["error"] == "Cannot connect to DC"
    assert r["checked"] is False


def test_enum_mssql_port_open(monkeypatch):
    factory = make_socket_factory()
    monkeypatch.setattr(dh.socket, "socket", factory)
    r = dh.enum_mssql("10.0.0.10", username="sa", password="pw")
    assert r["port_open"] is True
    assert "mssqlclient" in r["commands"][0]
    assert "sqsh" in r["commands"][1]


def test_enum_mssql_port_closed(monkeypatch):
    factory = make_socket_factory(connect_error=OSError("refused"))
    monkeypatch.setattr(dh.socket, "socket", factory)
    r = dh.enum_mssql("10.0.0.10")
    assert r["port_open"] is False
    assert "commands" not in r


# ---------------------------------------------------------------------------
# domain_audit_summary
# ---------------------------------------------------------------------------


@pytest.fixture
def audit(monkeypatch):
    calls = {}
    defaults = {
        "enum_dc": lambda *a, **k: {"domain": a[0]},
        "ldap_anonymous_enum": lambda *a, **k: {"success": False, "entries": []},
        "smb_enum": lambda *a, **k: {"null_session": False, "signing": True},
        "asrep_roast": lambda *a, **k: {"success": False, "asrep_users": []},
        "check_gpp_password": lambda *a, **k: {"success": False},
        "check_ms17_010": lambda *a, **k: {"vulnerable": False},
        "check_zerologon": lambda *a, **k: {"vulnerable": False},
        "enum_mssql": lambda *a, **k: {"port_open": False},
        "kerberoast": lambda *a, **k: {"success": False, "tgs_hashes": []},
        "bloodhound_collect": lambda *a, **k: {"success": True},
        "adcs_scan": lambda *a, **k: {"success": False},
    }
    for name, fn in defaults.items():

        def wrapper(*a, _fn=fn, _name=name, **k):
            calls[_name] = (a, k)
            return _fn(*a, **k)

        monkeypatch.setattr(dh, name, wrapper)
    return calls


def test_smb_enum_null_session_login_failure(smb, monkeypatch):
    original_init = smb.__init__

    def patched(self, *a, **k):
        original_init(self, *a, **k)
        self.fail_login = True

    monkeypatch.setattr(smb, "__init__", patched)
    r = dh.smb_enum("10.0.0.10")
    assert r["null_session"] is False
    assert r["shares"] == []
    assert r["success"] is True


def test_domain_audit_summary_dc_only(audit):
    r = dh.domain_audit_summary("corp.local", "10.0.0.10")
    assert r["success"] is True
    assert "ldap_anonymous_enum" in audit and "smb_enum" in audit
    assert "asrep_roast" not in audit
    assert "kerberoast" not in audit
    assert r["recommendations"] == []


def test_domain_audit_summary_critical_findings(audit, monkeypatch):
    monkeypatch.setattr(
        dh, "ldap_anonymous_enum", lambda *a, **k: {"success": True, "entries": [{"dn": "x"}]}
    )
    monkeypatch.setattr(dh, "smb_enum", lambda *a, **k: {"null_session": True, "signing": False})
    monkeypatch.setattr(dh, "check_gpp_password", lambda *a, **k: {"success": True})
    monkeypatch.setattr(dh, "check_ms17_010", lambda *a, **k: {"vulnerable": True})
    monkeypatch.setattr(dh, "check_zerologon", lambda *a, **k: {"vulnerable": True})
    r = dh.domain_audit_summary("corp.local", "10.0.0.10", "bob", "pw")
    recs = r["recommendations"]
    assert any("LDAP anonymous bind" in x for x in recs)
    assert any("SMB null session" in x for x in recs)
    assert any("SMB signing not required" in x for x in recs)
    assert any("GPP passwords" in x for x in recs)
    assert any("MS17-010" in x for x in recs)
    assert any("ZeroLogon" in x for x in recs)
    assert r["ms17_010"]["vulnerable"] is True


def test_domain_audit_summary_kerberos_findings(audit, monkeypatch):
    monkeypatch.setattr(
        dh,
        "asrep_roast",
        lambda *a, **k: {"success": True, "asrep_users": [{"username": "a"}, {"username": "b"}]},
    )
    monkeypatch.setattr(
        dh, "kerberoast", lambda *a, **k: {"success": True, "tgs_hashes": [1, 2, 3]}
    )
    monkeypatch.setattr(dh, "adcs_scan", lambda *a, **k: {"success": True})
    r = dh.domain_audit_summary("corp.local", "10.0.0.10", "bob", "pw", usernames=["a", "b", "c"])
    recs = r["recommendations"]
    assert "HIGH: 2 AS-REP roastable users found" in recs
    assert "MEDIUM: 3 kerberoastable SPNs found" in recs
    assert any("AD CS" in x for x in recs)
    assert "bloodhound" in r


def test_domain_audit_summary_without_dc_ip(audit):
    r = dh.domain_audit_summary("corp.local", "")
    assert r["success"] is True
    assert list(audit) == ["enum_dc"]
    assert r["recommendations"] == []


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_resolves_domain_and_dc_ip(monkeypatch):
    captured = {}

    def fake_summary(**kwargs):
        captured.update(kwargs)
        return {"success": True}

    monkeypatch.setattr(dh, "domain_audit_summary", fake_summary)
    monkeypatch.setattr(dh.socket, "gethostbyname", lambda host: "10.0.0.99")
    r = dh.run("corp.local")
    assert r == {"success": True}
    assert captured["domain"] == "corp.local"
    assert captured["dc_ip"] == "10.0.0.99"


def test_run_dns_resolution_failure(monkeypatch):
    captured = {}
    monkeypatch.setattr(dh, "domain_audit_summary", lambda **k: captured.update(k) or {})

    def boom(host):
        raise OSError("dns")

    monkeypatch.setattr(dh.socket, "gethostbyname", boom)
    dh.run("corp.local")
    assert captured["dc_ip"] == ""


def test_run_explicit_parameters(monkeypatch):
    captured = {}
    monkeypatch.setattr(dh, "domain_audit_summary", lambda **k: captured.update(k) or {})
    monkeypatch.setattr(dh.socket, "gethostbyname", lambda host: "should-not-be-used")
    dh.run(
        "10.0.0.10",
        dc_ip="10.0.0.10",
        domain="corp.local",
        username="bob",
        password="pw",
        userlist=["a"],
    )
    assert captured == {
        "domain": "corp.local",
        "dc_ip": "10.0.0.10",
        "username": "bob",
        "password": "pw",
        "usernames": ["a"],
    }
