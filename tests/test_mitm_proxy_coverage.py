"""Coverage tests for tools/mitm_proxy.py.

openssl / sockets / HTTP servers are fully mocked. The real CONNECT proxy loop
is exercised with fake in-memory sockets and patched select/ssl only.
"""

import io
import os
import subprocess
import threading
from unittest import mock

import pytest

from tools import mitm_proxy as mp


@pytest.fixture(autouse=True)
def clean_captured(monkeypatch):
    monkeypatch.setattr(mp, "CAPTURED", [])
    yield


# ---------------------------------------------------------------------------
# CA generation
# ---------------------------------------------------------------------------

def test_ensure_ca_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CA_DIR", str(tmp_path / "ca"))
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path / "ca" / "certs"))
    mp._ensure_ca_dir()
    assert os.path.isdir(mp.CA_DIR)
    assert os.path.isdir(mp.CERTS_DIR)


def test_openssl_available_true():
    with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as m:
        assert mp._openssl_available() is True
    assert m.call_args.args[0] == ["openssl", "version"]


def test_openssl_available_missing():
    with mock.patch("subprocess.run", side_effect=FileNotFoundError):
        assert mp._openssl_available() is False


def test_generate_ca_existing_files(tmp_path, monkeypatch):
    key = tmp_path / "ca.key"
    cert = tmp_path / "ca.pem"
    key.write_text("k")
    cert.write_text("c")
    monkeypatch.setattr(mp, "CA_DIR", str(tmp_path))
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path / "certs"))
    monkeypatch.setattr(mp, "CA_KEY", str(key))
    monkeypatch.setattr(mp, "CA_CERT", str(cert))
    with mock.patch("subprocess.run") as run:
        assert mp.generate_ca() is True
    run.assert_not_called()


def test_generate_ca_without_openssl(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CA_DIR", str(tmp_path))
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path / "certs"))
    monkeypatch.setattr(mp, "CA_KEY", str(tmp_path / "ca.key"))
    monkeypatch.setattr(mp, "CA_CERT", str(tmp_path / "ca.pem"))
    monkeypatch.setattr(mp, "_openssl_available", lambda: False)
    assert mp.generate_ca() is False


def test_generate_ca_success(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CA_DIR", str(tmp_path))
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path / "certs"))
    monkeypatch.setattr(mp, "CA_KEY", str(tmp_path / "ca.key"))
    monkeypatch.setattr(mp, "CA_CERT", str(tmp_path / "ca.pem"))
    monkeypatch.setattr(mp, "_openssl_available", lambda: True)
    with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
        assert mp.generate_ca() is True
    assert run.call_count == 2
    assert run.call_args_list[0].args[0][:2] == ["openssl", "genrsa"]


def test_generate_ca_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CA_DIR", str(tmp_path))
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path / "certs"))
    monkeypatch.setattr(mp, "CA_KEY", str(tmp_path / "ca.key"))
    monkeypatch.setattr(mp, "CA_CERT", str(tmp_path / "ca.pem"))
    monkeypatch.setattr(mp, "_openssl_available", lambda: True)
    err = subprocess.CalledProcessError(1, ["openssl"], stderr=b"boom")
    with mock.patch("subprocess.run", side_effect=err):
        assert mp.generate_ca() is False


def test_generate_host_cert_existing(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path))
    (tmp_path / "example.com.pem").write_text("c")
    (tmp_path / "example.com.key").write_text("k")
    with mock.patch("subprocess.run") as run:
        assert mp._generate_host_cert("example.com") == str(tmp_path / "example.com.pem")
    run.assert_not_called()


def test_generate_host_cert_wildcard_san(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(mp, "CA_CERT", str(tmp_path / "ca.pem"))
    monkeypatch.setattr(mp, "CA_KEY", str(tmp_path / "ca.key"))
    with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)), \
            mock.patch("builtins.open", mock.mock_open()) as mopen:
        result = mp._generate_host_cert("api.example.com")
    assert result == os.path.join(str(tmp_path), "api.example.com.pem")
    ext_writes = [c.args[0] for c in mopen().write.call_args_list]
    assert any("DNS:api.example.com,DNS:*.example.com" in w for w in ext_writes)


def test_generate_host_cert_single_label_no_wildcard(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path))
    monkeypatch.setattr(mp, "CA_CERT", str(tmp_path / "ca.pem"))
    monkeypatch.setattr(mp, "CA_KEY", str(tmp_path / "ca.key"))
    with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)), \
            mock.patch("builtins.open", mock.mock_open()) as mopen:
        mp._generate_host_cert("example.com")
    ext_writes = [c.args[0] for c in mopen().write.call_args_list]
    assert any("DNS:example.com\n" in w for w in ext_writes)
    assert not any("*." in w for w in ext_writes)


def test_generate_host_cert_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "CERTS_DIR", str(tmp_path))
    err = subprocess.CalledProcessError(1, ["openssl"], stderr=b"nope")
    with mock.patch("subprocess.run", side_effect=err):
        assert mp._generate_host_cert("example.com") is None


# ---------------------------------------------------------------------------
# handler helpers
# ---------------------------------------------------------------------------

def test_parse_headers():
    raw = (b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Test:  a b \r\n"
           b"BadLineWithoutColon\r\n\r\nbody")
    headers = mp._ProxyHandler._parse_headers(None, raw)
    assert headers == {"Host": "example.com", "X-Test": "a b"}


def test_extract_body():
    raw = b"POST / HTTP/1.1\r\nHost: h\r\n\r\nhello=1"
    assert mp._ProxyHandler._extract_body(None, raw) == "hello=1"
    assert mp._ProxyHandler._extract_body(None, b"no-separator") == ""


def test_capture_stores_and_truncates(monkeypatch):
    monkeypatch.setattr(mp, "CAPTURED", [])
    mp._ProxyHandler._capture(None, method="POST", uri="/x", host="h",
                              req_body="x" * 60000)
    entry = mp.CAPTURED[0]
    assert len(entry["req_body"]) == 50000
    assert entry["url"] == "http://h/x"
    assert entry["ts"]


def test_capture_uses_explicit_url():
    mp._ProxyHandler._capture(None, method="GET", uri="/y", host="h",
                              url="https://h/y")
    assert mp.CAPTURED[-1]["url"] == "https://h/y"


def test_capture_trims_when_max_reached(monkeypatch):
    monkeypatch.setattr(mp, "CAPTURED", [])
    monkeypatch.setattr(mp, "MAX_CAPTURED", 4)
    for i in range(5):
        mp._ProxyHandler._capture(None, method="GET", uri="/%d" % i, host="h")
    assert len(mp.CAPTURED) == 3
    assert mp.CAPTURED[0]["uri"] == "/2"


def test_log_message_does_not_raise():
    handler = object.__new__(mp._ProxyHandler)
    handler.log_message("code %s", 200)


# ---------------------------------------------------------------------------
# request verbs dispatch
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("verb", [
    "do_GET", "do_POST", "do_PUT", "do_DELETE", "do_PATCH", "do_HEAD", "do_OPTIONS",
])
def test_verb_dispatch(verb):
    fake = mock.Mock()
    getattr(mp._ProxyHandler, verb)(fake)
    fake._capture_http_request.assert_called_once_with()


# ---------------------------------------------------------------------------
# _capture_http_request
# ---------------------------------------------------------------------------

class FakeResp:
    status = 200

    def getheaders(self):
        return [("Content-Type", "text/plain")]

    def read(self):
        return b"pong"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeRequestHandler:
    _capture = mp._ProxyHandler._capture

    def __init__(self, headers=None, body=b"", path="/x", command="GET",
                 connection=None):
        self.headers = headers if headers is not None else {}
        self.rfile = io.BytesIO(body)
        self.path = path
        self.command = command
        self.connection = connection if connection is not None else object()
        self.wfile = io.BytesIO()
        self.responses = []
        self.errors = []

    def address_string(self):
        return "127.0.0.1"

    def send_response(self, code, message=None):
        self.responses.append(code)

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass

    def send_error(self, code, message=None):
        self.errors.append((code, message))


def test_capture_http_request_success():
    fake = FakeRequestHandler(headers={"Host": "example.com", "Content-Length": "5"},
                              body=b"a=1&b", path="/login", command="POST")
    with mock.patch("urllib.request.urlopen", return_value=FakeResp()) as urlopen:
        mp._ProxyHandler._capture_http_request(fake)
    assert fake.responses == [200]
    assert fake.wfile.getvalue() == b"pong"
    assert mp.CAPTURED[0]["method"] == "POST"
    assert mp.CAPTURED[0]["url"] == "http://example.com/login"
    assert mp.CAPTURED[0]["req_body"] == "a=1&b"
    req = urlopen.call_args.args[0]
    assert req.full_url == "http://example.com/login"


def test_capture_http_request_without_host_header():
    fake = FakeRequestHandler(path="/a")
    with mock.patch("urllib.request.urlopen", return_value=FakeResp()):
        mp._ProxyHandler._capture_http_request(fake)
    assert mp.CAPTURED[0]["host"] == "127.0.0.1"


def test_capture_http_request_upstream_error():
    fake = FakeRequestHandler(headers={"Host": "h"})
    with mock.patch("urllib.request.urlopen", side_effect=RuntimeError("boom")):
        mp._ProxyHandler._capture_http_request(fake)
    assert fake.errors and fake.errors[0][0] == 502


# ---------------------------------------------------------------------------
# _proxy_http / _tunnel / _connect_upstream
# ---------------------------------------------------------------------------

class FakeConn:
    def __init__(self, recv_chunks=()):
        self._chunks = list(recv_chunks)
        self.sent = []
        self.closed = False

    def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""

    def sendall(self, data):
        self.sent.append(data)

    def setblocking(self, flag):
        self.blocking = flag

    def close(self):
        self.closed = True


def test_proxy_http_forwards_and_captures():
    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn([
        b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\nhello=1",
    ])
    upstream = FakeConn([b"HTTP/1.1 200 OK\r\n\r\nhi", b""])
    mp._ProxyHandler._proxy_http(handler, upstream, "example.com", "tag1")
    assert upstream.sent[0].startswith(b"POST /submit")
    assert handler.connection.sent == [b"HTTP/1.1 200 OK\r\n\r\nhi"]
    assert upstream.closed is True
    entry = mp.CAPTURED[0]
    assert entry["method"] == "POST"
    assert entry["uri"] == "/submit"
    assert entry["req_body"] == "hello=1"
    assert entry["req_headers"]["Content-Type"] == "text/plain"


def test_proxy_http_swallows_connection_reset():
    handler = object.__new__(mp._ProxyHandler)

    class ResetConn(FakeConn):
        def recv(self, n):
            raise ConnectionResetError

    handler.connection = ResetConn()
    upstream = FakeConn()
    mp._ProxyHandler._proxy_http(handler, upstream, "h", "tag2")
    assert upstream.closed is True
    assert mp.CAPTURED == []


def test_tunnel_relays_and_closes(monkeypatch):
    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn([b"ping"])
    upstream = FakeConn()
    monkeypatch.setattr("select.select", lambda *a, **k: ([handler.connection], [], []))
    mp._ProxyHandler._tunnel(handler, upstream)
    assert upstream.sent == [b"ping"]
    assert upstream.closed is True


def test_tunnel_relays_upstream_to_client(monkeypatch):
    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn()
    upstream = FakeConn([b"pong"])
    monkeypatch.setattr("select.select", lambda *a, **k: ([upstream], [], []))
    mp._ProxyHandler._tunnel(handler, upstream)
    assert handler.connection.sent == [b"pong"]
    assert upstream.closed is True


def test_tunnel_timeout_breaks(monkeypatch):
    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn()
    upstream = FakeConn()
    monkeypatch.setattr("select.select", lambda *a, **k: ([], [], []))
    mp._ProxyHandler._tunnel(handler, upstream)
    assert upstream.closed is True


def test_tunnel_swallows_reset(monkeypatch):
    handler = object.__new__(mp._ProxyHandler)

    class ResetConn(FakeConn):
        def recv(self, n):
            raise BrokenPipeError

    handler.connection = ResetConn()
    upstream = FakeConn()
    monkeypatch.setattr("select.select", lambda *a, **k: ([handler.connection], [], []))
    mp._ProxyHandler._tunnel(handler, upstream)
    assert upstream.closed is True


def test_tunnel_returns_on_empty_data(monkeypatch):
    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn([b""])
    upstream = FakeConn()
    monkeypatch.setattr("select.select", lambda *a, **k: ([handler.connection], [], []))
    mp._ProxyHandler._tunnel(handler, upstream)
    assert upstream.closed is True


def test_tunnel_close_error_is_swallowed(monkeypatch):
    class BadClose(FakeConn):
        def close(self):
            raise OSError("close failed")

    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn()
    upstream = BadClose()
    monkeypatch.setattr("select.select", lambda *a, **k: ([], [], []))
    mp._ProxyHandler._tunnel(handler, upstream)


def test_proxy_http_breaks_on_empty_request():
    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn([b""])
    upstream = FakeConn([b""])
    mp._ProxyHandler._proxy_http(handler, upstream, "h", "tag")
    assert mp.CAPTURED == []
    assert upstream.closed is True


def test_proxy_http_stops_after_one_megabyte():
    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn([b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"])
    upstream = FakeConn([b"x" * 1048577, b"y"])
    mp._ProxyHandler._proxy_http(handler, upstream, "h", "tag")
    assert len(handler.connection.sent) == 1
    assert upstream.closed is True


def test_proxy_http_close_error_is_swallowed():
    class BadClose(FakeConn):
        def close(self):
            raise OSError("nope")

    handler = object.__new__(mp._ProxyHandler)
    handler.connection = FakeConn([b""])
    upstream = BadClose([b""])
    mp._ProxyHandler._proxy_http(handler, upstream, "h", "tag")


def test_connect_upstream_plain_port():
    sock = FakeConn()
    handler = object.__new__(mp._ProxyHandler)
    with mock.patch("socket.create_connection", return_value=sock) as create:
        assert mp._ProxyHandler._connect_upstream(handler, "h", 80) is sock
    create.assert_called_once_with(("h", 80), timeout=15)


def test_connect_upstream_tls_port():
    sock = FakeConn()
    wrapped = object()
    ctx = mock.Mock()
    ctx.wrap_socket.return_value = wrapped
    handler = object.__new__(mp._ProxyHandler)
    with mock.patch("socket.create_connection", return_value=sock), \
            mock.patch.object(mp.ssl, "SSLContext", return_value=ctx):
        result = mp._ProxyHandler._connect_upstream(handler, "h", 443)
    assert result is wrapped
    assert ctx.check_hostname is False
    ctx.wrap_socket.assert_called_once_with(sock, server_hostname="h")


# ---------------------------------------------------------------------------
# do_CONNECT
# ---------------------------------------------------------------------------

class ConnectHandler:
    def __init__(self, path="secure.example.com"):
        self.path = path
        self.connection = object()
        self.upstream = object()
        self.responses = []
        self.errors = []

    def _connect_upstream(self, host, port):
        self.connected = (host, port)
        return self.upstream

    def send_response(self, code, message=None):
        self.responses.append(code)

    def end_headers(self):
        pass

    def send_error(self, code, message=None):
        self.errors.append((code, message))


def test_do_connect_upstream_failure():
    handler = ConnectHandler()
    handler._connect_upstream = mock.Mock(side_effect=OSError("no route"))
    mp._ProxyHandler.do_CONNECT(handler)
    assert handler.errors[0][0] == 502


def test_do_connect_mitm_success(tmp_path, monkeypatch):
    handler = ConnectHandler()
    cert = tmp_path / "host.pem"
    cert.write_text("cert")
    tls = mock.Mock()
    tls.makefile.return_value = mock.Mock()
    ctx = mock.Mock()
    ctx.wrap_socket.return_value = tls
    handler._proxy_http = mock.Mock()
    handler._tunnel = mock.Mock()
    monkeypatch.setattr(mp, "_generate_host_cert", lambda host: str(cert))
    with mock.patch.object(mp.ssl, "SSLContext", return_value=ctx):
        mp._ProxyHandler.do_CONNECT(handler)
    assert handler.connected == ("secure.example.com", 443)
    assert handler.responses == [200]
    assert handler.connection is tls
    args = handler._proxy_http.call_args.args
    assert args[0] is handler.upstream
    assert args[1] == "secure.example.com"
    assert isinstance(args[2], str)
    handler._tunnel.assert_not_called()


def test_do_connect_explicit_port_and_tls_failure_falls_back_to_tunnel(tmp_path, monkeypatch):
    handler = ConnectHandler(path="host.local:8443")
    cert = tmp_path / "host.pem"
    cert.write_text("cert")
    ctx = mock.Mock()
    ctx.wrap_socket.side_effect = OSError("tls broken")
    handler._tunnel = mock.Mock()
    monkeypatch.setattr(mp, "_generate_host_cert", lambda host: str(cert))
    with mock.patch.object(mp.ssl, "SSLContext", return_value=ctx):
        mp._ProxyHandler.do_CONNECT(handler)
    assert handler.connected == ("host.local", 8443)
    handler._tunnel.assert_called_once_with(handler.upstream)


def test_do_connect_no_cert_falls_back_to_tunnel(monkeypatch):
    handler = ConnectHandler()
    handler._tunnel = mock.Mock()
    monkeypatch.setattr(mp, "_generate_host_cert", lambda host: None)
    mp._ProxyHandler.do_CONNECT(handler)
    handler._tunnel.assert_called_once_with(handler.upstream)


# ---------------------------------------------------------------------------
# MITMProxy public API
# ---------------------------------------------------------------------------

def test_ca_info_and_instruction():
    proxy = mp.MITMProxy()
    info = proxy.ca_info()
    assert set(info) == {"available", "ca_cert", "ca_key", "certs_dir"}
    assert info["ca_cert"] == mp.CA_CERT
    assert "MITM CA cert" in proxy.install_ca_instruction()


def test_get_captured_clear(monkeypatch):
    monkeypatch.setattr(mp, "CAPTURED", [{"url": "u"}])
    proxy = mp.MITMProxy()
    assert proxy.get_captured() == [{"url": "u"}]
    assert proxy.get_captured(clear=True) == [{"url": "u"}]
    assert mp.CAPTURED == []


def test_extract_credentials_patterns():
    proxy = mp.MITMProxy()
    captured = [
        {"url": "http://x/login", "req_body": "user=bob&password=s3cret&api_key=AK1",
         "req_headers": {}},
        {"url": "http://x/api", "req_body": "",
         "req_headers": {"Authorization": "Basic dXNlcjpwYXNz"}},
        {"url": "http://x/jwt", "req_body": "",
         "req_headers": {"Authorization": "Bearer aaa.bbb.ccc"}},
        {"url": "http://x/sess", "req_body": "session_id=abc123&token=tok1",
         "req_headers": {}},
    ]
    findings = proxy.extract_credentials(captured)
    by_type = {f["type"]: f for f in findings}
    assert by_type["password"]["value"] == "s3cret"
    assert by_type["api_key"]["value"] == "AK1"
    assert by_type["basic_auth"]["value"] == "dXNlcjpwYXNz"
    assert by_type["jwt"]["value"] == "aaa.bbb.ccc"
    assert by_type["session"]["value"] == "abc123"
    assert by_type["token"]["value"] == "tok1"
    assert all(f["url"].startswith("http://x/") for f in findings)
    assert all(len(f["match"]) <= 80 for f in findings)


def test_extract_credentials_empty():
    assert mp.MITMProxy().extract_credentials([]) == []


def test_extract_credentials_defaults_to_global_capture(monkeypatch):
    monkeypatch.setattr(mp, "CAPTURED", [
        {"url": "http://x/", "req_body": "password=pw", "req_headers": {}},
    ])
    findings = mp.MITMProxy().extract_credentials()
    assert findings[0]["value"] == "pw"


def test_extract_sessions():
    proxy = mp.MITMProxy()
    captured = [
        {"url": "http://x/a", "req_body": "session_id=s1&token=t2&jwt=j3"},
        {"url": "http://x/b", "req_body": "nothing"},
    ]
    sessions = proxy.extract_sessions(captured)
    assert [(s["param"], s["value"]) for s in sessions] == [
        ("session_id", "s1"), ("token", "t2"), ("jwt", "j3"),
    ]


def test_extract_sessions_defaults_to_global_capture(monkeypatch):
    monkeypatch.setattr(mp, "CAPTURED", [
        {"url": "http://x/a", "req_body": "session_id=s9"},
    ])
    sessions = mp.MITMProxy().extract_sessions()
    assert sessions == [{"param": "session_id", "value": "s9", "url": "http://x/a"}]


def test_capture_with_duration(monkeypatch):
    proxy = mp.MITMProxy()
    proxy.start = mock.Mock()
    proxy.stop = mock.Mock()
    monkeypatch.setattr(mp, "CAPTURED", [
        {"url": "http://x/", "req_body": "password=pw", "req_headers": {}},
    ])
    monkeypatch.setattr(mp.time, "sleep", lambda s: None)
    r = proxy.capture_with_duration(duration=5)
    assert r["total_requests"] == 1
    assert r["credentials"][0]["type"] == "password"
    proxy.start.assert_called_once_with()
    proxy.stop.assert_called_once_with()


class FakeHTTPServer:
    instances = []

    def __init__(self, addr, handler_cls):
        self.addr = addr
        self.handler_cls = handler_cls
        self._stopped = threading.Event()
        FakeHTTPServer.instances.append(self)

    def serve_forever(self):
        self._stopped.wait(5)

    def shutdown(self):
        self._stopped.set()


def test_proxy_start_stop_lifecycle(monkeypatch):
    FakeHTTPServer.instances = []
    monkeypatch.setattr(mp, "HTTPServer", FakeHTTPServer)
    monkeypatch.setattr(mp, "generate_ca", lambda: True)
    proxy = mp.MITMProxy(port=0, host="127.0.0.1")
    proxy.start()
    assert proxy.running() is True
    assert FakeHTTPServer.instances[0].addr == ("127.0.0.1", 0)
    assert issubclass(FakeHTTPServer.instances[0].handler_cls, mp._ProxyHandler)
    proxy.start()  # already running: warning branch, no second server
    assert len(FakeHTTPServer.instances) == 1
    proxy.stop()
    assert proxy.running() is False
    assert proxy._server is None


def test_proxy_stop_without_start():
    proxy = mp.MITMProxy()
    proxy.stop()  # no-op
    assert proxy.running() is False


def test_start_and_stop_proxy_globals(monkeypatch):
    monkeypatch.setattr(mp, "_GLOBAL_PROXY", None)
    fake_cls = mock.Mock()
    monkeypatch.setattr(mp, "MITMProxy", fake_cls)
    proxy = mp.start_proxy(port=9999)
    assert mp.get_proxy() is proxy
    fake_cls.assert_called_once_with(port=9999, host="127.0.0.1", threads=10)
    proxy.start.assert_called_once_with()
    mp.stop_proxy()
    assert mp.get_proxy() is None
    proxy.stop.assert_called_once_with()


def test_stop_proxy_without_instance(monkeypatch):
    monkeypatch.setattr(mp, "_GLOBAL_PROXY", None)
    mp.stop_proxy()
    assert mp.get_proxy() is None


def test_credential_patterns_constant():
    labels = {label for _, label in mp.CREDENTIAL_PATTERNS}
    assert {"password", "api_key", "basic_auth", "jwt", "token", "session"} <= labels
