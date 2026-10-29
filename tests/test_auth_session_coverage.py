import base64
import json
import threading
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from requests.auth import HTTPBasicAuth

from tools import cross_validator, csrf_scanner, deviation_oracle, race_profiler, session_matrix
from tools.deviation_oracle import DeviationOracle, OracleSession
from tools.race_profiler import RaceProfiler, StateIntegrityChecker, TransactionProbe
from tools.session_matrix import SessionComparator, SessionMatrix, make_matrix
from tools.workflow_tracer import StepRole, TraceStep, WorkflowTrace, WorkflowTracer


class FakeCookie:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class FakeCookieJar:
    def __init__(self):
        self._cookies = {}

    def set(self, name, value, **kwargs):
        self._cookies[name] = value

    def get(self, name, default=None):
        return self._cookies.get(name, default)

    def __iter__(self):
        return iter([FakeCookie(n, v) for n, v in self._cookies.items()])


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = text.encode("utf-8")


class FakeSession:
    """Deterministic requests.Session stand-in; no network access possible."""

    def __init__(self, handler=None):
        self._handler = handler
        self.calls = []
        self.cookies = FakeCookieJar()
        self.headers = {}
        self.verify = True
        self.closed = False
        self._lock = threading.Lock()

    def _record(self, method, url, kwargs):
        with self._lock:
            self.calls.append((method, url, dict(kwargs)))
        if self._handler is None:
            return FakeResponse()
        return self._handler(self, method, url, kwargs)

    def get(self, url, **kwargs):
        return self._record("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._record("POST", url, kwargs)

    def put(self, url, **kwargs):
        return self._record("PUT", url, kwargs)

    def patch(self, url, **kwargs):
        return self._record("PATCH", url, kwargs)

    def delete(self, url, **kwargs):
        return self._record("DELETE", url, kwargs)

    def request(self, method, url, **kwargs):
        return self._record(method.upper(), url, kwargs)

    def close(self):
        self.closed = True


class FrozenClock:
    def __init__(self, values=None):
        self._values = iter(values or [])
        self._last = 0.0

    def time(self):
        try:
            self._last = next(self._values)
        except StopIteration:
            return self._last
        return self._last


def _install_session_factory(monkeypatch, handler):
    created = []

    def factory():
        sess = FakeSession(handler)
        created.append(sess)
        return sess

    monkeypatch.setattr(requests, "Session", factory)
    return created


def _static_handler(status=200, text="ok", headers=None):
    def handler(sess, method, url, kwargs):
        return FakeResponse(status, text, headers)

    return handler


def _raiser(sess, method, url, kwargs):
    raise RuntimeError("network down")


def _trace_step(index, method="GET", url="http://t.test/x", status=200, role=StepRole.READ):
    return TraceStep(
        index=index,
        method=method,
        url=url,
        params={},
        body=None,
        response_status=status,
        response_body="ok",
        response_headers={},
        role=role,
    )


def _patch(sess, status=200, text="ok", index=0):
    return {"index": index, "status": status, "body": text, "length": len(text), "elapsed_ms": 1.0}


class TestSessionMatrixBasics:
    def test_register_get_and_list(self):
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw", role="admin")
        assert identity.role == "admin"
        assert matrix.get("alice") is identity
        assert matrix.list() == {"alice": "admin:alice"}

    def test_get_unknown_returns_none(self):
        matrix = SessionMatrix()
        assert matrix.get("ghost") is None
        assert matrix.list() == {}

    def test_make_matrix_trims_trailing_slash(self):
        matrix = make_matrix("http://t.test/")
        assert matrix.base_url == "http://t.test"

    def test_make_session_unknown_identity(self):
        matrix = SessionMatrix()
        assert matrix.make_session("ghost") is None

    def test_make_session_applies_cookies_headers_and_verify(self, monkeypatch):
        _install_session_factory(monkeypatch, _static_handler())
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        identity.cookies = {"sid": "s1"}
        identity.headers = {"X-Token": "t1"}
        sess = matrix.make_session("alice")
        assert isinstance(sess, FakeSession)
        assert sess.cookies.get("sid") == "s1"
        assert sess.headers["X-Token"] == "t1"
        from tools.settings import settings

        assert sess.verify == settings.verify_ssl


class TestSessionMatrixAuthenticate:
    def test_authenticate_all_form_success_captures_cookies(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))

        def handler(sess, method, url, kwargs):
            sess.cookies.set("sid", "abc")
            return FakeResponse(200, "welcome")

        created = _install_session_factory(monkeypatch, handler)
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        results = matrix.authenticate_all("http://t.test/login")
        assert results == {"alice": True}
        assert identity.authenticated is True
        assert identity.cookies == {"sid": "abc"}
        assert created[0].closed is True
        assert created[0].calls == [
            (
                "POST",
                "http://t.test/login",
                {"data": {"username": "alice", "password": "pw"}, "timeout": 10.0},
            ),
        ]

    def test_authenticate_all_skips_already_authenticated(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        created = _install_session_factory(monkeypatch, _raiser)
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        identity.authenticated = True
        results = matrix.authenticate_all("http://t.test/login")
        assert results == {"alice": True}
        assert created == []

    def test_authenticate_all_json_mode(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        created = _install_session_factory(monkeypatch, _static_handler())
        matrix = SessionMatrix("http://t.test")
        matrix.register("alice", "alice", "pw")
        results = matrix.authenticate_all("http://t.test/api/login", auth_mode="json")
        assert results == {"alice": True}
        assert created[0].calls[0][2]["json"] == {"username": "alice", "password": "pw"}

    def test_authenticate_all_basic_mode(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        created = _install_session_factory(monkeypatch, _static_handler())
        matrix = SessionMatrix("http://t.test")
        matrix.register("alice", "alice", "pw")
        results = matrix.authenticate_all("http://t.test/protected", auth_mode="basic")
        assert results == {"alice": True}
        method, url, kwargs = created[0].calls[0]
        assert method == "GET"
        assert isinstance(kwargs["auth"], HTTPBasicAuth)

    def test_authenticate_all_basic_success_persists_authorization_header(
        self, monkeypatch, tmp_path
    ):
        """Basic auth success stores no cookies, so authenticate_all() persists
        the encoded credentials explicitly and make_session() replays them for
        the supposedly authenticated identity."""
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, _static_handler())
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        matrix.authenticate_all("http://t.test/protected", auth_mode="basic")
        expected = "Basic " + base64.b64encode(b"alice:pw").decode()
        assert identity.authenticated is True
        assert identity.headers == {"Authorization": expected}
        assert identity.cookies == {}
        sess = matrix.make_session("alice")
        assert sess.headers["Authorization"] == expected
        assert sess.cookies.get("sid") is None

    def test_authenticate_all_401_marks_failure(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, _static_handler(401, "denied"))
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "bad")
        assert matrix.authenticate_all("http://t.test/login") == {"alice": False}
        assert identity.authenticated is False

    def test_authenticate_all_302_redirect_marks_failure(self, monkeypatch, tmp_path):
        """Rejected credentials answered with a 302 redirect to the login page
        are recorded as failed: only status_code == 200 counts as success
        (session_matrix.py:64)."""
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        headers = {"Location": "http://t.test/login?error=1"}
        _install_session_factory(monkeypatch, _static_handler(302, "", headers))
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "bad")
        assert matrix.authenticate_all("http://t.test/login") == {"alice": False}
        assert identity.authenticated is False
        assert identity.cookies == {}

    def test_authenticate_all_500_marks_failure(self, monkeypatch, tmp_path):
        """A 500 response is a failure, not a successful login: only
        status_code == 200 counts as success (session_matrix.py:64)."""
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, _static_handler(500, "boom"))
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        assert matrix.authenticate_all("http://t.test/login") == {"alice": False}
        assert identity.authenticated is False

    def test_authenticate_all_exception_marks_failure(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, _raiser)
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        assert matrix.authenticate_all("http://t.test/login") == {"alice": False}
        assert identity.authenticated is False

    def test_authenticate_all_does_not_scrape_session_headers(self, monkeypatch, tmp_path):
        """Login-time session headers are not copied into the identity; only
        basic mode persists an explicit Authorization header, so headers set by
        the target application cannot leak into other sessions."""
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))

        def handler(sess, method, url, kwargs):
            sess.headers["Authorization"] = "Bearer tok"
            return FakeResponse(200, "welcome")

        _install_session_factory(monkeypatch, handler)
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        matrix.authenticate_all("http://t.test/login", auth_mode="json")
        assert identity.authenticated is True
        assert identity.headers == {}

    def test_authenticate_all_ignores_auth_attribute(self, monkeypatch, tmp_path):
        """A session-level `_auth` attribute is not treated as credentials;
        only the explicit basic-mode Authorization header is persisted."""
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        created = []

        def factory():
            sess = FakeSession(_static_handler())
            sess._auth = "Basic dXNlcjpwYXNz"
            created.append(sess)
            return sess

        monkeypatch.setattr(requests, "Session", factory)
        matrix = SessionMatrix("http://t.test")
        identity = matrix.register("alice", "alice", "pw")
        matrix.authenticate_all("http://t.test/login")
        assert identity.authenticated is True
        assert identity.headers == {}
        assert created


class TestSessionMatrixPersistence:
    def test_save_persists_only_authenticated_identities(self, monkeypatch, tmp_path):
        target = tmp_path / "sessions.json"
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(target))
        matrix = SessionMatrix("http://t.test")
        alice = matrix.register("alice", "alice", "pw1", role="admin")
        matrix.register("bob", "bob", "pw2")
        alice.authenticated = True
        alice.cookies = {"sid": "1"}
        matrix._save()
        data = json.loads(target.read_text(encoding="utf-8"))
        assert list(data.keys()) == ["alice"]
        assert data["alice"]["password"] == "pw1"
        assert data["alice"]["cookies"] == {"sid": "1"}

    def test_save_error_swallowed(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))

        def raiser(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(session_matrix.os, "makedirs", raiser)
        matrix = SessionMatrix("http://t.test")
        matrix.register("alice", "alice", "pw").authenticated = True
        matrix._save()

    def test_load_restores_records_and_skips_existing(self, monkeypatch, tmp_path):
        target = tmp_path / "sessions.json"
        payload = {
            "alice": {
                "label": "alice",
                "username": "alice",
                "password": "p",
                "role": "admin",
                "cookies": {"sid": "1"},
                "headers": {},
                "tokens": {"t": "1"},
                "authenticated": True,
                "metadata": {"m": 1},
            }
        }
        target.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(target))
        matrix = SessionMatrix()
        bob = matrix.register("bob", "bob", "pw")
        matrix._load()
        alice = matrix.get("alice")
        assert alice.role == "admin"
        assert alice.cookies == {"sid": "1"}
        assert alice.tokens == {"t": "1"}
        assert alice.metadata == {"m": 1}
        assert matrix.get("bob") is bob
        target.write_text(json.dumps({"carol": {"label": "carol"}}), encoding="utf-8")
        matrix._load()
        assert matrix.get("alice") is alice
        assert matrix.get("carol") is None

    def test_load_fills_defaults_for_partial_record(self, monkeypatch, tmp_path):
        target = tmp_path / "sessions.json"
        target.write_text(json.dumps({"charlie": {}}), encoding="utf-8")
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(target))
        matrix = SessionMatrix()
        matrix._load()
        charlie = matrix.get("charlie")
        assert charlie.username == ""
        assert charlie.role == "user"
        assert charlie.authenticated is False

    def test_load_missing_file_is_noop(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "absent.json"))
        matrix = SessionMatrix()
        matrix._load()
        assert matrix.list() == {}
        assert matrix._loaded is True

    def test_load_malformed_json_swallowed(self, monkeypatch, tmp_path):
        target = tmp_path / "sessions.json"
        target.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(target))
        matrix = SessionMatrix()
        matrix._load()
        assert matrix.list() == {}


class TestSessionMatrixCrossSession:
    def _matrix_with_two(self, monkeypatch, tmp_path, handler):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, handler)
        matrix = SessionMatrix("http://t.test")
        for label in ("alice", "bob"):
            identity = matrix.register(label, label, "pw")
            identity.cookies = {"who": label}
            identity.authenticated = True
        return matrix

    def test_cross_session_test_reports_actor_and_target(self, monkeypatch, tmp_path):
        def handler(sess, method, url, kwargs):
            who = sess.cookies.get("who")
            return FakeResponse(200, ("body-%s-" % who) * 12)

        matrix = self._matrix_with_two(monkeypatch, tmp_path, handler)
        result = matrix.cross_session_test("alice", "bob", "http://t.test/profile")
        assert result["actor"] == {"label": "alice", "status": 200, "length": 132}
        assert result["target"]["label"] == "bob"
        assert result["target"]["status"] == 200
        assert result["body_match"] is False
        assert result["authz_gap"] is False
        assert set(result) == {"actor", "target", "body_match", "authz_gap"}

    def test_cross_session_test_missing_session(self):
        matrix = SessionMatrix("http://t.test")
        assert matrix.cross_session_test("ghost", "other", "http://t.test/x") == {
            "error": "session not found"
        }

    def test_cross_session_test_error_is_swallowed_by_callers_defect(self, monkeypatch, tmp_path):
        """Transport errors produce {"error": ...} with no authz_gap key, so the
        oracle's `result.get("authz_gap")` checks silently lose the signal."""
        matrix = self._matrix_with_two(monkeypatch, tmp_path, _raiser)
        result = matrix.cross_session_test("alice", "bob", "http://t.test/profile")
        assert result == {"error": "network down"}
        assert "authz_gap" not in result

    def test_cross_session_test_identical_bodies_are_not_authz_gap(self, monkeypatch, tmp_path):
        """Identical responses for two identities (a public page reachable by
        both) are not a cross-user authz gap: the gap requires the actor to
        succeed while the target is denied (session_matrix.py:132)."""
        body = "shared public dashboard content " * 4
        matrix = self._matrix_with_two(monkeypatch, tmp_path, _static_handler(200, body))
        result = matrix.cross_session_test("alice", "bob", "http://t.test/dashboard")
        assert result["body_match"] is True
        assert result["authz_gap"] is False

    def test_cross_session_test_short_body_never_flags_defect(self, monkeypatch, tmp_path):
        """The len(text) > 50 gate drops real access whose body is short, e.g.
        JSON APIs answering {"ok": true} (session_matrix.py:128)."""
        matrix = self._matrix_with_two(monkeypatch, tmp_path, _static_handler(200, '{"ok": true}'))
        result = matrix.cross_session_test("alice", "bob", "http://t.test/api/me")
        assert result["actor"]["status"] == 200
        assert result["authz_gap"] is False

    def test_cross_session_test_post_passes_kwargs(self, monkeypatch, tmp_path):
        matrix = self._matrix_with_two(monkeypatch, tmp_path, _static_handler(201, "created " * 10))
        result = matrix.cross_session_test(
            "alice", "bob", "http://t.test/orders", method="POST", data={"item": "1"}
        )
        assert result["actor"]["status"] == 201
        assert result["body_match"] is True
        assert result["authz_gap"] is False


class TestSessionComparator:
    def _matrix(self, monkeypatch, tmp_path, handler):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, handler)
        matrix = SessionMatrix("http://t.test")
        for label in ("alice", "bob"):
            identity = matrix.register(label, label, "pw")
            identity.cookies = {"who": label}
            identity.authenticated = True
        return matrix

    def test_compare_identical(self, monkeypatch, tmp_path):
        matrix = self._matrix(monkeypatch, tmp_path, _static_handler(200, "same page"))
        result = SessionComparator(matrix).compare("http://t.test/x", "alice", "bob")
        assert result["identical"] is True
        assert result["diff"] == {"identical": True}

    def test_compare_missing_sessions(self, monkeypatch, tmp_path):
        matrix = SessionMatrix("http://t.test")
        result = SessionComparator(matrix).compare("http://t.test/x", "a", "b")
        assert result == {"error": "session not found"}

    def test_compare_request_exception_returns_error(self, monkeypatch, tmp_path):
        matrix = self._matrix(monkeypatch, tmp_path, _raiser)
        result = SessionComparator(matrix).compare("http://t.test/x", "alice", "bob")
        assert result == {"error": "network down"}

    def test_compare_post_method(self, monkeypatch, tmp_path):
        sess_handler = _static_handler(200, "same page")
        matrix = self._matrix(monkeypatch, tmp_path, sess_handler)
        result = SessionComparator(matrix).compare(
            "http://t.test/x", "alice", "bob", method="POST", data={"a": "1"}
        )
        assert result["a"]["status"] == 200
        assert result["identical"] is True

    def test_status_diff_with_equal_body_is_inconsistent_defect(self, monkeypatch, tmp_path):
        """compare() reports identical=False (status differs) while _compute_diff
        reports {"identical": True} (text equal) (session_matrix.py:203/208)."""

        def handler(sess, method, url, kwargs):
            if sess.cookies.get("who") == "alice":
                return FakeResponse(200, "same body")
            return FakeResponse(500, "same body")

        matrix = self._matrix(monkeypatch, tmp_path, handler)
        result = SessionComparator(matrix).compare("http://t.test/x", "alice", "bob")
        assert result["identical"] is False
        assert result["diff"] == {"identical": True}

    def _comparator(self):
        return SessionComparator(SessionMatrix("http://t.test"))

    def test_compute_diff_nested_json_entry_keeps_wrapper_shape_defect(self):
        """_json_diff() always returns a dict, so the isinstance(sub_diff, list)
        branch is dead and nested diffs are embedded as {"diffs": ...} wrappers
        instead of flat {path, reason} entries (session_matrix.py:238-242)."""
        a = FakeResponse(200, '{"user": {"id": 1, "name": "a"}, "ok": true}')
        b = FakeResponse(200, '{"user": {"id": 2, "name": "a"}, "ok": true}')
        diff = self._comparator()._compute_diff(a, b)
        assert diff["total"] == 1
        entry = diff["diffs"][0]
        assert "reason" not in entry
        assert entry["diffs"][0]["diffs"][0]["path"] == "user.id"
        assert entry["diffs"][0]["diffs"][0]["reason"] == "value_diff"

    def test_compute_diff_type_mismatch_nested(self):
        a = FakeResponse(200, '{"x": 1}')
        b = FakeResponse(200, '{"x": "1"}')
        diff = self._comparator()._compute_diff(a, b)
        inner = diff["diffs"][0]["diffs"][0]
        assert inner["reason"] == "type_mismatch"
        assert (inner["a_type"], inner["b_type"]) == ("int", "str")

    def test_compute_diff_key_missing(self):
        a = FakeResponse(200, '{"x": 1}')
        b = FakeResponse(200, '{"y": 2}')
        diff = self._comparator()._compute_diff(a, b)
        reasons = {d["reason"] for d in diff["diffs"]}
        assert reasons == {"key_missing_in_a", "key_missing_in_b"}
        assert diff["total"] == 2

    def test_compute_diff_list_value_and_length(self):
        a = FakeResponse(200, '{"items": [1, 2, 3]}')
        b = FakeResponse(200, '{"items": [1, 9]}')
        diff = self._comparator()._compute_diff(a, b)
        inner = diff["diffs"][0]
        assert {d["path"] for d in inner["diffs"]} == {"items[1]", "items"}
        assert inner["total"] == 2

    def test_compute_diff_falsy_json_falls_back_defect(self):
        """`if a_json and b_json` treats valid falsy JSON documents (0, "", [])
        as parse failures, so differences fall back to status/length only."""
        a = FakeResponse(200, "0")
        b = FakeResponse(200, "1")
        diff = self._comparator()._compute_diff(a, b)
        assert "diffs" not in diff
        assert diff == {"status_diff": False, "length_diff": 0}

    def test_compute_diff_non_json_fallback(self):
        a = FakeResponse(200, "abc")
        b = FakeResponse(500, "abcdef")
        diff = self._comparator()._compute_diff(a, b)
        assert diff["status_diff"] is True
        assert diff["length_diff"] == -3


class TestDeviationOracleDiscovery:
    def test_discover_protected_paths_keeps_401_403_302(self):
        def handler(sess, method, url, kwargs):
            path = url.replace("http://t.test", "")
            if path == "/admin":
                return FakeResponse(401, "auth required")
            if path == "/api/admin":
                return FakeResponse(403, "forbidden")
            if path == "/profile":
                return FakeResponse(302, "redirect")
            return FakeResponse(200, "ok")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        assert oracle._discover_protected_paths() == ["/admin", "/profile", "/api/admin"]

    def test_discover_protected_paths_swallows_errors(self):
        oracle = DeviationOracle("http://t.test", FakeSession(_raiser))
        assert oracle._discover_protected_paths() == []

    def test_run_without_session_is_silent_noop_defect(self):
        """Without a session every sub-check silently degrades to 'nothing
        found'; the oracle reports vulnerable=False instead of an error."""
        oracle = DeviationOracle("http://t.test")
        result = oracle.run()
        assert result == {"vulnerable": False, "findings": [], "total": 0}


class TestDeviationOracleFindings:
    def _oracle(self):
        def handler(sess, method, url, kwargs):
            path = url.split("?")[0].replace("http://t.test", "")
            if path == "/admin":
                if method == "GET":
                    return FakeResponse(403, "forbidden")
                return FakeResponse(200, "admin panel")
            return FakeResponse(404, "nope")

        return DeviationOracle("http://t.test", FakeSession(handler))

    def test_method_tampering_flags_every_successful_write_method(self):
        oracle = self._oracle()
        oracle._test_method_tampering()
        assert len(oracle.findings) == 4
        assert {f["method"] for f in oracle.findings} == {"PUT", "PATCH", "DELETE", "POST"}
        assert all(f["severity"] == "medium" for f in oracle.findings)
        assert all(f["type"] == "method_tampering" for f in oracle.findings)

    def test_method_tampering_200_with_405_text_is_suppressed_defect(self):
        """A genuine 200 response is discarded because its body happens to
        contain '405' / 'not allowed' (deviation_oracle.py:171-172)."""

        def handler(sess, method, url, kwargs):
            if url.split("?")[0].endswith("/admin"):
                if method == "GET":
                    return FakeResponse(403, "forbidden")
                return FakeResponse(200, "405 method not allowed")
            return FakeResponse(404, "nope")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        oracle._test_method_tampering()
        assert oracle.findings == []

    def test_mass_assignment_flags_on_response_keyword(self):
        oracle = self._oracle()
        oracle._test_mass_assignment()
        assert len(oracle.findings) == 21
        assert all(f["type"] == "mass_assignment" for f in oracle.findings)
        assert {f["method"] for f in oracle.findings} == {"POST", "PUT", "PATCH"}

    def test_mass_assignment_keyword_in_body_is_unverified_defect(self):
        """Any successful response mentioning 'admin' is reported as a critical
        mass-assignment finding; the injected field is never verified
        (deviation_oracle.py:198-209)."""

        def handler(sess, method, url, kwargs):
            path = url.replace("http://t.test", "")
            if method == "GET":
                if path == "/admin":
                    return FakeResponse(403, "forbidden")
                return FakeResponse(404, "nope")
            return FakeResponse(200, "Welcome to the admin portal navigation menu")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        oracle._test_mass_assignment()
        assert len(oracle.findings) == 21
        assert all(f["severity"] == "critical" for f in oracle.findings)

    def test_mass_assignment_exception_swallowed(self):
        def handler(sess, method, url, kwargs):
            if method == "GET":
                return FakeResponse(403, "forbidden")
            raise RuntimeError("connection reset")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        oracle._test_mass_assignment()
        assert oracle.findings == []

    def test_method_tampering_exception_swallowed(self):
        def handler(sess, method, url, kwargs):
            if method == "GET":
                return FakeResponse(403, "forbidden")
            raise RuntimeError("connection reset")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        oracle._test_method_tampering()
        assert oracle.findings == []

    def test_collect_urls_unknown_identity(self):
        oracle = DeviationOracle("http://t.test")
        assert oracle._collect_urls_for_identity("ghost") == []

    def test_authz_gap_identical_public_bodies_are_not_reported(self, monkeypatch, tmp_path):
        """A path that merely requires login is not a BOLA finding: both
        identities receive byte-identical bodies, so session_matrix reports no
        authz_gap and the oracle adds no finding (session_matrix.py:132)."""
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        body = "member area content " * 5
        _install_session_factory(monkeypatch, _static_handler(200, body))

        def handler(sess, method, url, kwargs):
            path = url.replace("http://t.test", "")
            if path == "/admin":
                return FakeResponse(401, "auth required")
            return FakeResponse(404, "nope")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        for label in ("alice", "bob"):
            identity = oracle.matrix.register(label, label, "pw")
            identity.cookies = {"who": label}
            identity.authenticated = True
        oracle._test_authz_gaps()
        assert oracle.findings == []

    def test_authz_gaps_requires_two_identities(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, _static_handler(200, "x" * 80))
        oracle = DeviationOracle("http://t.test", FakeSession(_static_handler(401, "no")))
        oracle.matrix.register("alice", "alice", "pw")
        oracle._test_authz_gaps()
        assert oracle.findings == []

    def test_persisted_sessions_are_never_restored_defect(self, monkeypatch, tmp_path):
        """SessionMatrix._load() has no production caller, so sessions saved to
        ~/.aimy-skill/sessions.json are ignored and authz/IDOR checks are
        silently skipped (session_matrix.py:153, deviation_oracle.py:18)."""
        target = tmp_path / "sessions.json"
        payload = {
            "alice": {
                "label": "alice",
                "username": "a",
                "password": "p",
                "role": "admin",
                "cookies": {"sid": "1"},
                "headers": {},
                "tokens": {},
                "authenticated": True,
                "metadata": {},
            },
            "bob": {
                "label": "bob",
                "username": "b",
                "password": "p",
                "role": "user",
                "cookies": {"sid": "2"},
                "headers": {},
                "tokens": {},
                "authenticated": True,
                "metadata": {},
            },
        }
        target.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(target))
        oracle = DeviationOracle("http://t.test", FakeSession(_static_handler(404, "no")))
        assert oracle.matrix.list() == {}

    def test_idor_chain_finds_sequential_id(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))

        def handler(sess, method, url, kwargs):
            if sess.cookies.get("who") == "bob":
                return FakeResponse(200, "resource " * 10)
            return FakeResponse(403, "denied")

        _install_session_factory(monkeypatch, handler)
        oracle = DeviationOracle("http://t.test", FakeSession(_static_handler(404, "no")))
        for label in ("alice", "bob"):
            identity = oracle.matrix.register(label, label, "pw")
            identity.cookies = {"who": label}
            identity.authenticated = True
        trace = WorkflowTrace(name="alice", identity_label="alice", base_url="http://t.test")
        trace.add_step(_trace_step(0, url="http://t.test/order?id=3"))
        oracle.tracer.traces["alice"] = trace
        oracle._test_idor_chain()
        assert len(oracle.findings) == 1
        finding = oracle.findings[0]
        assert finding["type"] == "idor"
        assert finding["technique"] == "sequential_id_enumerate"
        assert finding["url"] == "http://t.test/order?id=4"
        assert finding["param"] == "id"
        assert finding["original_value"] == "3"
        assert finding["test_value"] == "4"
        assert finding["actor"] == "bob"
        assert finding["target"] == "alice"

    def test_idor_chain_matches_trace_name_not_identity_label_defect(self, monkeypatch, tmp_path):
        """_collect_urls_for_identity() looks up tracer.traces by identity label,
        but traces are keyed by trace name, so a normal trace key makes the whole
        IDOR chain return nothing (deviation_oracle.py:233)."""
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))
        _install_session_factory(monkeypatch, _static_handler(200, "resource " * 10))
        oracle = DeviationOracle("http://t.test", FakeSession(_static_handler(404, "no")))
        for label in ("alice", "bob"):
            identity = oracle.matrix.register(label, label, "pw")
            identity.cookies = {"who": label}
            identity.authenticated = True
        trace = WorkflowTrace(
            name="checkout-flow", identity_label="alice", base_url="http://t.test"
        )
        trace.add_step(_trace_step(0, url="http://t.test/order?id=3"))
        oracle.tracer.traces["checkout-flow"] = trace
        assert oracle._collect_urls_for_identity("alice") == []
        oracle._test_idor_chain()
        assert oracle.findings == []


def _replay_trace(name="flow"):
    trace = WorkflowTrace(name=name, identity_label="alice", base_url="http://t.test")
    trace.add_step(_trace_step(0, method="POST", url="http://t.test/auth", role=StepRole.AUTH))
    trace.add_step(_trace_step(1, method="POST", url="http://t.test/orders", role=StepRole.CREATE))
    return trace


class TestDeviationOracleWorkflow:
    def test_state_replay_reports_skip_and_replay(self):
        def handler(sess, method, url, kwargs):
            path = url.split("?")[0]
            if path.endswith("/orders"):
                return FakeResponse(200, "orders list")
            if path.endswith("/auth"):
                return FakeResponse(200, "sign in required")
            return FakeResponse(404, "nope")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        oracle.tracer.traces["flow"] = _replay_trace()
        oracle._test_state_replay()
        types = [f["type"] for f in oracle.findings]
        assert types.count("workflow_bypass") == 2
        assert types.count("state_replay") == 1

    def test_state_replay_login_body_suppresses_skip_but_not_replay_defect(self):
        """The keyword guard only applies to the skip test; a 200 reply on the
        replayed old URL is recorded even when it is just a login page
        (deviation_oracle.py:123-138)."""

        def handler(sess, method, url, kwargs):
            return FakeResponse(200, "please sign in to continue")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        oracle.tracer.traces["flow"] = _replay_trace()
        oracle._test_state_replay()
        assert [f["type"] for f in oracle.findings] == ["state_replay"]

    def test_state_replay_uses_get_and_ignores_original_method_defect(self):
        """POST workflow steps are replayed with GET (deviation_oracle.py:125),
        and a GET-tolerant endpoint still counts as a successful replay."""
        sess = FakeSession(_static_handler(200, "ok page"))
        oracle = DeviationOracle("http://t.test", sess)
        oracle.tracer.traces["flow"] = _replay_trace()
        oracle._test_state_replay()
        assert all(call[0] == "GET" for call in sess.calls)
        assert {f["type"] for f in oracle.findings} == {"workflow_bypass", "state_replay"}

    def test_state_replay_exception_swallowed(self):
        oracle = DeviationOracle("http://t.test", FakeSession(_raiser))
        oracle.tracer.traces["flow"] = _replay_trace()
        oracle._test_state_replay()
        assert oracle.findings == []

    def test_state_replay_no_traces_returns_early(self):
        oracle = DeviationOracle("http://t.test", FakeSession(_static_handler()))
        oracle._test_state_replay()
        assert oracle.findings == []


class TestDeviationOracleConstraints:
    def test_constraint_breaks_fabricate_findings_without_requests_defect(self):
        """_test_constraint_breaks() records high-severity 'constraint_break'
        findings from generator suggestions without sending a single request
        (deviation_oracle.py:140-159)."""
        sess = FakeSession(_raiser)
        oracle = DeviationOracle("http://t.test", sess)
        oracle.constraint_graph.ingest_request(
            "http://t.test/checkout", None, {"price": "10", "qty": "2"}
        )
        oracle._test_constraint_breaks()
        assert len(oracle.findings) == 29
        assert all(f["type"] == "constraint_break" for f in oracle.findings)
        assert sess.calls == []

    def test_constraint_breaks_empty_graph(self):
        oracle = DeviationOracle("http://t.test", FakeSession(_raiser))
        oracle._test_constraint_breaks()
        assert oracle.findings == []


class TestDeviationOraclePipeline:
    def test_run_collects_findings_from_all_checks(self, monkeypatch, tmp_path):
        monkeypatch.setattr(session_matrix, "SESSION_FILE", str(tmp_path / "s.json"))

        def matrix_handler(sess, method, url, kwargs):
            who = sess.cookies.get("who")
            if "order" in url:
                return (
                    FakeResponse(200, "resource " * 10)
                    if who == "bob"
                    else FakeResponse(403, "denied")
                )
            return (
                FakeResponse(200, "admin area " * 10)
                if who == "alice"
                else FakeResponse(403, "denied")
            )

        _install_session_factory(monkeypatch, matrix_handler)

        def handler(sess, method, url, kwargs):
            path = url.split("?")[0].replace("http://t.test", "")
            if method == "GET":
                if path == "/admin":
                    return FakeResponse(403, "forbidden")
                if path in ("/order", "/orders", "/auth"):
                    return FakeResponse(200, "orders list page")
                return FakeResponse(404, "nope")
            if path == "/admin":
                return FakeResponse(200, "admin panel")
            return FakeResponse(404, "nope")

        oracle = DeviationOracle("http://t.test", FakeSession(handler))
        for label in ("alice", "bob"):
            identity = oracle.matrix.register(label, label, "pw")
            identity.cookies = {"who": label}
            identity.authenticated = True
        trace = _replay_trace()
        trace.add_step(_trace_step(2, url="http://t.test/order?id=3"))
        oracle.tracer.traces["alice"] = trace
        oracle.constraint_graph.ingest_request(
            "http://t.test/checkout", None, {"price": "10", "qty": "2"}
        )

        result = oracle.run()
        assert result["vulnerable"] is True
        assert result["total"] == len(oracle.findings) == 60
        assert {f["type"] for f in result["findings"]} == {
            "authz_gap",
            "idor",
            "workflow_bypass",
            "state_replay",
            "method_tampering",
            "mass_assignment",
            "constraint_break",
        }

    def test_check_wrapper_returns_clean_result(self):
        sess = FakeSession(_static_handler(404, "not found"))
        result = deviation_oracle.check("http://t.test", sess=sess)
        assert result == {"vulnerable": False, "findings": [], "total": 0}
        assert sess.verify is not None

    def test_check_wrapper_creates_default_session(self, monkeypatch):
        created = _install_session_factory(monkeypatch, _static_handler(404, "not found"))
        result = deviation_oracle.check("http://t.test")
        assert result["vulnerable"] is False
        assert created[0].verify is not None


class TestOracleSession:
    def test_as_user_returns_session_and_resets_tracer(self, monkeypatch):
        _install_session_factory(monkeypatch, _static_handler(200, "ok"))
        oracle = OracleSession("http://t.test")
        oracle.matrix.register("alice", "alice", "pw")
        sess = oracle.as_user("alice")
        assert isinstance(sess, FakeSession)
        assert isinstance(oracle.tracer, WorkflowTracer)

    def test_as_user_unknown_keeps_tracer(self):
        oracle = OracleSession("http://t.test")
        tracer = oracle.tracer
        assert oracle.as_user("ghost") is None
        assert oracle.tracer is tracer

    def test_go_dispatch_is_broken_defect(self):
        """OracleSession.go() dispatches to self.get/self.post which do not
        exist, so any call raises AttributeError (deviation_oracle.py:253-254)."""
        with pytest.raises(AttributeError):
            OracleSession("http://t.test").go("GET", "http://t.test/x")


class TestRaceProfilerAnalysis:
    def _profiler(self, handler=None):
        return RaceProfiler(FakeSession(handler))

    def test_analyze_window_empty_responses(self):
        window = self._profiler()._analyze_window([], 200, "ok", 2, 5)
        assert window.elapsed_ms == 0
        assert window.duplicate_success is False
        assert window.state_mismatch is False
        assert window.integrity_violated is False
        assert window.resource_created_twice is False

    def test_analyze_window_duplicate_success(self):
        responses = [_patch(None, 200, "ok"), _patch(None, 200, "ok")]
        window = self._profiler()._analyze_window(responses, 200, "ok", 2, 2)
        assert window.duplicate_success is True
        assert window.state_mismatch is False
        assert window.integrity_violated is False
        assert window.resource_created_twice is False

    def test_analyze_window_uniform_failures_have_no_flags(self):
        responses = [_patch(None, 400, "rate limited") for _ in range(5)]
        window = self._profiler()._analyze_window(responses, 200, "ok", 2, 5)
        assert window.duplicate_success is False
        assert window.state_mismatch is False
        assert window.integrity_violated is False
        assert window.resource_created_twice is False

    def test_integrity_flag_is_order_independent(self):
        # 修复: 同一响应集合无论到达顺序, 完整性判定一致
        profiler = self._profiler()
        stable_first = [_patch(None, 200, "stable"), _patch(None, 200, "changed")]
        changed_first = [_patch(None, 200, "changed"), _patch(None, 200, "stable")]
        w1 = profiler._analyze_window(stable_first, 200, "stable", 6, 2)
        w2 = profiler._analyze_window(changed_first, 200, "stable", 6, 2)
        assert w1.state_mismatch is True and w2.state_mismatch is True
        assert w1.integrity_violated is True
        assert w2.integrity_violated is True

    def test_consistent_new_state_after_race_is_not_flagged_defect(self):
        """When every concurrent response shows the same *new* state that
        differs from the baseline, integrity_violated stays False because the
        check requires the responses to disagree with each other."""
        responses = [_patch(None, 200, "after"), _patch(None, 200, "after")]
        window = self._profiler()._analyze_window(responses, 200, "before", 6, 2)
        assert window.duplicate_success is True
        assert window.state_mismatch is False
        assert window.integrity_violated is False

    def test_resource_created_twice_same_id_is_missed_defect(self):
        """Repeated creation returning the same resource id (the classic double
        redeem result) is never flagged: the condition requires at least two
        distinct ids (race_profiler.py:157)."""
        responses = [_patch(None, 200, json.dumps({"id": 7})) for _ in range(3)]
        window = self._profiler()._analyze_window(responses, 200, "{}", 2, 3)
        assert window.resource_created_twice is False

    def test_resource_created_twice_unique_ids_is_missed_defect(self):
        """Mass creation with unique ids per request is never flagged either,
        because len(created_ids) > len(set(created_ids)) is False."""
        responses = [_patch(None, 200, json.dumps({"id": i})) for i in (1, 2, 3)]
        window = self._profiler()._analyze_window(responses, 200, "{}", 2, 3)
        assert window.resource_created_twice is False

    def test_resource_created_twice_mixed_ids_is_the_only_hit(self):
        responses = [
            _patch(None, 200, json.dumps({"id": 1})),
            _patch(None, 200, json.dumps({"id": 1})),
            _patch(None, 200, json.dumps({"id": 2})),
        ]
        window = self._profiler()._analyze_window(responses, 200, "{}", 2, 3)
        assert window.resource_created_twice is True

    def test_resource_id_parsing_ignores_non_json_success(self):
        responses = [_patch(None, 200, "not json"), _patch(None, 201, json.dumps({"uuid": "u-1"}))]
        window = self._profiler()._analyze_window(responses, 200, "", 0, 2)
        assert window.resource_created_twice is False
        assert window.duplicate_success is True


class TestRaceProfilerDetect:
    def test_detect_windows_found_for_all_concurrencies(self):
        sess = FakeSession(_static_handler(200, "ok"))
        result = RaceProfiler(sess, timeout=1.0).detect_windows(
            "http://t.test/redeem", "coupon", "POST", {"coupon": "1"}
        )
        assert result["window_found"] is True
        assert [w.concurrency for w in result["windows"]] == [5, 10, 20, 50]
        assert len(sess.calls) == 1 + 5 + 10 + 20 + 50

    def test_detect_windows_none_when_all_race_requests_fail(self):
        sess = FakeSession(_static_handler(400, "rate limited"))
        result = RaceProfiler(sess, timeout=1.0).detect_windows(
            "http://t.test/redeem", "coupon", "POST", {"coupon": "1"}
        )
        assert result == {"window_found": False, "windows": []}
        assert len(sess.calls) == 1 + 3 * (5 + 10 + 20 + 50)

    def test_detect_windows_baseline_failure_returns_empty(self):
        sess = FakeSession(_raiser)
        result = RaceProfiler(sess, timeout=1.0).detect_windows(
            "http://t.test/redeem", "coupon", "POST", {"coupon": "1"}
        )
        assert result == {"window_found": False, "windows": []}
        assert len(sess.calls) == 1

    def test_baseline_body_argument_swap_false_positive_defect(self):
        """修复后: detect_windows() 正确传入基线体, 混合响应集合稳定标记
        integrity_violated (与 as_completed 顺序无关)."""
        counter = {"n": 0}
        lock = threading.Lock()

        def handler(sess, method, url, kwargs):
            with lock:
                counter["n"] += 1
                n = counter["n"]
            return FakeResponse(200, "stable" if n % 2 else "changed")

        sess = FakeSession(handler)
        result = RaceProfiler(sess, timeout=1.0).detect_windows(
            "http://t.test/redeem", "coupon", "POST", {"coupon": "1"}
        )
        assert result["window_found"] is True
        window = result["windows"][0]
        bodies = {r["body"] for r in window.responses}
        assert bodies == {"stable", "changed"}
        assert window.integrity_violated is True

    def test_correct_analyze_window_call_does_not_flag_same_multiset(self):
        profiler = RaceProfiler(FakeSession())
        responses = [_patch(None, 200, "stable"), _patch(None, 200, "changed")]
        window = profiler._analyze_window(responses, 200, "stable", len("stable"), 2)
        assert window.state_mismatch is True
        # 修复后顺序无关: 混合响应集合稳定判为完整性破坏
        assert window.integrity_violated is True

    def test_race_round_records_transport_errors_as_status_zero(self):
        profiler = RaceProfiler(FakeSession(_raiser))
        responses = profiler._race_round("http://t.test/x", "POST", None, 3)
        assert len(responses) == 3
        assert all(r["status"] == 0 and r["error"] == "network down" for r in responses)

    def test_single_request_reports_elapsed_ms(self, monkeypatch):
        monkeypatch.setattr(race_profiler, "time", FrozenClock([10.0, 10.25]))
        profiler = RaceProfiler(FakeSession(_static_handler(200, "ok")))
        result = profiler._single_request("http://t.test/x", "GET")
        assert result["elapsed_ms"] == 250.0

    def test_check_get_marks_vulnerable_false_positive_defect(self):
        """check() defaults to GET for URLs without write keywords; any endpoint
        that answers 200 to every request then satisfies duplicate_success and
        is reported as race-vulnerable (race_profiler.py:134-135, 208)."""
        sess = FakeSession(_static_handler(200, "dashboard"))
        result = race_profiler.check("http://t.test/dashboard", None, sess)
        assert result["vulnerable"] is True
        assert result["windows_found"] == 4
        assert {call[0] for call in sess.calls} == {"GET"}

    def test_check_returns_non_serializable_windows_defect(self):
        sess = FakeSession(_static_handler(200, "dashboard"))
        result = race_profiler.check("http://t.test/dashboard", None, sess)
        with pytest.raises(TypeError):
            json.dumps(result["race_windows"])

    def test_check_write_keyword_uses_post(self):
        sess = FakeSession(_static_handler(200, "claimed"))
        result = race_profiler.check("http://t.test/api/redeem", "coupon", sess)
        assert result["vulnerable"] is True
        assert {call[0] for call in sess.calls} == {"POST"}
        assert sess.calls[0][2]["json"] == {"coupon": "1"}

    def test_check_creates_default_session_when_missing(self, monkeypatch):
        created = _install_session_factory(monkeypatch, _static_handler(200, "ok"))
        result = race_profiler.check("http://t.test/api/redeem", "coupon")
        assert result["vulnerable"] is True
        assert created[0].verify is not None


class TestRaceProfilerState:
    def test_transaction_probe_checkpoint_roundtrip(self):
        probe = TransactionProbe(FakeSession(_static_handler(200, "state-1")))
        assert probe.checkpoint("a", "http://t.test/a") == "state-1"
        assert probe.verify("a", "a") == {
            "checkpoint_a": "a",
            "checkpoint_b": "a",
            "changed": False,
            "len_before": 7,
            "len_after": 7,
        }

    def test_transaction_probe_verify_reports_changed(self):
        probe = TransactionProbe(FakeSession(_static_handler(200, "state-1")))
        probe.checkpoint("a", "http://t.test/a")
        probe._state_checkpoints["b"] = "state-2-longer"
        result = probe.verify("a", "b")
        assert result["changed"] is True
        assert (result["len_before"], result["len_after"]) == (7, 14)

    def test_transaction_probe_checkpoint_exception_returns_none(self):
        probe = TransactionProbe(FakeSession(_raiser))
        assert probe.checkpoint("a", "http://t.test/a") is None
        assert probe.verify("a", "b") == {"error": "missing checkpoint", "changed": False}

    def test_state_integrity_unchanged(self):
        checker = StateIntegrityChecker(FakeSession(_static_handler(200, "payload")))
        assert checker.snapshot("http://t.test/cart", "http://t.test/cart") == "payload"
        result = checker.assert_integrity("http://t.test/cart")
        assert result["http://t.test/cart"]["status"] == "ok"
        assert result["http://t.test/cart"]["unchanged"] is True

    def test_state_integrity_reports_modified(self):
        state = {"n": 0}

        def handler(sess, method, url, kwargs):
            state["n"] += 1
            return FakeResponse(200, "payload-%d" % state["n"])

        checker = StateIntegrityChecker(FakeSession(handler))
        checker.snapshot("http://t.test/cart", "http://t.test/cart")
        result = checker.assert_integrity("http://t.test/cart")
        assert result["http://t.test/cart"]["status"] == "modified"

    def test_state_integrity_no_baseline(self):
        checker = StateIntegrityChecker(FakeSession(_static_handler()))
        assert checker.assert_integrity("ghost") == {"ghost": {"status": "no_baseline"}}

    def test_state_integrity_request_error(self):
        state = {"n": 0}

        def handler(sess, method, url, kwargs):
            state["n"] += 1
            if state["n"] > 1:
                raise RuntimeError("connection reset")
            return FakeResponse(200, "payload")

        checker = StateIntegrityChecker(FakeSession(handler))
        checker.snapshot("http://t.test/cart", "http://t.test/cart")
        result = checker.assert_integrity("http://t.test/cart")
        assert result["http://t.test/cart"]["status"] == "error"

    def test_state_integrity_requests_label_not_snapshot_url_defect(self):
        """assert_integrity() re-requests the label as a URL
        (`label if label.startswith('http') else label`, race_profiler.py:185),
        not the URL the snapshot was taken from, so the comparison is against a
        different resource."""
        sess = FakeSession(lambda s, m, u, k: FakeResponse(200, "payload-" + u))
        checker = StateIntegrityChecker(sess)
        checker.snapshot("cart", "http://t.test/cart")
        result = checker.assert_integrity("cart")
        assert sess.calls[-1][1] == "cart"
        assert result["cart"]["status"] == "modified"

    def test_state_integrity_snapshot_exception_returns_none(self):
        checker = StateIntegrityChecker(FakeSession(_raiser))
        assert checker.snapshot("cart", "http://t.test/cart") is None


class TestCrossValidatorSqliLfi:
    URL = "http://t.test/item?id=1"

    def test_unix_passwd_leak_detected(self):
        sess = FakeSession(
            _static_handler(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon")
        )
        result = cross_validator.validate_sqli_with_lfi(self.URL, "id", sess)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.9
        assert result["dbms"] == "mysql"
        assert result["evidence"][0]["method"] == "mysql_load_file"
        assert len(sess.calls) == 1

    def test_windows_ini_leak_detected(self):
        sess = FakeSession(_static_handler(200, "[fonts]\r\nArial=arial.ttf"))
        result = cross_validator.validate_sqli_with_lfi(self.URL, "id", sess)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.85
        assert result["evidence"][0]["method"] == "mysql_load_file_win"

    def test_no_leak_tries_all_payloads(self):
        sess = FakeSession(_static_handler(200, "no data"))
        result = cross_validator.validate_sqli_with_lfi(self.URL, "id", sess)
        assert result["vulnerable"] is False
        assert result["confidence"] == 0.0
        assert len(sess.calls) == 9

    def test_status_500_with_leaked_file_is_missed_defect(self):
        """Only HTTP 200 responses are inspected, so a 500 carrying the file
        contents (query error output / partial response) is a false negative
        (cross_validator.py:19)."""
        sess = FakeSession(_static_handler(500, "root:x:0:0:root:/root:/bin/bash"))
        result = cross_validator.validate_sqli_with_lfi(self.URL, "id", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 9

    def test_transport_errors_are_swallowed_defect(self):
        """`except Exception: continue` makes network failures indistinguishable
        from 'not vulnerable'; no error field is surfaced
        (cross_validator.py:32-33)."""
        sess = FakeSession(_raiser)
        result = cross_validator.validate_sqli_with_lfi(self.URL, "id", sess)
        assert result == {
            "vulnerable": False,
            "method": "sqli_lfi_cross",
            "confidence": 0.0,
            "evidence": [],
        }
        assert len(sess.calls) == 9


class TestCrossValidatorSsrfLfi:
    URL = "http://t.test/fetch?url=x"

    def test_file_read_detected_and_breaks(self):
        sess = FakeSession(
            _static_handler(200, "PATH=/usr/local/bin:/usr/bin:/bin\nHOSTNAME=web-1")
        )
        result = cross_validator.validate_ssrf_with_lfi(self.URL, "url", sess)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.85
        assert result["evidence"][0]["type"] == "file_read"
        assert len(sess.calls) == 1

    def test_short_file_body_is_missed_defect(self):
        """/etc/issue style short reads (<= 30 chars) are discarded by the
        len(r.text) > 30 gate even though the file content leaked
        (cross_validator.py:49)."""
        sess = FakeSession(_static_handler(200, "root:x:0:0"))
        result = cross_validator.validate_ssrf_with_lfi(self.URL, "url", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 5

    def test_unrelated_body_not_flagged(self):
        sess = FakeSession(_static_handler(200, "no such file here, sorry for the inconvenience"))
        result = cross_validator.validate_ssrf_with_lfi(self.URL, "url", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 5

    def test_transport_errors_are_swallowed(self):
        sess = FakeSession(_raiser)
        result = cross_validator.validate_ssrf_with_lfi(self.URL, "url", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 5


class TestCrossValidatorLogPoison:
    URL = "http://t.test/page?file=x"

    def test_log_poison_marker_found(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))

        def handler(sess, method, url, kwargs):
            if "nginx" in url:
                return FakeResponse(200, "access log CROSSVAL_1234 entry")
            return FakeResponse(200, "logged")

        sess = FakeSession(handler)
        result = cross_validator.validate_lfi_with_log_poison(self.URL, "file", sess)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.95
        assert result["rce_available"] is True
        assert result["evidence"][0]["marker_found"] == "CROSSVAL_1234"
        assert len(sess.calls) == 4

    def test_poison_request_error_is_swallowed_and_scan_continues(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))

        def handler(sess, method, url, kwargs):
            if "headers" in kwargs:
                raise RuntimeError("connection reset")
            return FakeResponse(200, "log CROSSVAL_1234 inside")

        sess = FakeSession(handler)
        result = cross_validator.validate_lfi_with_log_poison(self.URL, "file", sess)
        assert result["vulnerable"] is True
        assert len(sess.calls) == 2

    def test_marker_absent(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))
        sess = FakeSession(_static_handler(200, "nothing useful"))
        result = cross_validator.validate_lfi_with_log_poison(self.URL, "file", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 6

    def test_log_request_error_is_swallowed_and_next_path_tried(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))

        def handler(sess, method, url, kwargs):
            if "headers" in kwargs:
                return FakeResponse(200, "logged")
            if "apache2" in url:
                raise RuntimeError("boom")
            return FakeResponse(200, "CROSSVAL_1234")

        sess = FakeSession(handler)
        result = cross_validator.validate_lfi_with_log_poison(self.URL, "file", sess)
        assert result["vulnerable"] is True
        assert len(sess.calls) == 3


class TestCrossValidatorSecondOrder:
    URL = "http://t.test/item?id=1"

    def test_second_order_marker_found(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))

        def handler(sess, method, url, kwargs):
            if url == self.URL:
                return FakeResponse(200, "page SORD_1234 content")
            return FakeResponse(200, "ok")

        sess = FakeSession(handler)
        result = cross_validator.validate_sqli_with_second_order(self.URL, "id", sess)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.9
        assert result["evidence"][0]["method"] == "second_order_injection"
        assert len(sess.calls) == 4

    def test_param_substring_replacement_breaks_confirmation_defect(self, monkeypatch):
        """`url.replace(param + '=', ...)` rewrites any parameter whose name
        ends with the tested param (userid= -> userid=SORD_...1), so the marker
        is never injected as the value of `id` and the confirmation URL is
        malformed (cross_validator.py:108)."""
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))
        url = "http://t.test/item?userid=1"

        def handler(sess, method, url, kwargs):
            qs = parse_qs(urlparse(url).query)
            if qs.get("id") == ["SORD_1234"]:
                return FakeResponse(200, "SORD_1234")
            return FakeResponse(200, "ok")

        sess = FakeSession(handler)
        result = cross_validator.validate_sqli_with_second_order(url, "id", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 6
        assert "userid=SORD_12341" in sess.calls[-1][1]

    def test_marker_absent(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))
        sess = FakeSession(_static_handler(200, "ok"))
        result = cross_validator.validate_sqli_with_second_order(self.URL, "id", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 6

    def test_confirm_request_errors_are_swallowed(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))

        def handler(sess, method, url, kwargs):
            if "UNION" in url:
                return FakeResponse(200, "ok")
            raise RuntimeError("boom")

        sess = FakeSession(handler)
        result = cross_validator.validate_sqli_with_second_order(self.URL, "id", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 6

    def test_inject_request_errors_are_swallowed(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))

        def handler(sess, method, url, kwargs):
            if url == self.URL:
                return FakeResponse(200, "SORD_1234")
            raise RuntimeError("boom")

        sess = FakeSession(handler)
        result = cross_validator.validate_sqli_with_second_order(self.URL, "id", sess)
        assert result["vulnerable"] is True
        assert len(sess.calls) == 4


class TestCrossValidatorAuthSqli:
    URL = "http://t.test/login?user=x"

    def test_bypass_page_detected(self):
        body = "Welcome to the dashboard. " * 5
        sess = FakeSession(_static_handler(200, body))
        result = cross_validator.validate_auth_with_sqli(self.URL, "user", sess)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.75
        assert len(sess.calls) == 1

    def test_password_keyword_suppresses_real_bypass_defect(self):
        """A dashboard that merely contains the word 'password' (change-password
        link) cancels the finding for every payload
        (cross_validator.py:137-139)."""
        body = "Welcome back, please update your password soon to stay secure. " * 2
        sess = FakeSession(_static_handler(200, body))
        result = cross_validator.validate_auth_with_sqli(self.URL, "user", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 6

    def test_public_page_is_false_positive_defect(self):
        """Any 200 page > 100 chars without login keywords counts as an auth
        bypass; there is no comparison against a baseline request
        (cross_validator.py:139)."""
        sess = FakeSession(_static_handler(200, "Public documentation index. " * 5))
        result = cross_validator.validate_auth_with_sqli(self.URL, "user", sess)
        assert result["vulnerable"] is True
        assert len(sess.calls) == 1

    def test_non_200_ignored(self):
        sess = FakeSession(_static_handler(403, "Forbidden"))
        result = cross_validator.validate_auth_with_sqli(self.URL, "user", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 6

    def test_transport_errors_are_swallowed(self):
        sess = FakeSession(_raiser)
        result = cross_validator.validate_auth_with_sqli(self.URL, "user", sess)
        assert result["vulnerable"] is False
        assert len(sess.calls) == 6


class TestCrossValidatorDispatch:
    def _vuln(self, confidence):
        def fn(url, param, sess, timeout=10.0):
            return {"vulnerable": True, "confidence": confidence, "method": "stub"}

        return fn

    def _safe(self):
        def fn(url, param, sess, timeout=10.0):
            return {"vulnerable": False, "confidence": 0.0, "method": "stub"}

        return fn

    def test_sqli_merges_both_cross_checks(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "validate_sqli_with_lfi", self._vuln(0.8))
        monkeypatch.setattr(cross_validator, "validate_sqli_with_second_order", self._vuln(0.6))
        result = cross_validator.run_cross_validation(
            "sqli", "http://t.test/x", "id", FakeSession()
        )
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.8
        assert set(result["cross_checks"]) == {"sqli_to_lfi", "second_order"}

    def test_ssrf_check(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "validate_ssrf_with_lfi", self._vuln(0.85))
        result = cross_validator.run_cross_validation(
            "ssrf", "http://t.test/x", "url", FakeSession()
        )
        assert set(result["cross_checks"]) == {"ssrf_to_file_read"}
        assert result["confidence"] == 0.85

    def test_lfi_check(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "validate_lfi_with_log_poison", self._vuln(0.95))
        result = cross_validator.run_cross_validation(
            "lfi", "http://t.test/x", "file", FakeSession()
        )
        assert set(result["cross_checks"]) == {"lfi_to_rce"}

    def test_auth_bypass_check(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "validate_auth_with_sqli", self._vuln(0.75))
        result = cross_validator.run_cross_validation(
            "auth_bypass", "http://t.test/x", "user", FakeSession()
        )
        assert set(result["cross_checks"]) == {"auth_sqli_bypass"}

    def test_negative_result_has_no_cross_checks(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "validate_sqli_with_lfi", self._safe())
        monkeypatch.setattr(cross_validator, "validate_sqli_with_second_order", self._safe())
        result = cross_validator.run_cross_validation(
            "sqli", "http://t.test/x", "id", FakeSession()
        )
        assert result == {"vulnerable": False, "confidence": 0.0, "method": "cross_validation"}

    def test_unknown_vtype_runs_nothing(self):
        sess = FakeSession(_raiser)
        result = cross_validator.run_cross_validation("xss", "http://t.test/x", "q", sess)
        assert result["vulnerable"] is False
        assert sess.calls == []

    def test_real_second_order_hit_through_dispatch(self, monkeypatch):
        monkeypatch.setattr(cross_validator, "time", FrozenClock([1234.0]))

        def handler(sess, method, url, kwargs):
            if url == "http://t.test/item?id=1":
                return FakeResponse(200, "SORD_1234")
            return FakeResponse(200, "no leak")

        sess = FakeSession(handler)
        result = cross_validator.run_cross_validation("sqli", "http://t.test/item?id=1", "id", sess)
        assert result["vulnerable"] is True
        assert set(result["cross_checks"]) == {"second_order"}


class TestCsrfTokenParsing:
    def test_name_before_value_order(self):
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
        assert csrf_scanner._find_csrf_token(html) == [
            {"name": "csrfmiddlewaretoken", "value": "abc123"}
        ]

    def test_value_before_name_order(self):
        html = '<input value="tok-xyz" name="authenticity_token">'
        assert csrf_scanner._find_csrf_token(html) == [
            {"name": "authenticity_token", "value": "tok-xyz"}
        ]

    def test_data_attribute(self):
        html = '<div data-csrf="d1"></div>'
        assert csrf_scanner._find_csrf_token(html) == [{"name": "csrf", "value": "d1"}]

    def test_value_is_truncated_to_30_chars(self):
        value = "0123456789" * 4
        html = '<input name="csrf" value="%s">' % value
        assert csrf_scanner._find_csrf_token(html)[0]["value"] == value[:30]

    def test_case_insensitive_match(self):
        html = '<input name="CSRF_TOKEN" value="tok">'
        assert csrf_scanner._find_csrf_token(html) == [{"name": "csrf_token", "value": "tok"}]

    def test_meta_tag_token_is_found(self):
        """`<meta name="csrf-token" content="...">` is parsed like an input
        token (csrf_scanner.py:40)."""
        html = '<head><meta name="csrf-token" content="meta-value"></head>'
        assert csrf_scanner._find_csrf_token(html) == [
            {"name": "csrf-token", "value": "meta-value"}
        ]

    def test_no_token(self):
        assert csrf_scanner._find_csrf_token("<html><body>plain</body></html>") == []

    def test_has_csrf_header_upper_and_lower(self):
        assert csrf_scanner._has_csrf_header(FakeResponse(headers={"X-XSRF-TOKEN": "t"})) == [
            "X-XSRF-TOKEN"
        ]
        assert csrf_scanner._has_csrf_header(FakeResponse(headers={"x-csrf-token": "t"})) == [
            "X-CSRF-TOKEN"
        ]
        assert csrf_scanner._has_csrf_header(FakeResponse()) == []

    def test_find_forms_actions_methods_and_inputs(self):
        html = (
            '<form method="post" action="update"><input name="a"></form>'
            '<form action="" method="post"><input name="b"></form>'
            '<form action="/abs" method="get"><input name="c"></form>'
            '<form action="http://other.test/x" method="post"><input name="d"></form>'
        )
        forms = csrf_scanner._find_forms(html, "http://t.test/dir/page")
        assert [f["action"] for f in forms] == [
            "http://t.test/dir/update",
            "http://t.test/dir/page",
            "http://t.test/abs",
            "http://other.test/x",
        ]
        assert [f["method"] for f in forms] == ["POST", "POST", "GET", "POST"]
        assert forms[2]["inputs"] == ["c"]

    def test_form_without_action_attribute_defaults_to_base_url(self):
        """Action-less POST forms (common in SPAs) are parsed with the page URL
        as their action."""
        html = '<form method="post"><input name="secret"></form>'
        assert csrf_scanner._find_forms(html, "http://t.test/") == [
            {"action": "http://t.test/", "method": "POST", "inputs": ["secret"]}
        ]

    def test_is_sensitive_depends_on_action_and_method(self):
        assert csrf_scanner._is_sensitive("/user/update", "POST") is True
        assert csrf_scanner._is_sensitive("/transfer", "POST") is True
        assert csrf_scanner._is_sensitive("/search", "POST") is False
        assert csrf_scanner._is_sensitive("/user/delete", "GET") is False


class TestCsrfCheck:
    def test_missing_token_on_post_form(self):
        html = '<form method="post" action="/update"><input name="username"></form>'
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_static_handler(200, html)))
        assert result["csrf_protected"] is False
        assert result["forms_analyzed"] == 1
        assert result["findings"] == [
            {
                "type": "missing_csrf_token",
                "action": "http://t.test/update",
                "method": "POST",
                "inputs": ["username"],
                "sensitive": True,
            }
        ]
        assert result["vulnerable"] is True

    def test_token_present_is_not_vulnerable(self):
        html = (
            '<form method="post" action="/profile/update">'
            '<input type="hidden" name="csrf_token" value="tok">'
            '<input name="email"></form>'
        )
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_static_handler(200, html)))
        assert result["csrf_protected"] is True
        assert result["findings"] == []
        assert result["vulnerable"] is False

    def test_get_forms_are_ignored(self):
        html = '<form method="get" action="/search"><input name="q"></form>'
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_static_handler(200, html)))
        assert result["forms_analyzed"] == 1
        assert result["findings"] == []
        assert result["vulnerable"] is False

    def test_javascript_action_is_skipped_and_not_vulnerable(self):
        html = '<form method="post" action="javascript:submit()"><input name="a"></form>'
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_static_handler(200, html)))
        assert result["forms_analyzed"] == 1
        assert result["findings"] == []
        assert result["vulnerable"] is False

    def test_page_wide_token_masks_missing_token_on_login_form_defect(self):
        """csrf_protected is page-global: a token in an unrelated form hides a
        login form without any token, and _is_sensitive() looks only at the
        action URL, so the login form is not even classified sensitive
        (csrf_scanner.py:109-130)."""
        html = (
            '<form method="post" action="/auth/login">'
            '<input name="username"><input name="password"></form>'
            '<form method="post" action="/search">'
            '<input name="q"><input type="hidden" name="csrf_token" value="tok">'
            "</form>"
        )
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_static_handler(200, html)))
        assert result["csrf_protected"] is True
        assert len(result["findings"]) == 1
        assert result["findings"][0]["action"] == "http://t.test/auth/login"
        assert result["findings"][0]["sensitive"] is False
        assert result["vulnerable"] is False

    def test_meta_token_detected_but_form_without_input_token_is_flagged(self):
        """The meta CSRF token is parsed and marks the page protected, but the
        form itself carries no token input, so the form-level match still
        reports it (csrf_scanner.py:40, 125-135)."""
        html = (
            '<head><meta name="csrf-token" content="meta-value"></head>'
            '<form method="post" action="/account/delete">'
            '<input name="confirm"></form>'
        )
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_static_handler(200, html)))
        assert result["token_in_page"] == [{"name": "csrf-token", "value": "meta-value"}]
        assert result["csrf_protected"] is True
        assert result["findings"] == [
            {
                "type": "missing_csrf_token",
                "action": "http://t.test/account/delete",
                "method": "POST",
                "inputs": ["confirm"],
                "sensitive": True,
            }
        ]
        assert result["vulnerable"] is True

    def test_csrf_header_marks_protected(self):
        html = '<form method="post" action="/search"><input name="q"></form>'
        result = csrf_scanner.check(
            "http://t.test/",
            sess=FakeSession(_static_handler(200, html, headers={"X-CSRF-TOKEN": "abc"})),
        )
        assert result["csrf_header"] == ["X-CSRF-TOKEN"]
        assert result["csrf_protected"] is True
        assert result["vulnerable"] is False

    def test_header_protection_keeps_finding_but_suppresses_vulnerable(self):
        """A sensitive form without a hidden token is still listed as a finding
        even when the application enforces CSRF via a response header, but the
        header protection keeps it from being reported vulnerable."""
        html = '<form method="post" action="/account/delete"><input name="confirm"></form>'
        result = csrf_scanner.check(
            "http://t.test/",
            sess=FakeSession(_static_handler(200, html, headers={"X-CSRF-TOKEN": "abc"})),
        )
        assert result["csrf_header"] == ["X-CSRF-TOKEN"]
        assert result["csrf_protected"] is True
        assert len(result["findings"]) == 1
        assert result["findings"][0]["sensitive"] is True
        assert result["vulnerable"] is False

    def test_form_without_inputs_is_not_flagged(self):
        """A POST form with no inputs has nothing to protect and generates
        neither a finding nor vulnerable=True (csrf_scanner.py:128)."""
        html = '<form method="post" action="/search"></form>'
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_static_handler(200, html)))
        assert result["forms_analyzed"] == 1
        assert result["findings"] == []
        assert result["vulnerable"] is False

    def test_request_exception_returns_error(self):
        result = csrf_scanner.check("http://t.test/", sess=FakeSession(_raiser))
        assert result["error"] == "network down"
        assert result["vulnerable"] is False

    def test_default_session_is_configured(self, monkeypatch):
        html = '<form method="post" action="/update"><input name="a"></form>'
        created = _install_session_factory(monkeypatch, _static_handler(200, html))
        result = csrf_scanner.check("http://t.test/")
        assert result["forms_analyzed"] == 1
        assert created[0].headers["User-Agent"].startswith("Mozilla/5.0")
        from tools.settings import settings

        assert created[0].verify == settings.verify_ssl


class TestCsrfBypass:
    URL = "http://t.test/form"

    def test_all_200_tests_mark_bypassable(self):
        sess = FakeSession(_static_handler(200, "ok"))
        result = csrf_scanner.bypass_check(self.URL, "/action", {"a": "1"}, sess)
        assert [t["test"] for t in result["tests"]] == [
            "no_referer",
            "no_origin",
            "wrong_origin",
            "method_override",
            "json_content_type",
        ]
        assert result["bypassable"] is True
        assert sess.calls[3][0] == "GET"
        assert sess.calls[3][2]["params"] == {"a": "1"}
        assert sess.calls[4][2]["json"] == {"a": "1"}

    def test_403_responses_not_bypassable(self):
        sess = FakeSession(_static_handler(403, "forbidden"))
        result = csrf_scanner.bypass_check(self.URL, "/action", {"a": "1"}, sess)
        assert len(result["tests"]) == 5
        assert all(t["bypassed"] is False for t in result["tests"])
        assert result["bypassable"] is False

    def test_500_responses_are_not_recorded(self):
        sess = FakeSession(_static_handler(500, "error"))
        result = csrf_scanner.bypass_check(self.URL, "/action", {"a": "1"}, sess)
        assert result["tests"] == []
        assert result["bypassable"] is False

    def test_exceptions_recorded_as_errors(self):
        sess = FakeSession(_raiser)
        result = csrf_scanner.bypass_check(self.URL, "/action", {"a": "1"}, sess)
        assert len(result["tests"]) == 5
        assert all(t["error"] == "network down" for t in result["tests"])
        assert result["bypassable"] is False

    def test_error_page_with_200_is_not_a_bypass(self):
        """An HTTP 200 CSRF rejection page is not a bypass: the body must also
        lack failure markers (csrf_scanner.py:178-185)."""
        sess = FakeSession(_static_handler(200, "CSRF verification failed. Request aborted."))
        result = csrf_scanner.bypass_check(self.URL, "/action", {"a": "1"}, sess)
        assert len(result["tests"]) == 5
        assert all(t["bypassed"] is False for t in result["tests"])
        assert result["bypassable"] is False

    def test_default_session_is_configured(self, monkeypatch):
        created = _install_session_factory(monkeypatch, _static_handler(200, "ok"))
        result = csrf_scanner.bypass_check(self.URL, "/action", {"a": "1"})
        assert result["bypassable"] is True
        assert created[0].verify is not None
