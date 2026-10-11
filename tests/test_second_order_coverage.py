"""Offline coverage tests for tools/second_order_verifier.py.

All HTTP is mocked (no network), time.time/time.sleep are patched, and
socket.getaddrinfo is patched so DNS callbacks never touch the resolver.
"""
import base64
import re
import socket
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from tools.second_order_verifier import (
    SecondOrderVerifier,
    VerificationResult,
    check,
)


class _Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status


def _payload_of(url, data):
    if isinstance(data, dict):
        return str(data.get("p", ""))
    if isinstance(data, str) and data:
        return data
    return parse_qs(urlparse(url).query).get("p", [""])[0]


def _handler(fn):
    def wrapped(url, method="GET", data=None, headers=None, cookies=None):
        return fn(_payload_of(url, data), url, method, data)
    return wrapped


def _run(handler, vuln_type, sess=None, evidence=None, **kwargs):
    sess = sess if sess is not None else MagicMock()
    with patch.object(SecondOrderVerifier, "_make_request",
                      MagicMock(side_effect=handler)), \
            patch("tools.second_order_verifier.time", MagicMock()):
        verifier = SecondOrderVerifier(sess=sess, timeout=5.0)
        return verifier.verify("http://t.local/page", "p", vuln_type, evidence, **kwargs)


# ---------------------------------------------------------------- SQLi

def _sqli_success(payload, url, method, data):
    if "SLEEP" in payload or "WAITFOR" in payload or "pg_sleep" in payload:
        return (200, "slow-response", 3.0)
    if "information_schema" in payload:
        return (200, "Duplicate entry 'x' for key '0xdeadbeef' MySQL 8.0.32", 0.05)
    match = re.search(r"AND '([a-z0-9]+)'='([a-z0-9]+)", payload)
    if match:
        if match.group(1) == match.group(2):
            return (200, "true-body-" * 20, 0.02)
        return (200, "false", 0.02)
    return (200, "generic", 0.02)


def _flat(payload, url, method, data):
    return (200, "same-body", 0.01)


class TestSqli:
    def test_all_three_methods_confirm(self):
        result = _run(_handler(_sqli_success), "sqli", evidence={"dbms": "mysql"})
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {
            "boolean_based", "time_based", "error_based"}
        assert result.confidence == 0.99
        assert len(result.evidence) == 3

    def test_postgres_dbms_hint(self):
        result = _run(_handler(_sqli_success), "sqli", evidence={"dbms": "PostgreSQL"})
        assert "time_based" in result.methods_succeeded

    def test_post_request_branch(self):
        result = _run(_handler(_sqli_success), "sqli", evidence={"dbms": "mysql"},
                      is_post=True, data={"other": "1"})
        assert result.confirmed is True

    def test_no_method_succeeds(self):
        result = _run(_handler(_flat), "sqli")
        assert result.confirmed is False
        assert result.confidence == 0.0
        assert result.methods_tried == ["boolean_based", "time_based", "error_based"]
        assert result.methods_succeeded == []

    def test_default_evidence_is_none(self):
        result = _run(_handler(_flat), "sqli", evidence=None)
        assert result.vuln_type == "sqli"

    def test_single_success_is_not_confirmed(self):
        def handler(payload, url, method, data):
            match = re.search(r"AND '([a-z0-9]+)'='([a-z0-9]+)", payload)
            if match:
                if match.group(1) == match.group(2):
                    return (200, "true-body", 0.01)
                return (200, "false", 0.01)
            return (200, "same", 0.01)

        result = _run(_handler(handler), "sqli", evidence={"dbms": "mysql"})
        assert result.methods_succeeded == ["boolean_based"]
        assert result.confirmed is False
        assert result.confidence == pytest.approx(0.40)


# ---------------------------------------------------------------- SSRF

def _ssrf_success(payload, url, method, data):
    if "169.254.169.254" in payload:
        return (200, "ami-id: i-123 instance-id: i-abc", 0.02)
    if "127.0.0.1" in payload:
        return (200, "internal-true", 0.02)
    if "127.0.0.2" in payload:
        return (200, "internal-false", 0.02)
    return (200, "", 0.02)


class TestSsrf:
    def test_response_diff_and_blind_oob(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = _run(_handler(_ssrf_success), "ssrf")
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {"response_diff", "blind_oob"}
        assert result.confidence == 0.95

    def test_dns_callback_resolved(self):
        resolved = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 80))]
        with patch("socket.getaddrinfo", return_value=resolved):
            result = _run(_handler(_ssrf_success), "ssrf")
        assert "dns_callback" in result.methods_succeeded
        assert result.confirmed is True
        assert result.confidence == 0.99

    def test_no_signal(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = _run(_handler(_flat), "ssrf")
        assert result.confirmed is False
        assert result.confidence == 0.0

    def test_post_request_branch(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = _run(_handler(_ssrf_success), "ssrf",
                          is_post=True, data={"other": "1"})
        assert result.confirmed is True

    def test_single_success_gives_low_confidence(self):
        def handler(payload, url, method, data):
            if "169.254.169.254" in payload:
                return (200, "ami-id: i-1", 0.01)
            return (200, "same", 0.01)

        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = _run(_handler(handler), "ssrf")
        assert result.methods_succeeded == ["blind_oob"]
        assert result.confirmed is False
        assert result.confidence == 0.35


# ---------------------------------------------------------------- XSS

def _xss_success(payload, url, method, data):
    return (200, "page:%s <aimy123> tail" % payload, 0.01)


def _xss_echo(payload, url, method, data):
    return (200, "echo:%s" % payload, 0.01)


class TestXss:
    def test_all_three_methods_confirm(self):
        result = _run(_handler(_xss_success), "xss")
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {
            "reflected_marker", "html_context", "event_handler"}
        assert result.confidence == 0.95

    def test_html_context_reflection_confirms(self):
        # 修复后: 成功判定与探测载荷 "<aimy_xss_%d>" 同格式, 未转义回显即记成功.
        assert re.search(r"<aimy_xss_[0-9]+>", "<aimy_xss_123>") is not None
        result = _run(_handler(_xss_echo), "xss")
        assert set(result.methods_succeeded) == {
            "reflected_marker", "html_context", "event_handler"}
        assert result.confirmed is True

    def test_one_method_only_is_not_confirmed(self):
        def handler(payload, url, method, data):
            if payload.startswith("aimy_"):
                return (200, "reflected:%s" % payload, 0.01)
            return (200, "nothing", 0.01)
        result = _run(_handler(handler), "xss")
        assert result.methods_succeeded == ["reflected_marker"]
        assert result.confirmed is False
        assert result.confidence == 0.30

    def test_post_request_branch(self):
        result = _run(_handler(_xss_success), "xss", is_post=True, data={"other": "1"})
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {
            "reflected_marker", "html_context", "event_handler"}


# ---------------------------------------------------------------- SSTI

def _ssti_success(payload, url, method, data):
    math_match = re.search(r"(\d+)\*(\d+)", payload)
    if math_match:
        product = int(math_match.group(1)) * int(math_match.group(2))
        return (200, "result=%d" % product, 0.01)
    marker_match = re.search(r"AIMYSSTI[a-z0-9]+", payload)
    if marker_match:
        return (200, "echo " + marker_match.group(0), 0.01)
    if "popen" in payload or "Runtime" in payload:
        return (200, "uid=1000(aimy) gid=1000(aimy)", 0.01)
    return (200, "nothing", 0.01)


class TestSsti:
    def test_math_string_and_file_read_confirm(self):
        result = _run(_handler(_ssti_success), "ssti")
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {
            "math_eval", "string_output", "file_read"}
        assert result.confidence == 0.99

    def test_no_method_succeeds(self):
        result = _run(_handler(_flat), "ssti")
        assert result.confirmed is False
        assert result.confidence == 0.0

    def test_post_request_branch(self):
        result = _run(_handler(_ssti_success), "ssti", is_post=True, data={"other": "1"})
        assert result.confirmed is True

    def test_single_success_gives_low_confidence(self):
        def handler(payload, url, method, data):
            if "AIMYSSTI" in payload:
                match = re.search(r"AIMYSSTI[a-z0-9]+", payload)
                return (200, "echo " + match.group(0), 0.01)
            return (200, "same", 0.01)

        result = _run(_handler(handler), "ssti")
        assert result.methods_succeeded == ["string_output"]
        assert result.confirmed is False
        assert result.confidence == 0.30


# ---------------------------------------------------------------- CMDI

def _cmdi_success(payload, url, method, data):
    if "sleep" in payload:
        return (200, "slept", 9.0)
    if payload.startswith("echo CMDI"):
        return (200, payload[len("echo "):], 0.01)
    if payload.startswith("touch"):
        return (200, "touched", 0.01)
    if payload.startswith("cat "):
        return (200, "file-content", 0.01)
    return (200, "", 0.01)


class TestCmdi:
    def test_time_output_blind_confirm(self):
        result = _run(_handler(_cmdi_success), "cmdi")
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {
            "time_based", "output_based", "blind_file"}
        assert result.confidence == 0.99

    def test_blind_file_failure_marker(self):
        def handler(payload, url, method, data):
            if payload.startswith("cat "):
                return (200, "AIMY_BLIND_FAIL", 0.01)
            return (200, "", 0.01)
        result = _run(_handler(handler), "cmdi")
        assert result.methods_succeeded == []
        assert result.confirmed is False

    def test_post_request_branch(self):
        result = _run(_handler(_cmdi_success), "cmdi", is_post=True, data={"other": "1"})
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {
            "time_based", "output_based", "blind_file"}

    def test_single_success_gives_low_confidence(self):
        def handler(payload, url, method, data):
            if payload.startswith("echo CMDI"):
                return (200, payload[len("echo "):], 0.01)
            if payload.startswith("cat "):
                return (200, "AIMY_BLIND_FAIL", 0.01)
            return (200, "", 0.01)

        result = _run(_handler(handler), "cmdi")
        assert result.methods_succeeded == ["output_based"]
        assert result.confirmed is False
        assert result.confidence == 0.30


# ---------------------------------------------------------------- LFI

class TestLfi:
    def test_known_file_wrapper_and_log_poisoning(self):
        state = {}

        def sess_get(url, **kwargs):
            user_agent = (kwargs.get("headers") or {}).get("User-Agent")
            if user_agent:
                state["poison"] = user_agent
            return _Resp("ok")

        sess = MagicMock()
        sess.get.side_effect = sess_get

        def handler(payload, url, method, data):
            if "php://filter" in payload:
                encoded = base64.b64encode(b"root:x:0:0:root:/root:/bin/bash\n")
                return (200, encoded.decode(), 0.01)
            if "access.log" in payload:
                return (200, "log line " + state.get("poison", ""), 0.01)
            if "etc/hostname" in payload:
                return (200, "lfi-body-" * 4, 0.01)
            return (200, "", 0.01)

        result = _run(_handler(handler), "lfi", sess=sess)
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {
            "known_file", "wrapper", "log_poisoning"}
        assert result.confidence == 0.99

    def test_generic_nonempty_body_is_not_known_file(self):
        # known_file 现在带负对照: payload 响应与"不存在文件"的响应相同 (站点
        # 兜底页) 时不记成功, 修复 "任意非空 body 即 known_file" 的假阳性.
        result = _run(_handler(lambda payload, url, method, data: (200, "hello", 0.01)),
                      "lfi")
        assert "known_file" not in result.methods_succeeded

    def test_reflected_payload_is_not_known_file(self):
        # payload 原样回显说明是反射, 不是文件读取 → 不记 known_file.
        result = _run(
            _handler(lambda payload, url, method, data: (200, "echo:%s" % payload, 0.01)),
            "lfi")
        assert "known_file" not in result.methods_succeeded

    def test_single_method_gives_low_confidence(self):
        def handler(payload, url, method, data):
            if "etc/hostname" in payload and "aimy_nonexistent" not in payload:
                return (200, "some-hostname-content", 0.01)
            return (200, "", 0.01)

        result = _run(_handler(handler), "lfi")
        assert result.methods_succeeded == ["known_file"]
        assert result.confirmed is False
        assert result.confidence == 0.30

    def test_all_methods_fail(self):
        def handler(payload, url, method, data):
            return (200, "", 0.01)
        result = _run(_handler(handler), "lfi")
        assert result.methods_succeeded == []
        assert result.confirmed is False

    def test_post_wrapper_non_base64_and_log_poisoning(self):
        state = {}

        def sess_get(url, **kwargs):
            user_agent = (kwargs.get("headers") or {}).get("User-Agent")
            if user_agent:
                state["poison"] = user_agent
            return _Resp("ok")

        sess = MagicMock()
        sess.get.side_effect = sess_get

        def handler(payload, url, method, data):
            if "php://filter" in payload:
                return (200, "not-valid-base64!!", 0.01)
            if payload == "php://input":
                return (200, "PATH=/usr/local/bin:/usr/bin", 0.01)
            if "access.log" in payload:
                return (200, "log " + state.get("poison", ""), 0.01)
            return (200, "", 0.01)

        result = _run(_handler(handler), "lfi", sess=sess,
                      is_post=True, data={"other": "1"})
        assert "wrapper" in result.methods_succeeded
        assert "log_poisoning" in result.methods_succeeded


# ---------------------------------------------------------------- NoSQLi

def _nosqli_success(payload, url, method, data):
    if "$ne" in payload or "$gt" in payload or "$regex" in payload:
        return (200, "operator-result-body", 0.02)
    if "$where" in payload:
        return (200, "true-body-aaaa" if "true" in payload else "false-body-b", 0.02)
    if payload == "true":
        return (200, "true-body-aaaa", 0.02)
    if payload == "false":
        return (200, "false-body-b", 0.02)
    return (200, "", 0.02)


class TestNosqli:
    def test_get_operator_and_boolean_confirm(self):
        result = _run(_handler(_nosqli_success), "nosqli")
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {"operator_injection", "boolean_based"}
        assert result.confidence == pytest.approx(0.90)

    def test_post_operator_and_boolean_confirm(self):
        result = _run(_handler(_nosqli_success), "nosqli",
                      is_post=True, data={"other": "1"})
        assert result.confirmed is True

    def test_no_signal(self):
        result = _run(_handler(_flat), "nosqli")
        assert result.confirmed is False

    def test_single_success_gives_low_confidence(self):
        def handler(payload, url, method, data):
            if "$ne" in payload:
                return (200, "operator-result-body", 0.02)
            return (200, "same-body", 0.02)

        result = _run(_handler(handler), "nosqli")
        assert result.methods_succeeded == ["operator_injection"]
        assert result.confirmed is False
        assert result.confidence == 0.30


# ---------------------------------------------------------------- XXE

def _xxe_success(payload, url, method, data):
    if "etc/passwd" in payload:
        return (200, "root:x:0:0:root:/root:/bin/bash", 0.02)
    if "nonexistent_aimy_file" in payload:
        return (200, "XML parse exception: entity not found", 0.02)
    return (200, "", 0.02)


class TestXxe:
    def test_file_read_and_error_confirm(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = _run(_handler(_xxe_success), "xxe")
        assert result.confirmed is True
        assert set(result.methods_succeeded) == {"file_read", "error_based"}
        assert result.confidence == pytest.approx(0.90)

    def test_oob_resolved(self):
        resolved = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 80))]
        with patch("socket.getaddrinfo", return_value=resolved):
            result = _run(_handler(_xxe_success), "xxe")
        assert "oob" in result.methods_succeeded
        assert result.confirmed is True

    def test_single_success_gives_low_confidence(self):
        def handler(payload, url, method, data):
            if "etc/passwd" in payload:
                return (200, "root:x:0:0:root:/root:/bin/bash", 0.02)
            return (200, "", 0.02)

        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = _run(_handler(handler), "xxe")
        assert result.methods_succeeded == ["file_read"]
        assert result.confirmed is False
        assert result.confidence == 0.30


# ---------------------------------------------------------------- dispatch / helpers

class TestDispatchAndHelpers:
    def test_unsupported_vuln_type(self):
        verifier = SecondOrderVerifier(sess=MagicMock())
        result = verifier.verify("http://t.local/page", "p", "not-a-type")
        assert result.confirmed is False
        assert result.methods_tried == ["unsupported"]
        assert "No verifier" in result.details["error"]

    def test_all_verifiers_survive_request_exceptions(self):
        def boom(*args, **kwargs):
            raise RuntimeError("offline")

        for vuln_type in ("sqli", "ssrf", "xss", "ssti", "cmdi", "lfi", "nosqli", "xxe"):
            with patch.object(SecondOrderVerifier, "_make_request",
                              MagicMock(side_effect=boom)), \
                    patch("tools.second_order_verifier.time", MagicMock()):
                result = SecondOrderVerifier(sess=MagicMock(), timeout=5.0).verify(
                    "http://t.local/page", "p", vuln_type, {})
            assert result.confirmed is False
            assert result.methods_succeeded == []

    def test_make_request_get_success(self):
        fake_time = MagicMock()
        fake_time.time.side_effect = [10.0, 10.25]
        sess = MagicMock()
        sess.get.return_value = _Resp("hello", 200)
        with patch("tools.second_order_verifier.time", fake_time):
            verb = SecondOrderVerifier(sess=sess, timeout=5.0)
            status, body, elapsed = verb._make_request("http://t.local/page")
        assert (status, body, elapsed) == (200, "hello", 0.25)
        sess.get.assert_called_once()

    def test_make_request_post_success(self):
        fake_time = MagicMock()
        fake_time.time.side_effect = [1.0, 1.5]
        sess = MagicMock()
        sess.post.return_value = _Resp("created", 201)
        with patch("tools.second_order_verifier.time", fake_time):
            verb = SecondOrderVerifier(sess=sess, timeout=5.0)
            status, body, elapsed = verb._make_request(
                "http://t.local/page", method="POST", data={"a": 1})
        assert (status, body) == (201, "created")
        assert elapsed == 0.5
        sess.post.assert_called_once()

    def test_make_request_error(self):
        sess = MagicMock()
        sess.get.side_effect = RuntimeError("boom")
        with patch("tools.second_order_verifier.time", MagicMock()):
            verb = SecondOrderVerifier(sess=sess, timeout=5.0)
            assert verb._make_request("http://t.local/page") == (None, "", 0.0)

    def test_inject_helpers(self):
        verb = SecondOrderVerifier(sess=MagicMock())
        injected = verb._inject_param("http://t.local/page?a=1&b=2", "p", "PAYLOAD")
        query = parse_qs(urlparse(injected).query)
        assert query["p"] == ["PAYLOAD"]
        assert query["a"] == ["1"]
        assert verb._inject_body(None, "p", "v") == {"p": "v"}
        assert verb._inject_body({"x": "y"}, "p", "v") == {"x": "y", "p": "v"}
        assert verb._inject_header(None, "tok") == {"X-Verify-Token": "tok"}
        assert verb._inject_header({"A": "B"}, "tok") == {"A": "B", "X-Verify-Token": "tok"}

    def test_random_suffix(self):
        suffix = SecondOrderVerifier(sess=MagicMock())._random_suffix(10)
        assert len(suffix) == 10
        assert re.fullmatch(r"[a-z0-9]{10}", suffix)

    def test_result_to_dict_rounds_confidence(self):
        result = VerificationResult(vuln_type="sqli", confirmed=True, confidence=0.123456789)
        data = result.to_dict()
        assert data["confidence"] == 0.1235
        assert data["vuln_type"] == "sqli"

    def test_check_helper(self):
        with patch.object(SecondOrderVerifier, "_make_request",
                          MagicMock(side_effect=_handler(_xss_success))), \
                patch("tools.second_order_verifier.time", MagicMock()):
            data = check("http://t.local/page", "p", "xss", sess=MagicMock(), timeout=5.0)
        assert data["confirmed"] is True
        assert data["vuln_type"] == "xss"

    def test_default_http_client_constructed(self):
        verb = SecondOrderVerifier()
        assert verb.sess is not None
