"""Offline coverage tests for tools/robust_verifier.py and tools/verification_oracle.py.

All HTTP is mocked, time.time/time.sleep are patched, and no DNS/network is used.
"""
import itertools
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, unquote, urlparse

import pytest
import requests

from tools.response_profiler import AnomalyReport, BaselineProfile
from tools.robust_verifier import (
    _get_baseline_response,
    _lfi_encode_path,
    _measure_baseline_ms,
    _probe_ssrf,
    verify_finding,
    verify_lfi_content,
    verify_sqli_boolean,
    verify_sqli_timeblind,
    verify_ssrf_oob,
)
from tools.verification_oracle import (
    ConfidenceLevel,
    ConfidenceVoter,
    VerificationOracle,
)


class _Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


def _fake_time(value=100.0):
    fake = MagicMock()
    fake.time.return_value = value
    return fake


def _response_param(url):
    return parse_qs(urlparse(url).query)


# ============================ robust_verifier ============================

class TestTimeBlind:
    def test_baseline_unavailable_returns_default(self):
        sess = MagicMock()
        sess.get.side_effect = requests.RequestException("down")
        result = verify_sqli_timeblind("http://t.local/page", "id", sess, timeout=15.0)
        assert result == {"vulnerable": False, "method": "time_blind",
                          "confidence": 0.0, "evidence": []}
        sess.get.assert_called()

    def test_baseline_too_slow_aborts(self):
        sess = MagicMock()
        with patch("tools.robust_verifier._measure_baseline_ms", return_value=20000.0):
            result = verify_sqli_timeblind("http://t.local/page", "id", sess, timeout=15.0)
        assert result["vulnerable"] is False
        assert result["evidence"] == []
        sess.get.assert_not_called()

    def test_confirmed_via_repeated_timeouts(self):
        sess = MagicMock()
        sess.get.side_effect = requests.Timeout("slow")
        with patch("tools.robust_verifier._measure_baseline_ms", return_value=100.0):
            result = verify_sqli_timeblind("http://t.local/page", "id", sess, timeout=15.0)
        assert result["vulnerable"] is True
        assert result["confidence"] == pytest.approx(0.95)
        assert result["dbms"] == "mysql"
        assert len(result["evidence"]) == 3
        assert {e["type"] for e in result["evidence"]} == {"timeout"}

    def test_confirmed_via_delay(self):
        sess = MagicMock()
        sess.get.return_value = _Resp("ok")
        fake = _fake_time()
        fake.time.side_effect = itertools.cycle([0.0, 5.0])
        with patch("tools.robust_verifier._measure_baseline_ms", return_value=100.0), \
                patch("tools.robust_verifier.time", fake):
            result = verify_sqli_timeblind("http://t.local/page", "id", sess, timeout=15.0)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.4
        assert result["dbms"] == "mysql"
        assert result["evidence"][0]["type"] == "time_delay"
        assert result["evidence"][0]["elapsed_ms"] == 5000.0

    def test_single_timeout_then_generic_errors(self):
        calls = {"n": 0}

        def get(url, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.Timeout("slow")
            raise requests.RequestException("nope")

        sess = MagicMock()
        sess.get.side_effect = get
        with patch("tools.robust_verifier._measure_baseline_ms", return_value=100.0):
            result = verify_sqli_timeblind("http://t.local/page", "id", sess, timeout=15.0)
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.4
        assert result["evidence"] == [
            {"type": "timeout", "dbms": "mysql", "payload": "' OR SLEEP(3)--"}]


class TestBoolean:
    def test_confirmed_pairs(self):
        def get(url, timeout=None):
            text = unquote(url)
            if "1=1" in text:
                return _Resp("T" * 300)
            if "1=2" in text:
                return _Resp("F" * 100)
            return _Resp("N" * 150)

        sess = MagicMock()
        sess.get.side_effect = get
        result = verify_sqli_boolean("http://t.local/page", "id", sess, timeout=5.0)
        assert result["vulnerable"] is True
        assert result["confidence"] == pytest.approx(0.7)
        assert len(result["evidence"]) == 2

    def test_no_differential(self):
        sess = MagicMock()
        sess.get.return_value = _Resp("X" * 100)
        result = verify_sqli_boolean("http://t.local/page", "id", sess, timeout=5.0)
        assert result["vulnerable"] is False
        assert result["confidence"] == 0.0
        assert result["evidence"] == []

    def test_baseline_unavailable(self):
        sess = MagicMock()
        sess.get.side_effect = requests.RequestException("down")
        result = verify_sqli_boolean("http://t.local/page", "id", sess, timeout=5.0)
        assert result["vulnerable"] is False

    def test_errors_after_baseline_are_swallowed(self):
        sess = MagicMock()
        sess.get.side_effect = [_Resp("X" * 100)] + [requests.RequestException("x")] * 12
        result = verify_sqli_boolean("http://t.local/page", "id", sess, timeout=5.0)
        assert result["vulnerable"] is False
        assert result["evidence"] == []

    def test_single_pair_confirmed_low_confidence(self):
        calls = {"n": 0}

        def single(url, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return _Resp("N" * 150)  # baseline
            if calls["n"] == 2:
                return _Resp("T" * 300)
            if calls["n"] == 3:
                return _Resp("F" * 100)
            return _Resp("N" * 150)

        sess = MagicMock()
        sess.get.side_effect = single
        result = verify_sqli_boolean("http://t.local/page", "id", sess, timeout=5.0)
        assert len(result["evidence"]) == 1
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.35


def _oob_mock(callbacks=()):
    oob = MagicMock()
    oob.register.return_value = "cb1"
    oob.get_callback_url.return_value = "http://10.0.0.1:9000/cb/cb1"
    oob.get_callback_domain.return_value = "cb1.oob"
    oob.pop_callbacks.return_value = list(callbacks)
    return oob


class TestSsrfOob:
    def test_callback_confirmed(self):
        sess = MagicMock()
        sess.get.return_value = _Resp("P" * 500)
        with patch("tools.robust_verifier.time", _fake_time()):
            result = verify_ssrf_oob("http://t.local/fetch", "url", sess, 5.0,
                                     oob_server=_oob_mock(callbacks=[{"x": 1}]))
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.95
        assert result["method"] == "oob_confirmed"
        assert result["evidence"][0]["type"] == "oob_callback"

    def test_offline_differential_suspected(self):
        def get(url, timeout=None):
            if "192.0.2.1" in url:
                return _Resp("C" * 100)
            return _Resp("P" * 500)

        sess = MagicMock()
        sess.get.side_effect = get
        with patch("tools.robust_verifier.time", _fake_time()):
            result = verify_ssrf_oob("http://t.local/fetch", "url", sess, 5.0,
                                     oob_server=_oob_mock(callbacks=[]))
        assert result["vulnerable"] is True
        assert result["confidence"] == 0.4
        assert result["method"] == "offline_differential"
        assert "suspected" in result["note"]

    def test_no_callback_inconclusive(self):
        sess = MagicMock()
        sess.get.return_value = _Resp("P" * 500)
        with patch("tools.robust_verifier.time", _fake_time()):
            result = verify_ssrf_oob("http://t.local/fetch", "url", sess, 5.0,
                                     oob_server=_oob_mock(callbacks=[]))
        assert result["vulnerable"] is False
        assert result["confidence"] == 0.0
        assert "inconclusive" in result["note"]

    def test_register_failure_skips_callback_id(self):
        oob = _oob_mock()
        oob.register.side_effect = RuntimeError("listener down")
        sess = MagicMock()
        sess.get.return_value = _Resp("P" * 10)
        with patch("tools.robust_verifier.time", _fake_time()):
            result = verify_ssrf_oob("http://t.local/fetch", "url", sess, 5.0,
                                     oob_server=oob)
        assert result["vulnerable"] is False
        oob.get_callback_url.assert_not_called()
        oob.pop_callbacks.assert_not_called()

    def test_oob_server_import_failure(self):
        sess = MagicMock()
        sess.get.return_value = _Resp("P" * 10)
        with patch("tools.oob_server.OOBServer.get_instance",
                   side_effect=RuntimeError("offline")), \
                patch("tools.robust_verifier.time", _fake_time()):
            result = verify_ssrf_oob("http://t.local/fetch", "url", sess, 5.0,
                                     oob_server=None)
        assert result["vulnerable"] is False
        assert result["offline_oob"]["status"] == "inconclusive"


class TestProbeSsrf:
    def test_none_target_returns_default_sample(self):
        sess = MagicMock()
        sample = _probe_ssrf("http://t.local/fetch", "url", None, sess, 5.0)
        assert sample == {"responded": False, "status": 0, "length": 0, "elapsed_ms": 0}
        sess.get.assert_not_called()

    def test_response_sample_records_status_length_elapsed(self):
        fake = _fake_time()
        fake.time.side_effect = [50.0, 50.4]
        sess = MagicMock()
        sess.get.return_value = _Resp("body!", 201)
        with patch("tools.robust_verifier.time", fake):
            sample = _probe_ssrf("http://t.local/fetch", "url",
                                 "http://127.0.0.1/", sess, 5.0)
        assert sample["responded"] is True
        assert sample["status"] == 201
        assert sample["length"] == 5
        assert sample["elapsed_ms"] == 400.0

    def test_error_sample(self):
        sess = MagicMock()
        sess.get.side_effect = requests.RequestException("x")
        with patch("tools.robust_verifier.time", _fake_time()):
            sample = _probe_ssrf("http://t.local/fetch", "url",
                                 "http://127.0.0.1/", sess, 5.0)
        assert sample["responded"] is False
        assert sample["status"] == 0


class TestLfiContent:
    def test_two_signatures_confirm(self):
        sess = MagicMock()
        sess.get.side_effect = [_Resp("root:x:0:0:root:/root:/bin/sh extra-padding")] \
            + [_Resp("tiny")] * 20
        result = verify_lfi_content("http://t.local/view", "file", sess, 5.0)
        assert result["vulnerable"] is True
        assert result["confidence"] == pytest.approx(0.95)
        assert len(result["evidence"]) == 2

    def test_single_signature_confirms_with_pattern_weight(self):
        sess = MagicMock()
        sess.get.side_effect = [_Resp("root:x:0:0:root:/root:/bin/zsh")] \
            + [_Resp("tiny")] * 20
        result = verify_lfi_content("http://t.local/view", "file", sess, 5.0)
        assert result["vulnerable"] is True
        assert result["confidence"] == pytest.approx(0.9)

    def test_status_and_length_filters(self):
        sess = MagicMock()
        sess.get.return_value = _Resp("root:x:0:0:root:/root:/bin/bash", 404)
        assert verify_lfi_content("http://t.local/view", "file", sess, 5.0)["vulnerable"] is False

        sess2 = MagicMock()
        sess2.get.return_value = _Resp("root:", 200)
        assert verify_lfi_content("http://t.local/view", "file", sess2, 5.0)["vulnerable"] is False

    def test_request_errors_are_swallowed(self):
        sess = MagicMock()
        sess.get.side_effect = requests.RequestException("x")
        result = verify_lfi_content("http://t.local/view", "file", sess, 5.0)
        assert result["vulnerable"] is False
        assert result["evidence"] == []

    def test_three_signatures_break_early(self):
        body = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534"
        sess = MagicMock()
        sess.get.return_value = _Resp(body)
        result = verify_lfi_content("http://t.local/view", "file", sess, 5.0)
        assert result["vulnerable"] is True
        assert len(result["evidence"]) == 3
        assert sess.get.call_count == 1


class TestRobustHelpers:
    def test_measure_baseline_none_when_all_fail(self):
        sess = MagicMock()
        sess.get.side_effect = requests.RequestException("x")
        assert _measure_baseline_ms("http://t/", "id", sess, 5.0) is None

    def test_measure_baseline_median_of_three(self):
        fake = _fake_time()
        fake.time.side_effect = itertools.cycle([0.0, 0.1])
        sess = MagicMock()
        sess.get.return_value = _Resp()
        with patch("tools.robust_verifier.time", fake):
            value = _measure_baseline_ms("http://t/", "id", sess, 5.0)
        assert value == pytest.approx(100.0)

    def test_measure_baseline_mean_when_fewer_samples(self):
        calls = {"n": 0}

        def get(url, timeout=None):
            calls["n"] += 1
            if calls["n"] == 2:
                raise requests.RequestException("x")
            return _Resp()

        sess = MagicMock()
        sess.get.side_effect = get
        fake = _fake_time()
        fake.time.side_effect = [0.0, 0.2, 0.0, 0.0, 0.4]
        with patch("tools.robust_verifier.time", fake):
            value = _measure_baseline_ms("http://t/", "id", sess, 5.0)
        assert value == pytest.approx(300.0)

    def test_get_baseline_response_error(self):
        sess = MagicMock()
        sess.get.side_effect = requests.RequestException("x")
        assert _get_baseline_response("http://t/", "id", sess, 5.0) is None

    def test_lfi_encode_path_variants(self):
        # 修复后返回全部变体 (原样优先, 附编码/包装器绕过), 供调用方逐个探测.
        variants = _lfi_encode_path("/etc/passwd")
        assert variants[0] == "/etc/passwd"
        assert "%2fetc%2fpasswd" in variants
        assert "....//....//....//...." + "/etc/passwd" in variants
        assert any(v.startswith("php://filter/") for v in variants)
        plain = _lfi_encode_path("c:/windows/win.ini")
        assert plain[0] == "c:/windows/win.ini"


class TestVerifyFinding:
    def test_sqli_combines_subchecks(self):
        time_blind = {"vulnerable": True, "confidence": 0.8, "dbms": "mysql",
                      "evidence": [{"type": "time_delay"}]}
        boolean = {"vulnerable": False, "confidence": 0.0, "evidence": []}
        with patch("tools.robust_verifier.verify_sqli_timeblind",
                   return_value=time_blind), \
                patch("tools.robust_verifier.verify_sqli_boolean",
                      return_value=boolean):
            result = verify_finding("sqli", "http://t.local/page", "id", MagicMock(), 5.0)
        assert result["vulnerable"] is True
        assert result["method"] == "combined"
        assert result["dbms"] == "mysql"
        assert result["confidence"] == 0.8
        assert result["sub_checks"]["time_blind"]["vulnerable"] is True

    def test_dispatch_ssrf_and_lfi(self):
        with patch("tools.robust_verifier.verify_ssrf_oob",
                   return_value={"vulnerable": False}) as ssrf, \
                patch("tools.robust_verifier.verify_lfi_content",
                      return_value={"vulnerable": False}) as lfi:
            assert verify_finding("ssrf", "http://t/", "url", MagicMock(), 5.0)[
                "vulnerable"] is False
            assert verify_finding("lfi", "http://t/", "f", MagicMock(), 5.0)[
                "vulnerable"] is False
            ssrf.assert_called_once()
            lfi.assert_called_once()

    def test_unknown_type(self):
        result = verify_finding("deser", "http://t/", "p", MagicMock(), 5.0)
        assert result == {"vulnerable": False, "confidence": 0.0, "method": "unknown"}


# ============================ verification_oracle ============================

def _oracle(analyze=None):
    profiler = MagicMock()
    profiler.profile_endpoint.return_value = BaselineProfile(
        status=200, length=100, body_hash="baseline-hash", elapsed=0.1)
    profiler.analyze.side_effect = analyze or (
        lambda *args, **kwargs: AnomalyReport(is_anomalous=False))
    return VerificationOracle(response_profiler=profiler), profiler


def _fake_generate(group, key, context="all", waf_name=None, max_payloads=50):
    if key == "time_mysql" or key == "time":
        return [{"payload": "PAY_TIME_%d" % i} for i in range(3)]
    return []


class TestVoterLevel:
    def test_level_property(self):
        voter = ConfidenceVoter()
        voter.add_vote("x", 0.9, family="f")
        assert voter.level == ConfidenceLevel.CONFIRMED

    def test_level_low_for_empty(self):
        assert ConfidenceVoter().level == ConfidenceLevel.LOW


class TestVoterStatics:
    def test_vote_status_code_branches(self):
        assert ConfidenceVoter.vote_status_code(_Resp(status_code=200), 200) == 0.0
        assert ConfidenceVoter.vote_status_code(_Resp(status_code=500), 200) == 0.5
        assert ConfidenceVoter.vote_status_code(_Resp(status_code=502), 200) == 0.5
        assert ConfidenceVoter.vote_status_code(_Resp(status_code=503), 200) == 0.5
        assert ConfidenceVoter.vote_status_code(_Resp(status_code=201), 200) == 0.3
        assert ConfidenceVoter.vote_status_code(_Resp(status_code=404), 200) == 0.3

    def test_vote_length_diff_branches(self):
        assert ConfidenceVoter.vote_length_diff(300, 100) == 0.7
        assert ConfidenceVoter.vote_length_diff(110, 100) == 0.5
        assert ConfidenceVoter.vote_length_diff(104, 100) == 0.3
        assert ConfidenceVoter.vote_length_diff(101, 100) == 0.0
        assert ConfidenceVoter.vote_length_diff(100, 0) == 0.0

    def test_vote_body_hash_branches(self):
        assert ConfidenceVoter.vote_body_hash("a", "b") == 0.6
        assert ConfidenceVoter.vote_body_hash("a", "a") == 0.0

    def test_vote_time_elapsed_branches(self):
        assert ConfidenceVoter.vote_time_elapsed(1.0, 0.5, 5.0) == 0.0
        assert ConfidenceVoter.vote_time_elapsed(10.0, 1.0, 5.0) == 0.9

    def test_vote_evidence_keywords_branches(self):
        assert ConfidenceVoter.vote_evidence_keywords("a b c", ["a", "b", "c"]) == 0.9
        assert ConfidenceVoter.vote_evidence_keywords("a z", ["a", "b", "c"]) == 0.5
        assert ConfidenceVoter.vote_evidence_keywords("z", ["a", "b"]) == 0.0

    def test_vote_oob_callback_branches(self):
        assert ConfidenceVoter.vote_oob_callback(True) == 0.95
        assert ConfidenceVoter.vote_oob_callback(False) == 0.0

    def test_vote_multiple_payloads_branches(self):
        assert ConfidenceVoter.vote_multiple_payloads(0, 0) == 0.0
        assert ConfidenceVoter.vote_multiple_payloads(5, 10) == 0.8
        assert ConfidenceVoter.vote_multiple_payloads(3, 10) == 0.5
        assert ConfidenceVoter.vote_multiple_payloads(1, 10) == 0.2


class TestOracleDispatch:
    def test_not_vulnerable_finding_short_circuits(self):
        oracle, profiler = _oracle()
        finding = {"vulnerable": False, "type": "sqli"}
        result = oracle.verify("sqli", finding, "http://t/", "id", MagicMock(), timeout=5.0)
        assert result["confidence_votes"] == []
        assert result["confidence_score"] == 0.0

    def test_unknown_detector_returns_finding(self):
        oracle, profiler = _oracle()
        finding = {"vulnerable": True, "type": "unknown"}
        result = oracle.verify("unknown_kind", finding, "http://t/", "id",
                               MagicMock(), timeout=5.0)
        assert result is finding
        assert "confidence_score" not in result

    def test_ssrf_disclosure_vote(self):
        oracle, profiler = _oracle()
        result = oracle.verify("ssrf", {"vulnerable": True, "type": "disclosure"},
                               "http://t/", "url", MagicMock(), timeout=5.0)
        assert result["confidence_score"] == 0.6
        assert "disclosure:0.60" in result["confidence_votes"]
        assert result["verified"] is False

    def test_ssrf_oob_http_callback_vote(self):
        oracle, profiler = _oracle()
        result = oracle.verify("ssrf", {"vulnerable": True, "type": "oob_http_callback"},
                               "http://t/", "url", MagicMock(), timeout=5.0)
        assert result["confidence"] == "confirmed"
        assert "oob_callback:0.95" in result["confidence_votes"]
        assert result["verified"] is True


class TestOracleSqli:
    def test_timeout_and_boolean_evidence(self):
        oracle, profiler = _oracle(
            analyze=lambda url, param, resp, method="GET": AnomalyReport(
                is_anomalous=resp.text.startswith("T")))
        profiler.profile_endpoint.return_value.elapsed = 0.1

        def get(url, timeout=None):
            if "PAY_TIME" in url:
                raise requests.Timeout("slow")
            if "TRUE" in url:
                return _Resp("T" * 300)
            return _Resp("F" * 100)

        sess = MagicMock()
        sess.get.side_effect = get
        pairs = [("TRUE1", "FALSE1"), ("TRUE2", "FALSE2")]
        with patch("tools.payload_engine.generate",
                   side_effect=lambda *a, **k: [{"payload": "PAY_TIME_%d" % i}
                                                for i in range(3)]), \
                patch("tools.payload_engine.generate_sqli_boolean", return_value=pairs):
            result = oracle.verify("sqli", {"vulnerable": True, "type": "sqli"},
                                   "http://t.local/page?id=1", "id", sess, timeout=10.0)
        assert result["verified"] is True
        assert result["confidence"] == "confirmed"
        assert result["confidence_score"] == 0.96
        assert result["reproduction"] == {
            "samples_required": 3, "observed": 4, "reproduced": True}
        assert "time_confirmed:0.85" in result["confidence_votes"]
        assert result["cvss_vector"] == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert result["cvss_score"] > 0

    def test_elapsed_delay_path(self):
        oracle, profiler = _oracle()
        sess = MagicMock()
        sess.get.return_value = _Resp("x" * 120)
        fake = _fake_time()
        fake.time.side_effect = itertools.cycle([0.0, 10.0])
        with patch("tools.payload_engine.generate",
                   side_effect=lambda *a, **k: [{"payload": "PAY_TIME_%d" % i}
                                                for i in range(3)]), \
                patch("tools.payload_engine.generate_sqli_boolean",
                      return_value=[("TRUE1", "FALSE1")]), \
                patch("tools.verification_oracle.time", fake):
            result = oracle.verify("sqli", {"vulnerable": True, "type": "sqli"},
                                   "http://t.local/page?id=1", "id", sess, timeout=10.0)
        assert "time_delay:0.90" in result["confidence_votes"]
        assert result["verified"] is True
        assert result["confidence_score"] == 0.96

    def test_zero_baseline_uses_measured_fallback(self):
        oracle, profiler = _oracle()
        profiler.profile_endpoint.return_value.elapsed = 0.0
        sess = MagicMock()
        sess.get.return_value = _Resp("z" * 100)
        fake = _fake_time()
        fake.time.side_effect = itertools.cycle([0.0, 0.05])
        with patch("tools.payload_engine.generate", return_value=[]), \
                patch("tools.payload_engine.generate_sqli_boolean", return_value=[]), \
                patch("tools.verification_oracle.time", fake):
            result = oracle.verify("sqli", {"vulnerable": True, "type": "sqli"},
                                   "http://t.local/page?id=1", "id", sess, timeout=10.0)
        assert result["confidence"] == "low"
        assert result["confidence_score"] == 0.0
        assert result["verified"] is False
        assert result["confidence_votes"] == []

    def test_slow_baseline_skips_time_probes(self):
        oracle, profiler = _oracle()
        profiler.profile_endpoint.return_value.elapsed = 9.0
        sess = MagicMock()
        sess.get.return_value = _Resp("z" * 100)
        with patch("tools.payload_engine.generate") as gen, \
                patch("tools.payload_engine.generate_sqli_boolean", return_value=[]):
            result = oracle.verify("sqli", {"vulnerable": True, "type": "sqli"},
                                   "http://t.local/page?id=1", "id", sess, timeout=10.0)
        gen.assert_not_called()
        assert result["confidence_score"] == 0.0

    def test_missing_baseline_returns_finding_untouched(self):
        oracle, profiler = _oracle()
        profiler.profile_endpoint.return_value = None
        finding = {"vulnerable": True, "type": "sqli"}
        result = oracle.verify("sqli", finding, "http://t.local/page?id=1", "id",
                               MagicMock(), timeout=10.0)
        assert "confidence_score" not in result

    def test_generic_exceptions_are_skipped(self):
        oracle, profiler = _oracle()

        def get(url, timeout=None):
            if "PAY_TIME" in url:
                raise ValueError("broken")
            if "TRUE" in url:
                return _Resp("T" * 300)
            raise ValueError("broken")

        sess = MagicMock()
        sess.get.side_effect = get
        with patch("tools.payload_engine.generate",
                   return_value=[{"payload": "PAY_TIME_0"}]), \
                patch("tools.payload_engine.generate_sqli_boolean",
                      return_value=[("TRUE1", "FALSE1")]):
            result = oracle.verify("sqli", {"vulnerable": True, "type": "sqli"},
                                   "http://t.local/page?id=1", "id", sess, timeout=10.0)
        assert result["confidence_score"] == 0.0
        assert result["confidence_votes"] == []


class TestOracleCmdi:
    def test_multiple_evidence_capped_by_reproduction(self):
        oracle, profiler = _oracle()

        def get(url, timeout=None):
            text = unquote(url)
            if "nominal_healthcheck" in text:
                raise requests.RequestException("no baseline")
            if "PAY_CMDI_TIME" in text:
                raise requests.Timeout("slow")
            return _Resp("uid=0(root) gid=0")

        sess = MagicMock()
        sess.get.side_effect = get
        seeds = {
            "time": [{"payload": "PAY_CMDI_TIME"}],
            "output": [{"payload": "PAY_CMDI_OUT", "indicator": "uid="},
                       {"payload": "PAY_CMDI_NO_INDICATOR"}],
        }
        with patch("tools.payload_engine.generate",
                   side_effect=lambda group, key, *a, **k: seeds.get(key, [])):
            result = oracle.verify("cmdi", {"vulnerable": True, "type": "cmdi"},
                                   "http://t.local/run", "cmd", sess, timeout=5.0)
        assert result["confidence_score"] == 0.55
        assert result["verified"] is False
        assert result["reproduction"]["observed"] == 2
        assert "timeout:0.70" in result["confidence_votes"]
        assert "multi_confirmed:0.80" in result["confidence_votes"]

    def test_elapsed_delay_and_output_exceptions(self):
        oracle, profiler = _oracle()

        def get(url, timeout=None):
            text = unquote(url)
            if "PAY_CMDI_TIME_ERR" in text:
                raise ValueError("boom")
            if "PAY_CMDI_TIME_OK" in text:
                return _Resp("ok")
            if "PAY_CMDI_OUT_ERR" in text:
                raise ValueError("boom")
            return _Resp("no indicator here")

        sess = MagicMock()
        sess.get.side_effect = get
        seeds = {
            "time": [{"payload": "PAY_CMDI_TIME_ERR"}, {"payload": "PAY_CMDI_TIME_OK"}],
            "output": [{"payload": "PAY_CMDI_OUT_ERR", "indicator": "uid="},
                       {"payload": "PAY_CMDI_OUT_NONE", "indicator": "uid="}],
        }
        fake = _fake_time()
        fake.time.side_effect = itertools.count(0.0, 5.0)
        with patch.object(VerificationOracle, "_measure_baseline", return_value=0.3), \
                patch("tools.payload_engine.generate",
                      side_effect=lambda group, key, *a, **k: seeds.get(key, [])), \
                patch("tools.verification_oracle.time", fake):
            result = oracle.verify("cmdi", {"vulnerable": True, "type": "cmdi"},
                                   "http://t.local/run", "cmd", sess, timeout=5.0)
        assert "time_delay:0.90" in result["confidence_votes"]
        assert result["reproduction"]["observed"] == 1
        assert result["confidence_score"] == 0.55


class TestOracleXss:
    def test_reflected_unescaped_payload(self):
        oracle, profiler = _oracle()
        payload = "<script>alert(1)</script>"

        def get(url, timeout=None):
            values = _response_param(url).get("q", [""])
            return _Resp("<div>%s</div>" % values[0])

        sess = MagicMock()
        sess.get.side_effect = get
        with patch("tools.html_context_parser.probe_and_detect", return_value="html"), \
                patch("tools.payload_engine.generate",
                      return_value=[{"payload": payload}]):
            result = oracle.verify("xss", {"vulnerable": True, "type": "xss"},
                                   "http://t.local/search", "q", sess, timeout=5.0)
        assert result["verified"] is True
        assert result["confidence"] == "confirmed"
        assert "trigger_fired:0.85" in result["confidence_votes"]
        assert result["reproduction"] == {
            "samples_required": 1, "observed": 1, "reproduced": True}

    def test_not_reflected_falls_back_to_all_contexts(self):
        oracle, profiler = _oracle()
        contexts = []

        def fake_generate(group, key, context="all", waf_name=None, max_payloads=50):
            contexts.append(key)
            return [{"payload": "probe_%s" % key}]

        sess = MagicMock()
        sess.get.return_value = _Resp("<p>nothing here</p>")
        with patch("tools.html_context_parser.probe_and_detect",
                   return_value="not_reflected"), \
                patch("tools.payload_engine.generate", side_effect=fake_generate):
            result = oracle.verify("xss", {"vulnerable": True, "type": "xss"},
                                   "http://t.local/search", "q", sess, timeout=5.0)
        assert contexts == ["html", "attr", "js"]
        assert result["confidence"] == "low"
        assert result["verified"] is False
        assert "context_not_reflected:0.10" in result["confidence_votes"]

    def test_post_body_reflection(self):
        oracle, profiler = _oracle()

        def post(url, **kwargs):
            data = kwargs.get("data") or {}
            return _Resp("<i>%s</i>" % data.get("q", ""))

        sess = MagicMock()
        sess.post.side_effect = post
        with patch("tools.html_context_parser.probe_and_detect", return_value="html"), \
                patch("tools.payload_engine.generate",
                      return_value=[{"payload": "<img src=x onerror=alert(1)>"}]):
            result = oracle.verify("xss", {"vulnerable": True, "type": "xss"},
                                   "http://t.local/search", "q", sess, timeout=5.0,
                                   post_body=True, post_data={"q": "1"})
        assert result["verified"] is True
        assert sess.post.called

    def test_escaped_reflection_is_not_confirmed(self):
        oracle, profiler = _oracle()
        payload = "<script>alert(1)</script>"

        def get(url, timeout=None):
            marker = _response_param(url).get("q", [""])[0]
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            return _Resp("<div>%s%s</div>" % (marker[:len(marker) - len(payload)],
                                              escaped))

        sess = MagicMock()
        sess.get.side_effect = get
        with patch("tools.html_context_parser.probe_and_detect", return_value="html"), \
                patch("tools.payload_engine.generate",
                      return_value=[{"payload": payload}]):
            result = oracle.verify("xss", {"vulnerable": True, "type": "xss"},
                                   "http://t.local/search", "q", sess, timeout=5.0)
        assert result["verified"] is False

    def test_request_exception_is_skipped(self):
        oracle, profiler = _oracle()
        sess = MagicMock()
        sess.get.side_effect = ValueError("boom")
        with patch("tools.html_context_parser.probe_and_detect", return_value="html"), \
                patch("tools.payload_engine.generate",
                      return_value=[{"payload": "PAY_XSS"}]):
            result = oracle.verify("xss", {"vulnerable": True, "type": "xss"},
                                   "http://t.local/search", "q", sess, timeout=5.0)
        assert result["confidence_score"] == 0.3
        assert result["verified"] is False


class TestOracleLfi:
    def test_multiple_files_confirmed(self):
        oracle, profiler = _oracle()

        def get(url, timeout=None):
            text = unquote(url)
            if "PAY_LFI_1" in text:
                return _Resp("root:x:0:0:root:/root:/bin/bash")
            if "PAY_LFI_2" in text:
                return _Resp("[fonts]\n[extensions]")
            raise requests.RequestException("nope")

        sess = MagicMock()
        sess.get.side_effect = get
        seeds = [{"payload": "PAY_LFI_1"}, {"payload": "PAY_LFI_2"}, {"payload": "PAY_LFI_3"}]
        with patch("tools.payload_engine.generate", return_value=seeds):
            result = oracle.verify("lfi", {"vulnerable": True, "type": "lfi"},
                                   "http://t.local/view", "f", sess, timeout=5.0)
        assert result["verified"] is True
        assert result["confidence"] == "high"
        assert "multi_file_confirmed:0.75" in result["confidence_votes"]
        assert result["reproduction"]["observed"] == 2

    def test_no_signature_match(self):
        oracle, profiler = _oracle()
        sess = MagicMock()
        sess.get.return_value = _Resp("nothing interesting")
        with patch("tools.payload_engine.generate", return_value=[{"payload": "PAY_LFI"}]):
            result = oracle.verify("lfi", {"vulnerable": True, "type": "lfi"},
                                   "http://t.local/view", "f", sess, timeout=5.0)
        assert result["confidence_score"] == 0.0
        assert result["verified"] is False


class TestOracleSsrf:
    def test_oob_type_vote(self):
        oracle, profiler = _oracle()
        finding = {"vulnerable": True, "type": "interaction", "oob_type": "dns"}
        result = oracle.verify("ssrf", finding, "http://t.local/fetch", "url",
                               MagicMock(), timeout=5.0)
        assert result["verified"] is True
        assert result["confidence"] == "confirmed"
        assert "oob_dns:0.90" in result["confidence_votes"]

    def test_no_evidence_is_capped(self):
        oracle, profiler = _oracle()
        result = oracle.verify("ssrf", {"vulnerable": True, "type": "maybe"},
                               "http://t.local/fetch", "url", MagicMock(), timeout=5.0)
        assert result["verified"] is False
        assert result["confidence_score"] == 0.0


class TestOracleEmit:
    def test_cvss_failure_is_swallowed(self):
        oracle, profiler = _oracle()
        voter = ConfidenceVoter()
        voter.add_vote("test", 0.9, family="test")
        with patch("tools.verification_oracle.cvss_base_score",
                   side_effect=ValueError("bad vector")):
            result = oracle._emit({"vulnerable": True}, voter, "sqli", observed=3)
        assert "cvss_vector" in result
        assert "cvss_score" not in result

    def test_measure_baseline_all_fail(self):
        oracle, profiler = _oracle()
        sess = MagicMock()
        sess.get.side_effect = requests.RequestException("x")
        assert oracle._measure_baseline("http://t/", "id", sess, 5.0) == 0.3

    def test_measure_baseline_median_and_mean(self):
        oracle, profiler = _oracle()
        sess = MagicMock()
        sess.get.return_value = _Resp("z")
        fake = _fake_time()
        fake.time.side_effect = itertools.cycle([0.0, 0.2])
        with patch("tools.verification_oracle.time", fake):
            assert oracle._measure_baseline("http://t/", "id", sess, 5.0) == pytest.approx(0.2)

        calls = {"n": 0}

        def get(url, timeout=None):
            calls["n"] += 1
            if calls["n"] == 2:
                raise requests.RequestException("x")
            return _Resp("z")

        sess2 = MagicMock()
        sess2.get.side_effect = get
        fake2 = _fake_time()
        fake2.time.side_effect = [0.0, 0.2, 0.0, 0.0, 0.4]
        with patch("tools.verification_oracle.time", fake2):
            assert oracle._measure_baseline("http://t/", "id", sess2, 5.0) == pytest.approx(0.3)
