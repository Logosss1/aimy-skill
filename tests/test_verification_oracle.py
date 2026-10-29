from unittest.mock import MagicMock

from tools.verification_oracle import (
    ConfidenceLevel,
    ConfidenceVoter,
    VerificationOracle,
)


class TestConfidenceLevel:
    def test_from_score_confirmed(self):
        assert ConfidenceLevel.from_score(0.95) == ConfidenceLevel.CONFIRMED
        assert ConfidenceLevel.from_score(0.85) == ConfidenceLevel.CONFIRMED

    def test_from_score_high(self):
        assert ConfidenceLevel.from_score(0.70) == ConfidenceLevel.HIGH
        assert ConfidenceLevel.from_score(0.65) == ConfidenceLevel.HIGH

    def test_from_score_medium(self):
        assert ConfidenceLevel.from_score(0.40) == ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.from_score(0.35) == ConfidenceLevel.MEDIUM

    def test_from_score_low(self):
        assert ConfidenceLevel.from_score(0.10) == ConfidenceLevel.LOW
        assert ConfidenceLevel.from_score(0.0) == ConfidenceLevel.LOW


class TestConfidenceVoter:
    def test_vote_status_code_same(self):
        class Resp:
            status_code = 200

        assert ConfidenceVoter.vote_status_code(Resp(), 200) == 0.0

    def test_vote_status_code_500(self):
        class Resp:
            status_code = 500

        assert ConfidenceVoter.vote_status_code(Resp(), 200) == 0.5

    def test_vote_status_code_502(self):
        class Resp:
            status_code = 502

        assert ConfidenceVoter.vote_status_code(Resp(), 200) == 0.5

    def test_vote_status_code_200_same(self):
        class Resp:
            status_code = 200

        assert ConfidenceVoter.vote_status_code(Resp(), 200) == 0.0

    def test_vote_status_code_503(self):
        class Resp:
            status_code = 503

        assert ConfidenceVoter.vote_status_code(Resp(), 200) == 0.5

    def test_vote_status_code_different(self):
        class Resp:
            status_code = 200

        assert ConfidenceVoter.vote_status_code(Resp(), 404) == 0.3

    def test_vote_length_diff_large(self):
        score = ConfidenceVoter.vote_length_diff(300, 100)
        assert score == 0.7

    def test_vote_length_diff_small(self):
        score = ConfidenceVoter.vote_length_diff(104, 100)
        assert score == 0.3

    def test_vote_length_diff_medium(self):
        score = ConfidenceVoter.vote_length_diff(110, 100)
        assert score == 0.5

    def test_vote_length_diff_small_medium(self):
        score = ConfidenceVoter.vote_length_diff(104, 100)
        assert score == 0.3

    def test_vote_length_diff_zero_baseline(self):
        assert ConfidenceVoter.vote_length_diff(100, 0) == 0.0

    def test_vote_body_hash_different(self):
        assert ConfidenceVoter.vote_body_hash("abc", "def") == 0.6

    def test_vote_body_hash_same(self):
        assert ConfidenceVoter.vote_body_hash("abc", "abc") == 0.0

    def test_vote_time_elapsed_above_threshold(self):
        score = ConfidenceVoter.vote_time_elapsed(10.0, 1.0, 5.0)
        assert score > 0

    def test_vote_time_elapsed_below_threshold(self):
        assert ConfidenceVoter.vote_time_elapsed(1.0, 0.5, 5.0) == 0.0

    def test_vote_evidence_keywords_many(self):
        score = ConfidenceVoter.vote_evidence_keywords(
            "error warning critical", ["error", "warning", "critical"]
        )
        assert score == 0.9

    def test_vote_evidence_keywords_few(self):
        score = ConfidenceVoter.vote_evidence_keywords(
            "error found", ["error", "warning", "critical"]
        )
        assert score == 0.5

    def test_vote_evidence_keywords_none(self):
        assert ConfidenceVoter.vote_evidence_keywords("nothing here", ["error", "warning"]) == 0.0

    def test_vote_oob_callback_true(self):
        assert ConfidenceVoter.vote_oob_callback(True) == 0.95

    def test_vote_oob_callback_false(self):
        assert ConfidenceVoter.vote_oob_callback(False) == 0.0

    def test_vote_multiple_payloads_high(self):
        assert ConfidenceVoter.vote_multiple_payloads(5, 10) == 0.8

    def test_vote_multiple_payloads_medium(self):
        assert ConfidenceVoter.vote_multiple_payloads(3, 10) == 0.5

    def test_vote_multiple_payloads_low(self):
        assert ConfidenceVoter.vote_multiple_payloads(1, 10) == 0.2

    def test_vote_multiple_payloads_zero_tried(self):
        assert ConfidenceVoter.vote_multiple_payloads(0, 0) == 0.0

    def test_voter_score_empty(self):
        v = ConfidenceVoter()
        assert v.score == 0.0

    def test_voter_evidence(self):
        v = ConfidenceVoter()
        v.add_vote("source_a", 0.5)
        v.add_vote("source_b", 0.7)
        assert len(v.evidence()) == 2
        assert "source_a:0.50" in v.evidence()[0]


class TestVerificationOracle:
    def test_oracle_init(self):
        oracle = VerificationOracle()
        assert oracle.profiler is not None

    def test_verify_not_vulnerable(self):
        oracle = VerificationOracle()
        finding = {"vulnerable": False, "type": "sqli"}
        result = oracle.verify("sqli", finding, "http://test.com", "id", MagicMock(), timeout=2.0)
        assert result["confidence_score"] == 0.0
        assert result["confidence_votes"] == []

    def test_verify_unknown_detector(self):
        oracle = VerificationOracle()
        finding = {"vulnerable": True, "type": "unknown"}
        result = oracle.verify(
            "unknown_type", finding, "http://test.com", "id", MagicMock(), timeout=2.0
        )
        assert result["vulnerable"] is True

    def test_verify_ssrf_disclosure(self):
        oracle = VerificationOracle()
        finding = {"vulnerable": True, "type": "disclosure"}
        result = oracle.verify("ssrf", finding, "http://test.com", "url", MagicMock(), timeout=2.0)
        assert result["vulnerable"] is True
        assert result["type"] == "disclosure"

    def test_verify_ssrf_oob_callback(self):
        oracle = VerificationOracle()
        finding = {"vulnerable": True, "type": "oob_http_callback", "oob_type": "http"}
        result = oracle.verify("ssrf", finding, "http://test.com", "url", MagicMock(), timeout=2.0)
        assert result["vulnerable"] is True

    def test_verify_ssrf_no_oob(self):
        oracle = VerificationOracle()
        finding = {"vulnerable": True, "type": "ssrf_maybe"}
        result = oracle.verify("ssrf", finding, "http://test.com", "url", MagicMock(), timeout=2.0)
        assert result["vulnerable"] is True

    def test_emit_basic(self):
        oracle = VerificationOracle()
        voter = ConfidenceVoter()
        voter.add_vote("test", 0.9, family="test")
        finding = {"vulnerable": True, "type": "sqli"}
        result = oracle._emit(finding, voter, "sqli", observed=1)
        assert "confidence" in result
        assert "confidence_score" in result
        assert "reproduction" in result
        assert "verified" in result
