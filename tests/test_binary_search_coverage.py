"""Coverage tests for tools/binary_search.py.

The HTTP layer is stubbed with unittest.mock: session.get is driven by
in-process "oracles" that parse the injected SQL payloads. No network.
"""

import re
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest

import tools.binary_search as bs
from tools.binary_search import (
    _extract_char,
    binary_search_columns,
    binary_search_sqli_blind,
    blind_sqli_extract_data,
    sqli_union_probe,
)

URL = "http://target.test/item"


class Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def _make_session(handler):
    sess = mock.Mock()
    sess.get.side_effect = handler
    return sess


def _raiser(exc):
    def handler(url, timeout=None):
        raise exc

    return handler


def _param_value(url, name="id"):
    return parse_qs(urlparse(url).query, keep_blank_values=True)[name][0]


_ASCII_RE = re.compile(r"ASCII\(SUBSTRING\(\((.+?)\),(\d+),1\)\)>(\d+)")


def _oracle_handler(values, true_text="y" * 60, raise_always=False):
    """Boolean-blind oracle: true iff ASCII(SUBSTRING(query,pos,1)) > mid."""

    def handler(url, timeout=None):
        if raise_always:
            raise RuntimeError("connection reset")
        condition = _param_value(url)
        if "1=2" in condition:
            return Resp(500, "")
        match = _ASCII_RE.search(condition)
        if not match:
            return Resp(200, true_text)
        query, pos, mid = match.group(1), int(match.group(2)), int(match.group(3))
        text = values.get(query)
        if text is None and query.startswith("(") and query.endswith(")"):
            text = values.get(query[1:-1], "")
        if text is None:
            text = ""
        if pos > len(text):
            return Resp(200, true_text)
        char = text[pos - 1]
        if ord(char) > mid:
            return Resp(200, true_text)
        return Resp(500, "")

    return handler


class TestBinarySearchColumns:
    def _order_by_handler(self, real_columns):
        def handler(url, timeout=None):
            payload = _param_value(url)
            number = int(re.search(r"ORDER BY (\d+)", payload).group(1))
            if number <= real_columns:
                return Resp(200, "ok")
            return Resp(500, "error")

        return handler

    def test_exact_column_count(self):
        sess = _make_session(self._order_by_handler(4))
        result = binary_search_columns(URL, "id", sess, max_columns=10)
        assert result["vulnerable"] is True
        assert result["column_count"] == 4
        assert result["confidence"] == 0.9
        assert {e["result"] for e in result["evidence"]} == {"ok", "fail"}

    def test_all_probes_fail(self):
        sess = _make_session(self._order_by_handler(0))
        result = binary_search_columns(URL, "id", sess, max_columns=50)
        assert result["vulnerable"] is False
        assert result["column_count"] is None
        assert len(result["evidence"]) == 5
        assert all(e["result"] == "fail" for e in result["evidence"])

    def test_all_ok_respects_max_columns(self):
        sess = _make_session(self._order_by_handler(1000))
        result = binary_search_columns(URL, "id", sess, max_columns=3)
        assert result["column_count"] == 3

    def test_transport_errors_recorded_as_evidence(self):
        sess = _make_session(_raiser(TimeoutError("timeout")))
        result = binary_search_columns(URL, "id", sess, max_columns=50)
        assert result["vulnerable"] is False
        assert all(e["result"] == "error" for e in result["evidence"])
        assert "timeout" in result["evidence"][0]["error"]


class TestBlindBinarySearch:
    def test_no_boolean_baseline(self):
        sess = _make_session(lambda url, timeout=None: Resp(500, ""))
        result = binary_search_sqli_blind(URL, "id", sess)
        assert result["vulnerable"] is False
        assert result["error"] == "no boolean baseline"

    def test_no_boolean_baseline_when_requests_keep_erroring(self):
        sess = _make_session(_raiser(RuntimeError("boom")))
        result = binary_search_sqli_blind(URL, "id", sess)
        assert result["error"] == "no boolean baseline"

    def test_both_conditions_true(self):
        sess = _make_session(lambda url, timeout=None: Resp(200, "x" * 60))
        result = binary_search_sqli_blind(URL, "id", sess)
        assert result["vulnerable"] is False
        assert result["error"] == "1=1 and 1=2 both true, not blind injectable"

    def test_extracts_database_name(self):
        sess = _make_session(_oracle_handler({"SELECT DATABASE()": "zebra"}))
        result = binary_search_sqli_blind(URL, "id", sess, extract_len=5)
        assert result["vulnerable"] is True
        assert result["extracted"] == "zebra"
        assert result["evidence"][0]["value"] == "zebra"
        assert result["evidence"][0]["query"] == "SUBSTRING"
        assert result["confidence"] == pytest.approx(0.75)

    def test_all_conditions_true_yields_no_extraction(self):
        def handler(url, timeout=None):
            condition = _param_value(url)
            if "1=2" in condition:
                return Resp(500, "")
            return Resp(200, "x" * 60)

        sess = _make_session(handler)
        result = binary_search_sqli_blind(URL, "id", sess, extract_len=2)
        assert result["vulnerable"] is True
        assert result["extracted"] == ""
        assert result["evidence"] == []
        assert result["confidence"] == 0.5

    def test_alternate_baseline_then_extraction(self):
        values = {"SELECT DATABASE()": "app"}

        def handler(url, timeout=None):
            condition = _param_value(url)
            if "1=1" in condition:
                return Resp(500, "")
            if condition.endswith("AND 1--"):
                return Resp(200, "x" * 60)
            return _oracle_handler(values)(url)

        sess = _make_session(handler)
        result = binary_search_sqli_blind(URL, "id", sess, extract_len=3)
        assert result["vulnerable"] is True
        assert result["extracted"] == "app"

    def test_short_success_body_counts_as_true(self):
        values = {"SELECT DATABASE()": "x"}

        def handler(url, timeout=None):
            condition = _param_value(url)
            if "1=2" in condition:
                return Resp(500, "")
            if "1=1" in condition:
                return Resp(200, "ok")
            return _oracle_handler(values, true_text="ok")(url)

        sess = _make_session(handler)
        result = binary_search_sqli_blind(URL, "id", sess, extract_len=1)
        assert result["vulnerable"] is True
        assert result["extracted"] == "x"


class TestBlindExtractData:
    def test_not_injectable_when_baseline_missing(self):
        sess = _make_session(lambda url, timeout=None: Resp(500, ""))
        result = blind_sqli_extract_data(URL, "id", sess)
        assert result["vulnerable"] is False
        assert result["error"] == "not blind injectable"

    def test_not_injectable_when_true_and_false_identical(self):
        sess = _make_session(lambda url, timeout=None: Resp(200, "y" * 30))
        result = blind_sqli_extract_data(URL, "id", sess)
        assert result["error"] == "not blind injectable"

    def test_extracts_version_user_database_and_tables(self):
        tables_query = (
            "(SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE())"
        )
        values = {
            "SELECT VERSION()": "8.0.32",
            "SELECT USER()": "root",
            "SELECT DATABASE()": "appdb",
            "SELECT CURRENT_USER()": "root",
            tables_query: "users,orders",
        }
        sess = _make_session(_oracle_handler(values, true_text="y" * 30))
        result = blind_sqli_extract_data(URL, "id", sess)
        assert result["vulnerable"] is True
        assert result["data"] == {
            "version": "8.0.32",
            "user": "root",
            "database": "appdb",
            "current_user": "root",
            "tables": "users,orders",
        }
        labels = [e["label"] for e in result["evidence"]]
        assert labels == ["version", "user", "database", "current_user", "tables"]
        assert result["confidence"] == 0.95

    def test_transport_error_during_probe_is_not_injectable(self):
        sess = _make_session(_raiser(RuntimeError("boom")))
        result = blind_sqli_extract_data(URL, "id", sess)
        assert result["error"] == "not blind injectable"


class TestExtractChar:
    def test_finds_target_character(self):
        target = "M"

        def oracle(condition):
            return ord(target) > int(condition.rsplit(">", 1)[1])

        assert _extract_char("SELECT 1", 1, oracle) == target

    def test_all_false_returns_lowest_bound(self):
        assert _extract_char("SELECT 1", 1, lambda condition: False) == " "

    def test_all_true_returns_none(self):
        assert _extract_char("SELECT 1", 1, lambda condition: True) is None


class TestUnionProbe:
    def test_no_columns_found_returns_early(self, monkeypatch):
        monkeypatch.setattr(
            bs, "binary_search_columns", lambda *a, **k: {"vulnerable": False, "column_count": None}
        )
        sess = _make_session(lambda url, timeout=None: Resp(404, ""))
        result = sqli_union_probe(URL, "id", sess)
        assert result["vulnerable"] is False
        assert result["columns"] is None
        assert result["usable_columns"] == []

    def test_finds_usable_columns(self, monkeypatch):
        monkeypatch.setattr(
            bs, "binary_search_columns", lambda *a, **k: {"vulnerable": True, "column_count": 2}
        )

        def handler(url, timeout=None):
            payload = _param_value(url)
            if payload.startswith("' UNION SELECT"):
                if "'EXTRACT_1'" in payload:
                    return Resp(200, "no marker here")
                return Resp(404, "")
            if payload.startswith('" UNION SELECT'):
                raise RuntimeError("connection reset")
            if payload.startswith(" UNION SELECT"):
                marker = "EXTRACT_1" if "'EXTRACT_1'" in payload else "EXTRACT_2"
                return Resp(200, "echo: %s" % marker)
            return Resp(404, "")

        sess = _make_session(handler)
        result = sqli_union_probe(URL, "id", sess)
        assert result["vulnerable"] is True
        assert result["columns"] == 2
        assert result["usable_columns"] == [1, 2]
        assert result["confidence"] == 0.85
        assert all(e["method"] == "union" for e in result["evidence"])

    def test_no_marker_in_response_means_no_usable_columns(self, monkeypatch):
        monkeypatch.setattr(
            bs, "binary_search_columns", lambda *a, **k: {"vulnerable": True, "column_count": 1}
        )
        sess = _make_session(lambda url, timeout=None: Resp(404, ""))
        result = sqli_union_probe(URL, "id", sess)
        assert result["vulnerable"] is False
        assert result["columns"] == 1
        assert result["usable_columns"] == []
        assert result["confidence"] == 0.0
