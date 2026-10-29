"""Verify that all check() results are normalized at the output boundary."""

import json

from tools.output import output


def test_missing_vulnerable_is_added(capsys):
    output({"type": "xss", "evidence": ["<script>"]})
    payload = json.loads(capsys.readouterr().out)
    assert payload["vulnerable"] is False
    assert payload["type"] == "xss"
    assert payload["evidence"] == ["<script>"]


def test_unknown_fields_are_preserved(capsys):
    output({"vulnerable": True, "type": "sqli", "custom_field": {"a": 1}})
    payload = json.loads(capsys.readouterr().out)
    assert payload["vulnerable"] is True
    assert payload["custom_field"] == {"a": 1}


def test_legacy_int_vulnerable_is_preserved(capsys):
    output({"vulnerable": 3, "type": "unauth"})
    payload = json.loads(capsys.readouterr().out)
    assert payload["vulnerable"] == 3


def test_non_check_dict_is_passed_through(capsys):
    output({"target": "http://x", "count": 3})
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"target": "http://x", "count": 3}
