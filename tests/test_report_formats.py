import json
import os

from tools.reporter import generate_markdown, generate_sarif, save_report


def _report():
    return {
        "target": "http://target.test/page?id=1",
        "timestamp": "2026-01-01T00:00:00Z",
        "elapsed_seconds": 1.5,
        "summary": {"vulnerabilities": 1, "exploit_ready": 0, "critical": False},
        "details": {
            "sqli": [
                {
                    "url": "http://target.test/page",
                    "param": "id",
                    "confidence_score": 0.9,
                    "evidence": ["sql error"],
                }
            ],
        },
    }


def test_sarif_document_shape():
    sarif = generate_sarif(_report())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "aimy-skill"
    assert run["results"][0]["ruleId"] == "aimy/sqli"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_markdown_contains_finding():
    md = generate_markdown(_report())
    assert "SQli".upper() in md
    assert "http://target.test/page" in md
    assert "id" in md


def test_save_report_writes_json_html_sarif_markdown(tmp_path):
    paths = save_report(_report(), str(tmp_path))
    assert set(paths) == {"json", "html", "sarif", "markdown"}
    for path in paths.values():
        assert os.path.exists(path)
    payload = json.loads(open(paths["sarif"], encoding="utf-8").read())
    assert payload["version"] == "2.1.0"
