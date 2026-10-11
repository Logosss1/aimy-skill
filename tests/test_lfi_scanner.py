import re

import responses

from tools.lfi_scanner import check


class TestLFIScanner:
    @responses.activate
    def test_traversal_detection(self):
        body = "root:x:0:0:root:/root:/bin/bash"
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/file\?.*"),
            body=body,
            status=200,
        )

        result = check("http://test.com/file", "file")
        assert result["vulnerable"] is True
        assert len(result["findings"]) > 0
        # evidence 必须非空: FPF 要求 >= min_evidence 条, 否则真 LFI 会被
        # 以 "insufficient_evidence" 丢弃 (曾导致 orchestrator 漏报 LFI).
        assert len(result.get("evidence") or []) > 0
        assert any("lfi:" in e for e in result["evidence"])

    @responses.activate
    def test_no_lfi(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/file\?.*"),
            body="x",
            status=404,
        )

        result = check("http://test.com/file", "file")
        assert result["vulnerable"] is False
