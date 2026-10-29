"""Tests for tools.recon.dir_fuzzer - catch-all detection."""

from tools.recon.dir_fuzzer import _detect_catchall, fuzz_directories


class FakeResp:
    def __init__(self, status, body, content_type="text/html"):
        self.status_code = status
        self.content = body
        self.headers = {"Content-Type": content_type}


class FakeSession:
    """Minimal requests.Session stand-in driven by a url->FakeResp handler."""

    def __init__(self, handler):
        self._handler = handler
        self.verify = False

    def get(self, url, **kwargs):
        return self._handler(url)


class TestDetectCatchall:
    def test_normal_404_server_no_catchall(self):
        """随机路径返回 404 => 无 catch-all."""
        sess = FakeSession(lambda url: FakeResp(404, b"not found"))
        assert _detect_catchall("http://x.test", sess, 2.0) is None

    def test_same_200_body_is_catchall(self):
        """任意路径都返回同样的 200 页面 => 识别为 catch-all."""
        sess = FakeSession(lambda url: FakeResp(200, b"<html>spa shell</html>"))
        sig = _detect_catchall("http://x.test", sess, 2.0)
        assert sig is not None
        assert isinstance(sig, int)

    def test_distinct_200_bodies_no_catchall(self):
        """200 但每次 body 不同 => 不是 catch-all (可能是随机内容)."""
        counter = {"n": 0}

        def handler(url):
            counter["n"] += 1
            return FakeResp(200, b"body-%d" % counter["n"])

        sess = FakeSession(handler)
        assert _detect_catchall("http://x.test", sess, 2.0) is None


class TestFuzzDirectoriesCatchall:
    def test_catchall_server_reports_zero_interesting(self):
        """catch-all 服务器: 所有路径同 body => interesting 为空, 不污染下游."""
        sess = FakeSession(lambda url: FakeResp(200, b"ok"))
        r = fuzz_directories(
            "http://x.test", wordlist=["admin", "login", ".env"], sess=sess, timeout=2.0
        )
        assert r["catchall_detected"] is True
        assert r["catchall_skipped"] > 0
        assert r["interesting"] == []

    def test_normal_server_reports_interesting(self):
        """正常服务器: 只有 /admin 存在 => 只报 /admin."""

        def handler(url):
            if url.endswith("/admin"):
                return FakeResp(200, b"<html>admin panel</html>")
            return FakeResp(404, b"nope")

        sess = FakeSession(handler)
        r = fuzz_directories(
            "http://x.test", wordlist=["admin", "login", ".env"], sess=sess, timeout=2.0
        )
        assert r["catchall_detected"] is False
        assert r["catchall_skipped"] == 0
        paths = [x["path"] for x in r["interesting"]]
        assert "/admin" in paths
        assert "/login" not in paths

    def test_body_hash_not_leaked_in_output(self):
        """内部去重用的 body_hash 不应出现在对外结果里."""

        def handler(url):
            if url.endswith("/admin"):
                return FakeResp(200, b"<html>admin</html>")
            return FakeResp(404, b"nope")

        sess = FakeSession(handler)
        r = fuzz_directories("http://x.test", wordlist=["admin"], sess=sess, timeout=2.0)
        for item in r["interesting"]:
            assert "body_hash" not in item
        for item in r["all"]:
            assert "body_hash" not in item

    def test_catchall_flag_present_always(self):
        sess = FakeSession(lambda url: FakeResp(404, b"x"))
        r = fuzz_directories("http://x.test", wordlist=["admin"], sess=sess, timeout=2.0)
        assert "catchall_detected" in r
        assert "catchall_skipped" in r
