"""Coverage tests for tools/crawler.py.

All HTTP is stubbed with an in-process fake session (no network access).
The only real wait is a 1 ms delay branch of Crawler.crawl.
"""

from unittest import mock

import pytest

import tools.crawler as crawler_mod
from tools.crawler import Crawler, _first, _flatten_dict, crawl

BASE = "http://site.test"


class FakeResponse:
    def __init__(self, url, text="", status_code=200, headers=None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class FakeSession:
    """requests.Session stand-in that routes every GET through a callable."""

    def __init__(self, router=None):
        self.router = router
        self.headers = {}
        self.verify = True
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        if self.router is None:
            raise RuntimeError("no route for %s" % url)
        return self.router(url)


def _resp(url, text="", status=200, headers=None):
    return FakeResponse(url, text, status, headers)


class TestModuleHelpers:
    def test_flatten_dict_nested(self):
        assert _flatten_dict({"a": {"b": {"c": 1}}, "d": 2}) == {"a.b.c": 1, "d": 2}

    def test_flatten_dict_empty(self):
        assert _flatten_dict({}) == {}

    def test_first_handles_list_str_and_other(self):
        assert _first(["x", "y"]) == "x"
        assert _first([]) is None
        assert _first("s") == "s"
        assert _first(123) is None

    def test_fake_session_default_raises(self):
        with pytest.raises(RuntimeError):
            FakeSession().get(BASE)


class TestCrawlerBasics:
    def test_init_strips_trailing_slash(self):
        c = Crawler(BASE + "/")
        assert c.base_url == BASE
        assert c.base_netloc == "site.test"
        assert c.visited == set()
        assert c.is_spa is False

    def test_get_http_uses_provided_session(self):
        sess = FakeSession()
        c = Crawler(BASE, sess=sess)
        http = c._get_http()
        assert http is sess
        assert http.verify == crawler_mod.settings.verify_ssl
        assert http.headers["User-Agent"].startswith("Mozilla/5.0")
        assert c._get_http() is sess

    def test_get_http_creates_session_when_missing(self):
        created = FakeSession()
        with mock.patch.object(crawler_mod.requests, "Session", return_value=created):
            c = Crawler(BASE)
            http = c._get_http()
        assert http is created
        assert http.verify == crawler_mod.settings.verify_ssl

    @pytest.mark.parametrize(
        "href, expected",
        [
            ("/a/b/", BASE + "/a/b"),
            ("/", BASE + "/"),
            ("page?x=1", BASE + "/page?x=1"),
            ("#frag", BASE + "/"),
            ("mailto:x@y.com", None),
            ("javascript:void(0)", None),
        ],
    )
    def test_normalize(self, href, expected):
        c = Crawler(BASE)
        assert c._normalize(href, BASE) == expected

    def test_should_crawl(self):
        c = Crawler(BASE)
        assert c._should_crawl(BASE + "/page") is True
        assert c._should_crawl("http://other.test/page") is False
        assert c._should_crawl(BASE + "/static/logo.png") is False

    def test_detect_spa(self):
        c = Crawler(BASE)
        assert c._detect_spa('<div id="root"></div>') is True
        assert c._detect_spa("const a = Vue.createApp({})") is True
        assert c._detect_spa("<html><body>plain</body></html>") is False

    def test_extract_js_bundles_dedupes(self):
        c = Crawler(BASE)
        html = (
            '<script src="/a.js"></script><script src="/a.js"></script>'
            "<script src='/b.js'></script><script>inline</script>"
        )
        assert c._extract_js_bundles(html) == ["/a.js", "/b.js"]

    def test_analyze_js_for_api(self):
        c = Crawler(BASE)
        js = (
            'var a = "/api/users"; axios.get("v1/items");'
            'var base = baseURL: "http://api.site.test";'
            'url: "/xx/yy"; path: "/admin"; route: "/r1";'
            '"/about": {component: Home}; const tiny = "/ab";'
        )
        apis = c._analyze_js_for_api(js)
        assert "/api/users" in apis
        assert "v1/items" in apis
        assert "http://api.site.test" in apis
        assert "/xx/yy" in apis
        assert "/admin" in apis
        assert "/r1" in apis
        assert "/about" in apis
        assert "/ab" not in apis


class TestCrawlerExtractors:
    def test_extract_forms_bs4(self):
        c = Crawler(BASE)
        html = (
            '<form action="/login" method="post">'
            '<input name="user" type="text" value="a">'
            '<input type="hidden">'
            "</form>"
            "<form><input name='q'></form>"
        )
        c._extract_forms(html, BASE + "/p")
        assert c.forms[0]["action"] == BASE + "/login"
        assert c.forms[0]["method"] == "POST"
        assert c.forms[0]["inputs"][0]["name"] == "user"
        assert c.forms[1]["action"] == BASE + "/p"
        assert c.forms[1]["method"] == "GET"
        assert {"user", "q"} <= c.all_params

    def test_extract_forms_bs4_exception_swallowed(self):
        c = Crawler(BASE)
        with mock.patch.object(crawler_mod, "BeautifulSoup", side_effect=RuntimeError("bad")):
            c._extract_forms("<form></form>", BASE)
        assert c.forms == []

    def test_extract_forms_without_bs4(self, monkeypatch):
        monkeypatch.setattr(crawler_mod, "HAS_BS4", False)
        c = Crawler(BASE)
        c._extract_forms('<form action="/s"><input name="a"><input name="b"></form>', BASE)
        assert c.forms[0]["action"] == BASE + "/s"
        assert c.forms[0]["method"] == "GET"
        assert [i["name"] for i in c.forms[0]["inputs"]] == ["a", "b"]
        assert {"a", "b"} <= c.all_params

    def test_extract_endpoints_bs4(self):
        c = Crawler(BASE)
        html = (
            '<a href="/page?x=1&y=2">p</a>'
            '<a href="/page?x=1&y=2">dup</a>'
            '<a href="mailto:x@y.com">m</a>'
            '<a href="/style.css">c</a>'
            "<a>nohref</a>"
            '<script>var u = "/api/users";</script>'
        )
        c._extract_endpoints(html, BASE + "/p")
        assert c.endpoints["/page"]["params"] == ["x", "y"]
        assert {"x", "y"} <= c.all_params
        assert "/api/users" in c.api_endpoints
        assert c.endpoints["/api/users"]["url"] == BASE + "/api/users"

    def test_extract_endpoints_bs4_exception_swallowed(self):
        c = Crawler(BASE)
        with mock.patch.object(crawler_mod, "BeautifulSoup", side_effect=RuntimeError("bad")):
            c._extract_endpoints('<a href="/x">x</a>var a = "/api/y";', BASE)
        assert "/api/y" in c.api_endpoints
        assert "/x" not in c.endpoints

    def test_extract_endpoints_without_bs4(self, monkeypatch):
        monkeypatch.setattr(crawler_mod, "HAS_BS4", False)
        c = Crawler(BASE)
        c._extract_endpoints('<a href="/ignored">x</a>var a = "/api/z";', BASE + "/p")
        assert "/ignored" not in c.endpoints
        assert "/api/z" in c.api_endpoints

    def test_extract_embedded_params(self):
        c = Crawler(BASE)
        c._extract_embedded_params(
            '{"alpha": "1"} var beta = "x"; let gamma = "y"; const delta = "z"; {"a": "1"}'
        )
        assert {"alpha", "beta", "gamma", "delta"} <= c.all_params
        assert "a" not in c.all_params

    def test_extract_ssr_data(self):
        c = Crawler(BASE)
        html = (
            '<script id="__NEXT_DATA__" type="application/json">'
            '{"props": {"pageProps": {"u": "/api/next", "n": {"d": "/deep"}}}}'
            "</script>"
            "<script>window.__INITIAL_STATE__ = "
            '{"a": "/api/state", "b": "http://cdn.test/x.json", "c": {"d": "/api/deep"}};</script>'
            '<script>window.__NUXT__ = {"route": "/nuxt"}</script>'
        )
        c._extract_ssr_data(html, BASE)
        assert {"/api/next", "/deep", "/api/state", "/api/deep", "/nuxt"} <= c.api_endpoints
        assert "http://cdn.test/x.json" in c.api_endpoints
        assert c.endpoints["/api/state"]["source"] == "ssr"

    def test_extract_ssr_data_invalid_json_is_swallowed(self):
        c = Crawler(BASE)
        html = (
            '<script id="__NEXT_DATA__" type="application/json">{bad}</script>'
            "<script>window.__INITIAL_STATE__ = {bad};</script>"
            "<script>window.__NUXT__ = {bad}</script>"
        )
        c._extract_ssr_data(html, BASE)
        assert c.api_endpoints == set()

    def test_hit_common_api_branches(self):
        def router(url):
            if url.endswith("/api/health"):
                return _resp(url, '{"ok": 1}', 200, {"Content-Type": "application/json"})
            if url.endswith("/api/status"):
                return _resp(url, "x" * 8000, 200, {"Content-Type": "text/html"})
            if url.endswith("/api/ping"):
                return _resp(url, "gone", 0)
            if url.endswith("/api/v1/health"):
                raise RuntimeError("boom")
            return _resp(url, "", 404)

        c = Crawler(BASE, sess=FakeSession(router))
        found = c._hit_common_api()
        assert {f[0] for f in found} == {"/api/health"}

    def test_fetch_page_ok_and_error(self):
        def router(url):
            if url == BASE + "/ok":
                return _resp(url, "hi")
            raise RuntimeError("down")

        c = Crawler(BASE, sess=FakeSession(router))
        ok = c._fetch_page(BASE + "/ok")
        assert ok[0] == BASE + "/ok"
        assert ok[1].text == "hi"
        assert c._fetch_page(BASE + "/dead") is None

    def test_process_page_redirect_and_links(self):
        c = Crawler(BASE)
        html = '<a href="/next">n</a><a href="/img.png">i</a><a href="http://other.test/x">e</a>'
        r = _resp(BASE + "/final", html)
        new_urls = c._process_page(BASE + "/p", r)
        urls = [u for u, _ in new_urls]
        assert BASE + "/final" in urls
        assert BASE + "/next" in urls
        assert BASE + "/img.png" not in urls
        assert "http://other.test/x" not in urls

    def test_process_page_without_bs4(self, monkeypatch):
        monkeypatch.setattr(crawler_mod, "HAS_BS4", False)
        c = Crawler(BASE)
        r = _resp(BASE + "/p", '<a href="/next">n</a><a href="/skip.css">c</a>')
        new_urls = c._process_page(BASE + "/p", r)
        assert [u for u, _ in new_urls] == [BASE + "/next"]

    def test_process_page_bs4_exception_swallowed(self):
        c = Crawler(BASE)
        with mock.patch.object(crawler_mod, "BeautifulSoup", side_effect=RuntimeError("bad")):
            new_urls = c._process_page(BASE + "/p", _resp(BASE + "/p", "<a href='/x'>x</a>"))
        assert new_urls == []


class TestCrawlLoop:
    def test_crawl_threaded_multi_page(self):
        def router(url):
            if url == BASE:
                return _resp(url, '<a href="/a">a</a><a href="/b">b</a><a href="/broken">x</a>')
            if url == BASE + "/a":
                return _resp(
                    url, '<a href="/c">c</a><form action="/submit"><input name="q"></form>'
                )
            if url == BASE + "/b":
                return _resp(url, "")
            if url == BASE + "/c":
                return _resp(url, "")
            raise RuntimeError("connection refused")

        c = Crawler(BASE, max_depth=2, max_pages=10, sess=FakeSession(router))
        result = c.crawl()
        assert result["summary"]["pages_crawled"] == 4
        assert {BASE, BASE + "/a", BASE + "/b", BASE + "/c"} <= set(result["urls"])
        assert result["is_spa"] is False
        assert result["forms"][0]["action"] == BASE + "/submit"
        assert "q" in result["parameters"]
        assert result["summary"]["endpoints_found"] >= 3

    def test_crawl_single_worker_respects_max_pages(self):
        c = Crawler(
            BASE, max_pages=1, sess=FakeSession(lambda url: _resp(url, '<a href="/a">a</a>'))
        )
        result = c.crawl()
        assert result["summary"]["pages_crawled"] == 1
        assert result["urls"] == [BASE]
        assert result["summary"]["is_spa"] is False

    def test_crawl_self_link_and_delay(self):
        c = Crawler(
            BASE,
            max_pages=5,
            delay=0.001,
            sess=FakeSession(lambda url: _resp(url, '<a href="/">self</a>')),
        )
        result = c.crawl()
        assert result["summary"]["pages_crawled"] == 2

    def test_crawl_spa_bundles_and_common_api_fallback(self):
        def router(url):
            if url == BASE:
                return _resp(
                    url,
                    '<div id="app"></div>'
                    '<script src="/static/app.js"></script>'
                    '<script src="/static/fail.js"></script>'
                    'var cfg = "/api/users";',
                )
            if url == BASE + "/static/app.js":
                return _resp(
                    url,
                    'var a="/api/users";axios.get("v1/items");'
                    'base:"http://api.site.test";url:"/x/y";'
                    'path:"/admin";route:"/r1";"/about":{component:Home}',
                )
            if url == BASE + "/static/fail.js":
                raise RuntimeError("bundle gone")
            if url.endswith("/api/health") or url.endswith("/api/users"):
                return _resp(url, '{"ok": true}', 200, {"Content-Type": "application/json"})
            return _resp(url, "", 404)

        c = Crawler(BASE, max_pages=1, sess=FakeSession(router))
        result = c.crawl()
        assert result["is_spa"] is True
        assert {"/api/users", "v1/items"} <= set(result["js_api_endpoints"])
        assert result["endpoints"]["/api/health"]["status"] == 200
        assert "status" not in result["endpoints"]["/api/users"]

    def test_crawl_spa_detection_fetch_failure_is_swallowed(self):
        state = {"n": 0}

        def router(url):
            state["n"] += 1
            if state["n"] == 1:
                return _resp(url, "plain")
            raise RuntimeError("down")

        c = Crawler(BASE, max_pages=1, sess=FakeSession(router))
        result = c.crawl()
        assert result["is_spa"] is False

    def test_crawl_spa_stage_fetch_failure_is_swallowed(self):
        state = {"n": 0}

        def router(url):
            state["n"] += 1
            if state["n"] <= 2:
                return _resp(url, '<div id="root"></div>')
            raise RuntimeError("down")

        c = Crawler(BASE, max_pages=1, sess=FakeSession(router))
        result = c.crawl()
        assert result["is_spa"] is True
        assert result["js_api_endpoints"] == []

    def test_crawl_single_worker_fetch_failure(self):
        def router(url):
            raise RuntimeError("connection refused")

        c = Crawler(BASE, max_pages=1, sess=FakeSession(router))
        result = c.crawl()
        assert result["summary"]["pages_crawled"] == 0
        assert result["is_spa"] is False

    def test_module_level_crawl(self):
        result = crawl(BASE, max_pages=1, sess=FakeSession(lambda url: _resp(url, "<html></html>")))
        assert result["summary"]["pages_crawled"] == 1
        assert set(result) >= {"urls", "endpoints", "forms", "api_endpoints", "summary"}


class TestModuleImportGuard:
    def test_module_import_without_bs4(self, monkeypatch):
        import importlib
        import sys

        monkeypatch.setitem(sys.modules, "bs4", None)
        try:
            reloaded = importlib.reload(crawler_mod)
            assert reloaded.HAS_BS4 is False
        finally:
            monkeypatch.undo()
            importlib.reload(crawler_mod)
        assert crawler_mod.HAS_BS4 is True


class FakeElement:
    def __init__(self, attrs=None, text=None):
        self.attrs = attrs or {}
        self._text = text

    def get_attribute(self, name):
        return self.attrs.get(name)

    def text_content(self):
        return self._text


class FakeApiCall:
    def __init__(self, url, method="GET", status=200, response_body=None):
        self.url = url
        self.method = method
        self.status = status
        self.response_body = response_body


class FakeScript:
    def __init__(self, body):
        self.response_body = body


class FakeTextHandle:
    def __init__(self, page, text):
        self.page = page
        self.text = text
        self.first = self

    def count(self):
        return 1 if self.text in self.page.buttons else 0

    def click(self, timeout=None):
        self.page.url = self.page.url + "#clicked"


class FakePage:
    def __init__(self, url, html="", anchors=(), scripts=(), buttons=(), content_error=None):
        self.url = url
        self._html = html
        self.anchors = list(anchors)
        self.scripts = list(scripts)
        self.buttons = list(buttons)
        self.content_error = content_error
        self.a_calls = 0
        self.goto_calls = []
        self.closed = False

    def content(self):
        if self.content_error:
            raise self.content_error
        return self._html

    def query_selector_all(self, selector):
        if selector == "a[href]":
            self.a_calls += 1
            if self.a_calls <= 1:
                return []
            return [FakeElement({"href": h}) for h in self.anchors]
        if selector == "script[src]":
            return [FakeElement({"src": s}) for s in self.scripts]
        if selector == "button":
            return [FakeElement(text=t) for t in self.buttons]
        return []

    def goto(self, href, wait_until=None, timeout=None):
        self.goto_calls.append(href)
        self.url = href
        self._html = "visited %s" % href

    def get_by_text(self, text, exact=True):
        return FakeTextHandle(self, text)

    def close(self):
        self.closed = True


class FakeEngine:
    def __init__(self, page, api_calls=None, scripts=None):
        self.page = page
        self.api_calls = api_calls or []
        self.scripts = scripts or []
        self.started = False
        self.stopped = False
        self.navigated = []
        self.capture_api = None

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def new_page(self, capture_api=False):
        self.capture_api = capture_api
        return self.page

    def navigate_and_wait(self, page, url, timeout=None):
        self.navigated.append((url, timeout))

    def get_api_calls(self):
        return list(self.api_calls)

    def get_scripts(self):
        return list(self.scripts)


class TestSpaCrawlerWithFakeEngine:
    """SpaCrawler tests with an injected fake engine (Playwright never used)."""

    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        import tools.spa_crawler as spa_mod

        self.spa_mod = spa_mod
        monkeypatch.setattr(spa_mod.time, "sleep", lambda seconds: None)

    def _page(self):
        return FakePage(
            "http://app.test/",
            html="<html>home</html>",
            anchors=["http://app.test/about", "http://other.test/x", "#top", "javascript:void(0)"],
            scripts=["/static/app.js"],
            buttons=["Login", "Login"],
        )

    def _engine(self):
        return FakeEngine(
            self._page(),
            api_calls=[
                FakeApiCall(
                    "http://app.test/api/login",
                    "POST",
                    200,
                    '{"endpoints": ["/api/a", 1], "links": ["/api/b"]}',
                ),
                FakeApiCall("http://app.test/none", "GET", 500, None),
            ],
            scripts=[
                FakeScript(None),
                FakeScript('var x="/api/users";path:"/admin";get("/orders")'),
            ],
        )

    def test_crawl_discovers_links_apis_and_clicks(self):
        engine = self._engine()
        crawler = self.spa_mod.SpaCrawler(
            "http://app.test", max_clicks=5, max_depth=2, engine=engine
        )
        result = crawler.crawl()
        assert engine.capture_api is True
        assert engine.navigated == [("http://app.test", 30000)]
        assert engine.page.goto_calls == ["http://app.test/about"]
        assert engine.page.closed is True
        assert "http://app.test/about" in result["internal_links"]
        assert "/api/login" in result["api_routes"]
        assert {"/api/a", "/api/b"} <= set(result["api_routes"])
        assert {"/api/users", "/admin", "/orders"} <= set(result["js_api_routes"])
        assert result["endpoints"]["/api/login"]["spa_api"] is True
        assert result["urls_crawled"] >= 1

    def test_crawl_module_level_function(self):
        engine = self._engine()
        result = self.spa_mod.crawl_spa("http://app.test", max_clicks=1, max_depth=1, engine=engine)
        assert result["urls_crawled"] >= 1

    def test_crawl_playwright_unavailable(self):
        with mock.patch.object(self.spa_mod.PlaywrightEngine, "is_available", return_value=False):
            result = self.spa_mod.SpaCrawler("http://app.test").crawl()
        assert result["error"] == "Playwright not available"
        assert result["endpoints"] == {}

    def test_crawl_auto_engine_is_started_and_stopped(self):
        engine = self._engine()
        with (
            mock.patch.object(self.spa_mod.PlaywrightEngine, "is_available", return_value=True),
            mock.patch.object(self.spa_mod, "PlaywrightEngine", return_value=engine),
        ):
            result = self.spa_mod.SpaCrawler("http://app.test", max_clicks=0).crawl()
        assert engine.started is True
        assert engine.stopped is True
        assert result["api_discovered"] >= 1

    def test_crawl_engine_failure_returns_empty_result(self):
        engine = self._engine()
        engine.navigate_and_wait = mock.Mock(side_effect=RuntimeError("crashed"))
        result = self.spa_mod.SpaCrawler("http://app.test", engine=engine).crawl()
        assert "crashed" in result["error"]
        assert engine.page.closed is False

    def test_auto_engine_stop_failure_is_swallowed(self):
        engine = self._engine()
        engine.stop = mock.Mock(side_effect=RuntimeError("stop failed"))
        with (
            mock.patch.object(self.spa_mod.PlaywrightEngine, "is_available", return_value=True),
            mock.patch.object(self.spa_mod, "PlaywrightEngine", return_value=engine),
        ):
            result = self.spa_mod.SpaCrawler("http://app.test", max_clicks=0).crawl()
        assert result["api_discovered"] >= 1

    def test_goto_failure_is_swallowed(self):
        page = self._page()
        page.goto = mock.Mock(side_effect=RuntimeError("goto failed"))
        engine = FakeEngine(page, scripts=[FakeScript('path:"/x1"')])
        crawler = self.spa_mod.SpaCrawler(
            "http://app.test", max_clicks=5, max_depth=1, engine=engine
        )
        result = crawler.crawl()
        assert result["urls_crawled"] == 1
        assert "/x1" in result["js_api_routes"]

    def test_click_failure_is_swallowed(self):
        class BadClickHandle:
            def __init__(self):
                self.first = self

            def count(self):
                return 1

            def click(self, timeout=None):
                raise RuntimeError("click failed")

        page = self._page()
        page.get_by_text = mock.Mock(return_value=BadClickHandle())
        engine = FakeEngine(page)
        crawler = self.spa_mod.SpaCrawler(
            "http://app.test", max_clicks=5, max_depth=2, engine=engine
        )
        result = crawler.crawl()
        assert page.closed is True
        assert result["urls_crawled"] == 1

    def test_extract_from_page_swallows_page_errors(self):
        page = FakePage("http://app.test/", content_error=RuntimeError("no html"))
        engine = FakeEngine(page, api_calls=[FakeApiCall("http://app.test/api/x")])
        crawler = self.spa_mod.SpaCrawler("http://app.test", engine=engine)
        crawler._extract_from_page(page)
        assert "/api/x" in crawler.api_routes
        assert "/api/x" in crawler.discovered_endpoints

    def test_extract_from_page_merges_methods_for_known_path(self):
        page = FakePage("http://app.test/", html="<html></html>")
        engine = FakeEngine(
            page,
            api_calls=[
                FakeApiCall("http://app.test/api/x", "GET"),
                FakeApiCall("http://app.test/api/x", "POST"),
            ],
        )
        crawler = self.spa_mod.SpaCrawler("http://app.test", engine=engine)
        crawler._extract_from_page(page)
        assert crawler.discovered_endpoints["/api/x"]["methods"] == ["GET", "POST"]

    def test_parse_json_response_ignores_bad_input(self):
        crawler = self.spa_mod.SpaCrawler("http://app.test")
        crawler._parse_json_response("{bad", "http://app.test/")
        crawler._parse_json_response("[1, 2]", "http://app.test/")
        crawler._parse_json_response(
            '{"endpoints": [1, "/ok"], "routes": "nope"}', "http://app.test/"
        )
        assert crawler.api_routes == {"/ok"}

    def test_get_internal_links_swallows_errors(self):
        page = mock.Mock()
        page.query_selector_all.side_effect = RuntimeError("boom")
        crawler = self.spa_mod.SpaCrawler("http://app.test")
        assert crawler._get_internal_links(page) == []

    def test_get_clickable_elements_filters_and_dedupes(self):
        page = FakePage("http://app.test/", buttons=["Login", "Login", "x" * 40, "  ", "OK"])
        crawler = self.spa_mod.SpaCrawler("http://app.test")
        assert set(crawler._get_clickable_elements(page)) == {"Login", "OK"}

    def test_get_clickable_elements_swallows_errors(self):
        page = mock.Mock()
        page.query_selector_all.side_effect = RuntimeError("boom")
        crawler = self.spa_mod.SpaCrawler("http://app.test")
        assert crawler._get_clickable_elements(page) == []

    def test_empty_result_shape(self):
        result = self.spa_mod.SpaCrawler("http://app.test")._empty_result("nope")
        assert result["error"] == "nope"
        assert result["api_discovered"] == 0
