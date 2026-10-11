import re

import responses

from tools.ssti_detector import check


class TestSSTIDetector:
    @responses.activate
    def test_expression_reflection(self):
        body = '999998000001'
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body=body, status=200,
        )
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is True

    @responses.activate
    def test_alt_engine_detection(self):
        body = '<html>A</html>'
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body=body, status=200,
        )
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is True

    @responses.activate
    def test_no_ssti(self):
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body='normal page content', status=200,
        )
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is False

    @responses.activate
    def test_echo_endpoint_is_not_ssti(self):
        """回显输入不等于 SSTI: payload 被原样返回时不得判 vulnerable.

        回归: /clean_sqli 回显 `{{config}}` 时, indicator "config" 作为子串
        出现在响应里, 旧实现误判为 SSTI.
        """
        from urllib.parse import unquote_plus

        def cb(request):
            q = unquote_plus(request.url.split("?", 1)[1]) if "?" in request.url else ""
            val = q.split("=", 1)[1] if "=" in q else ""
            # Echo the input verbatim, exactly like a reflecting endpoint.
            return (200, {}, "<html><body>Search results for: %s</body></html>" % val)

        responses.add_callback(
            responses.GET, re.compile(r'http://test\.com/page\?.*'), callback=cb)
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is False

    @responses.activate
    def test_echo_with_evaluation_is_ssti(self):
        """回显但求值过: 响应含 49 且不含 payload => 真 SSTI."""
        from urllib.parse import unquote_plus

        def cb(request):
            q = unquote_plus(request.url.split("?", 1)[1]) if "?" in request.url else ""
            val = q.split("=", 1)[1] if "=" in q else ""
            if "7*7" in val:
                return (200, {}, "Result: 49")
            return (200, {}, "Hello")

        responses.add_callback(
            responses.GET, re.compile(r'http://test\.com/page\?.*'), callback=cb)
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is True

    @responses.activate
    def test_boolean_blind_needs_length_delta(self):
        """布尔盲注需长度显著变化, 仅内容不同 (回显) 不算."""
        from urllib.parse import unquote_plus

        def cb(request):
            q = unquote_plus(request.url.split("?", 1)[1]) if "?" in request.url else ""
            val = q.split("=", 1)[1] if "=" in q else ""
            return (200, {}, "<html><body>echo: %s</body></html>" % val)

        responses.add_callback(
            responses.GET, re.compile(r'http://test\.com/page\?.*'), callback=cb)
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is False

    @responses.activate
    def test_time_based_fallback(self):
        import time
        # Fast catch-all for baseline + detect payloads
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body='no ssti match', status=200,
        )
        # Slow callback only for the sleep() payload URL
        def delayed(request):
            time.sleep(3)
            return (200, {}, 'ok')
        responses.add_callback(
            responses.GET,
            re.compile(r'.*sleep.*'),
            callback=delayed,
        )
        result = check('http://test.com/page', 'name', timeout=5)
        assert result['vulnerable'] is True
