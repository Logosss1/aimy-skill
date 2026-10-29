from tools import sqli_blind
from tools.sqli_blind import BlindInjector, BlindTech, ResponseClassifier, check, check_oob_dns


class FakeResp:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json_data = json_data
        self.headers = {}

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON")
        return self._json_data


class FakeSession:
    def __init__(self, handler=None):
        self.handler = handler
        self.calls = []
        self.verify = True

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.handler is None:
            return FakeResp(200, "ok")
        return self.handler(url, kwargs)


class ScriptedSession:
    def __init__(self, items):
        self.items = list(items)
        self.calls = []
        self.verify = True

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeTime:
    def __init__(self, ticks=None):
        self.ticks = list(ticks or [])
        self.sleeps = []

    def time(self):
        if self.ticks:
            return self.ticks.pop(0)
        return 0.0

    def sleep(self, seconds):
        self.sleeps.append(seconds)


def _raising_handler(url, kwargs):
    raise RuntimeError("boom")


def _raising_session():
    return FakeSession(_raising_handler)


class CalibrateStub:
    def __init__(self, result, true_len=10, false_len=30):
        self.result = result
        self.true_len = true_len
        self.false_len = false_len
        self.calibrated = result

    def calibrate(self, *args, **kwargs):
        self.calibrated = self.result
        return self.result

    def is_true(self, *args, **kwargs):
        return None


class TestClassifierMore:
    def test_calibrate_true_exception_with_variant(self):
        sess = ScriptedSession(
            [
                RuntimeError("boom"),
                FakeResp(200, "true-body"),
                FakeResp(200, "false-body"),
            ]
        )
        clf = ResponseClassifier(sess, 5.0)
        ok = clf.calibrate(
            "http://t.test/x",
            "id",
            "' AND 1=1-- ",
            "' AND 1=2-- ",
            waf_bypass_variants=["variant-1"],
        )
        assert ok is True
        assert clf.true_len == len("true-body")
        assert clf.calibrated is True
        assert "variant-1" in sess.calls[1][0]

    def test_calibrate_true_exception_no_variant(self):
        sess = ScriptedSession([RuntimeError("boom")])
        clf = ResponseClassifier(sess, 5.0)
        assert clf.calibrate("http://t.test/x", "id", "t", "f") is False
        assert clf.calibrated is False

    def test_calibrate_variant_loop_continues_after_error(self):
        sess = ScriptedSession(
            [
                RuntimeError("boom"),
                RuntimeError("boom2"),
                FakeResp(200, "true-body"),
                FakeResp(200, "false-body"),
            ]
        )
        clf = ResponseClassifier(sess, 5.0)
        ok = clf.calibrate(
            "http://t.test/x",
            "id",
            "t",
            "f",
            waf_bypass_variants=["v1", "v2"],
        )
        assert ok is True
        assert clf.true_len == len("true-body")

    def test_calibrate_false_exception(self):
        sess = ScriptedSession([FakeResp(200, "true-body"), RuntimeError("boom")])
        clf = ResponseClassifier(sess, 5.0)
        assert clf.calibrate("http://t.test/x", "id", "t", "f") is False

    def test_calibrate_with_baseline_exception(self):
        sess = ScriptedSession([RuntimeError("boom")])
        clf = ResponseClassifier(sess, 5.0)
        assert clf.calibrate_with_baseline("http://t.test/x", "id", sess, 5.0) is False

    def test_is_true_fast_true(self):
        sess = ScriptedSession([FakeResp(200, "0" * 10)])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 10
        clf.false_len = 30
        assert clf.is_true("http://t.test/x", "id", "p") is True

    def test_is_true_fast_false(self):
        sess = ScriptedSession([FakeResp(200, "0" * 30)])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 10
        clf.false_len = 30
        assert clf.is_true("http://t.test/x", "id", "p") is False

    def test_is_true_text_similarity_true(self):
        sess = ScriptedSession([FakeResp(200, "a" * 10)])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 10
        clf.false_len = 10
        clf.true_text = "a" * 10
        clf.false_text = "b" * 10
        assert clf.is_true("http://t.test/x", "id", "p") is True

    def test_is_true_text_similarity_false(self):
        sess = ScriptedSession([FakeResp(200, "b" * 10)])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 10
        clf.false_len = 10
        clf.true_text = "a" * 10
        clf.false_text = "b" * 10
        assert clf.is_true("http://t.test/x", "id", "p") is False

    def test_is_true_not_calibrated(self):
        clf = ResponseClassifier(FakeSession(), 5.0)
        assert clf.is_true("http://t.test/x", "id", "p") is None

    def test_is_true_diff_based_true(self):
        sess = ScriptedSession([FakeResp(200, "0" * 21)])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 20
        clf.false_len = 25
        assert clf.is_true("http://t.test/x", "id", "p") is True

    def test_is_true_diff_based_false(self):
        sess = ScriptedSession([FakeResp(200, "0" * 24)])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 20
        clf.false_len = 25
        assert clf.is_true("http://t.test/x", "id", "p") is False

    def test_is_true_ambiguous_returns_none(self):
        sess = ScriptedSession([FakeResp(200, "abcf")])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 4
        clf.false_len = 4
        clf.true_text = "abcd"
        clf.false_text = "abce"
        assert clf.is_true("http://t.test/x", "id", "p") is None

    def test_is_true_exception_returns_none(self):
        sess = ScriptedSession([RuntimeError("boom")])
        clf = ResponseClassifier(sess, 5.0)
        clf.calibrated = True
        clf.true_len = 10
        clf.false_len = 20
        assert clf.is_true("http://t.test/x", "id", "p") is None


class TestAutoDetectSignatures:
    def _detect(self, body):
        injector = BlindInjector(FakeSession(lambda u, k: FakeResp(200, body)), timeout=1.0)
        return injector._auto_detect_dbms("http://t.test/x", "id")

    def test_mysql_signature(self):
        assert self._detect("You have an error in your SQL syntax") == "mysql"

    def test_mssql_signature(self):
        assert self._detect("Microsoft SQL Server driver error") == "mssql"

    def test_postgresql_signature(self):
        assert self._detect("postgresql psql fatal error") == "postgresql"

    def test_oracle_signature(self):
        assert self._detect("ORA-00911: invalid character") == "oracle"


class TestTimeHelpers:
    def test_time_delay_cached(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector._time_ok = True
        assert injector._time_delay_confirmed("http://t.test/x", "id") is True

    def test_time_delay_unknown_dbms(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        assert injector._time_delay_confirmed("http://t.test/x", "id") is False

    def test_time_delay_confirmed(self, monkeypatch):
        monkeypatch.setattr(sqli_blind, "time", FakeTime([0.0, 1.0]))
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.dbms = "mysql"
        assert injector._time_delay_confirmed("http://t.test/x", "id") is True

    def test_time_delay_exception(self):
        injector = BlindInjector(_raising_session(), timeout=1.0)
        injector.dbms = "mysql"
        assert injector._time_delay_confirmed("http://t.test/x", "id") is False

    def test_measure_baseline_exception(self):
        injector = BlindInjector(_raising_session(), timeout=1.0)
        assert injector._measure_baseline("http://t.test/x", "id") == 0.3

    def test_measure_baseline_zero_duration(self, monkeypatch):
        monkeypatch.setattr(sqli_blind, "time", FakeTime([0.0] * 10))
        injector = BlindInjector(FakeSession(), timeout=1.0)
        assert injector._measure_baseline("http://t.test/x", "id") == 0.001

    def test_rate_limit_burst(self, monkeypatch):
        fake_time = FakeTime()
        monkeypatch.setattr(sqli_blind, "time", fake_time)
        monkeypatch.setattr(sqli_blind.random, "uniform", lambda a, b: 0.0)
        injector = BlindInjector(FakeSession(), timeout=1.0)
        for _ in range(50):
            injector._rate_limit()
        assert len(fake_time.sleeps) == 51
        assert fake_time.sleeps[-1] == 1.5

    def test_auto_detect_dbms_timing(self, monkeypatch):
        monkeypatch.setattr(sqli_blind, "time", FakeTime([0.0, 5.0]))
        injector = BlindInjector(
            FakeSession(lambda u, k: FakeResp(200, "hello world")),
            timeout=1.0,
            sleep_time=3,
        )
        assert injector._auto_detect_dbms("http://t.test/x", "id") == "mysql"

    def test_auto_detect_dbms_exception(self):
        injector = BlindInjector(_raising_session(), timeout=1.0)
        assert injector._auto_detect_dbms("http://t.test/x", "id") is None


class TestCharExtraction:
    def _injector(self, monkeypatch):
        monkeypatch.setattr(sqli_blind, "time", FakeTime())
        monkeypatch.setattr(sqli_blind.random, "uniform", lambda a, b: 0.0)
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.dbms = "mysql"
        return injector

    def test_char_bool_unknown_dbms(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.dbms = "unknown"
        assert injector._extract_char_bool("u", "p", "q", 1) is None

    def test_char_bool_binary_search(self, monkeypatch):
        injector = self._injector(monkeypatch)

        def oracle(url, param, payload):
            for c in "ab":
                if "='%s'" % c in payload:
                    return c == "b"
                if ">'%s'" % c in payload:
                    return "b" > c
            return None

        injector.classifier.is_true = oracle
        assert injector._extract_char_bool("u", "p", "q", 1, charset="ab") == "b"

    def test_char_bool_eq_fallback(self, monkeypatch):
        injector = self._injector(monkeypatch)
        injector.classifier.is_true = lambda url, param, payload: (
            "='a'" in payload if ">" not in payload else None
        )
        assert injector._extract_char_bool("u", "p", "q", 1, charset="ab") == "a"

    def test_char_bool_ambiguous_returns_none(self, monkeypatch):
        injector = self._injector(monkeypatch)

        def raising(url, param, payload):
            raise RuntimeError("boom")

        injector.classifier.is_true = raising
        assert injector._extract_char_bool("u", "p", "q", 1, charset="ab") is None

    def test_char_bool_eq_false_narrows_high(self, monkeypatch):
        injector = self._injector(monkeypatch)
        injector.classifier.is_true = lambda url, param, payload: False
        assert injector._extract_char_bool("u", "p", "q", 1, charset="ab") is None

    def test_char_bool_eq_match_after_false_gt(self, monkeypatch):
        injector = self._injector(monkeypatch)
        injector.classifier.is_true = lambda url, param, payload: (
            "='" in payload and ">" not in payload
        )
        assert injector._extract_char_bool("u", "p", "q", 1, charset="ab") == "a"

    def test_char_bool_eq_raises_after_false_gt(self, monkeypatch):
        injector = self._injector(monkeypatch)

        def flaky(url, param, payload):
            if "='" in payload:
                raise RuntimeError("boom")
            return False

        injector.classifier.is_true = flaky
        assert injector._extract_char_bool("u", "p", "q", 1, charset="ab") is None

    def test_char_time_binary_search(self, monkeypatch):
        fake_time = FakeTime([0.0, 2.0, 0.0, 0.0, 0.0, 2.0])
        monkeypatch.setattr(sqli_blind, "time", fake_time)
        monkeypatch.setattr(sqli_blind.random, "uniform", lambda a, b: 0.0)
        injector = BlindInjector(FakeSession(), timeout=1.0, sleep_time=2)
        injector.dbms = "mysql"
        assert injector._extract_char_time("u", "p", "q", 1, charset="ab") == "b"

    def test_char_time_exception_returns_none(self, monkeypatch):
        monkeypatch.setattr(sqli_blind, "time", FakeTime())
        monkeypatch.setattr(sqli_blind.random, "uniform", lambda a, b: 0.0)
        injector = BlindInjector(_raising_session(), timeout=1.0)
        injector.dbms = "mysql"
        assert injector._extract_char_time("u", "p", "q", 1, charset="ab") is None

    def test_string_bool_stops_at_none(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        table = {1: "a", 2: "b"}
        calls = []

        def fake(url, param, query, pos):
            calls.append(pos)
            return table.get(pos)

        injector._extract_char_bool = fake
        assert injector._extract_string_bool("u", "p", "q", max_len=5) == "ab"
        assert calls == [1, 2, 3]

    def test_char_time_unknown_dbms(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.dbms = "unknown"
        assert injector._extract_char_time("u", "p", "q", 1) is None

    def test_string_time_stops_at_none(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector._extract_char_time = lambda url, param, query, pos: "x"
        assert injector._extract_string_time("u", "p", "q", max_len=3) == "xxx"

    def test_string_time_breaks_on_none(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        table = {1: "a", 2: None}
        injector._extract_char_time = lambda url, param, query, pos: table.get(pos)
        assert injector._extract_string_time("u", "p", "q", max_len=5) == "a"


class TestParallelExtraction:
    def test_no_technique(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        assert injector._extract_string_parallel("u", "p", "q") == ""

    def test_zero_max_len(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.tech = BlindTech.BOOLEAN
        assert injector._extract_string_parallel("u", "p", "q", max_len=0) == ""

    def test_boolean_full_run(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.tech = BlindTech.BOOLEAN
        table = {1: "a", 2: "b", 3: "c"}
        injector._extract_char_bool = lambda url, param, query, pos: table.get(pos)
        assert injector._extract_string_parallel("u", "p", "q", max_len=3) == "abc"

    def test_probe_early_abort(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.tech = BlindTech.BOOLEAN
        calls = []

        def fake(url, param, query, pos):
            calls.append(pos)
            return None

        injector._extract_char_bool = fake
        assert injector._extract_string_parallel("u", "p", "q", max_len=4) == ""
        assert calls == [1, 2]

    def test_extract_exception_returns_none(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.tech = BlindTech.BOOLEAN

        def boom(url, param, query, pos):
            raise RuntimeError("boom")

        injector._extract_char_bool = boom
        assert injector._extract_string_parallel("u", "p", "q", max_len=2) == ""

    def test_time_aborts_without_delay(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.tech = BlindTech.TIME
        injector._time_delay_confirmed = lambda url, param: False
        assert injector._extract_string_parallel("u", "p", "q", max_len=2) == ""


class TestErrorExtraction:
    def test_via_error_exception(self):
        injector = BlindInjector(_raising_session(), timeout=1.0)
        injector.dbms = "mysql"
        assert injector._extract_via_error("u", "p", "q") is None

    def test_unknown_dbms_returns_none(self):
        injector = BlindInjector(FakeSession(), timeout=1.0)
        injector.dbms = "db2"
        assert injector._extract_via_error("u", "p", "q") is None

    def test_no_pattern_match_returns_none(self):
        injector = BlindInjector(
            FakeSession(lambda u, k: FakeResp(200, "nothing interesting")), timeout=1.0
        )
        injector.dbms = "mysql"
        assert injector._extract_via_error("u", "p", "q") is None

    def test_error_pattern_match(self):
        body = "XPATH syntax error: '~8.0.32'"
        injector = BlindInjector(FakeSession(lambda u, k: FakeResp(200, body)), timeout=1.0)
        injector.dbms = "mysql"
        assert injector._extract_via_error("u", "p", "@@version") == "8.0.32"


class TestTryDbmsQueries:
    def _injector(self):
        injector = BlindInjector(FakeSession(lambda u, k: FakeResp(200, "ok")), timeout=1.0)
        injector.max_len = 4
        return injector

    def _result(self):
        return {
            "vulnerable": False,
            "dbms": None,
            "technique": None,
            "data": {},
            "error": None,
            "waf_detected": None,
        }

    def test_boolean_success_with_empty_query_skip(self, monkeypatch):
        monkeypatch.setitem(sqli_blind.MYSQL_QUERIES, "empty", None)
        injector = self._injector()
        injector.classifier = CalibrateStub(True)
        injector._extract_string_parallel = lambda url, param, query, ml=None: "8.0.32"
        result = self._result()
        assert injector._try_dbms_queries("http://t.test/x", "q", "mysql", result) is True
        assert result["data"]["version"] == "8.0.32"
        assert result["technique"] == "boolean"
        assert result["vulnerable"] is True

    def test_error_extraction_success(self, monkeypatch):
        monkeypatch.setitem(sqli_blind.MYSQL_QUERIES, "empty", None)
        injector = self._injector()
        injector.classifier = CalibrateStub(False)
        injector._extract_via_error = lambda url, param, query: "5.7.9"
        result = self._result()
        assert injector._try_dbms_queries("http://t.test/x", "q", "mysql", result) is True
        assert result["technique"] == "error"
        assert result["data"]["version"] == "5.7.9"

    def test_time_extraction_success(self, monkeypatch):
        monkeypatch.setitem(sqli_blind.MYSQL_QUERIES, "empty", None)
        injector = self._injector()
        injector.classifier = CalibrateStub(False)
        injector._extract_via_error = lambda url, param, query: None
        injector._extract_string_parallel = lambda url, param, query, ml=None: "8.0.32"
        result = self._result()
        assert injector._try_dbms_queries("http://t.test/x", "q", "mysql", result) is True
        assert result["technique"] == "time"
        assert result["vulnerable"] is True

    def test_custom_queries_override_defaults(self, monkeypatch):
        # 回归: run(queries=...) 的调用方查询现在会注入提取项, 不再被静默忽略.
        monkeypatch.setitem(sqli_blind.MYSQL_QUERIES, "empty", None)
        injector = self._injector()
        injector.classifier = CalibrateStub(True)
        seen = []

        def extract(url, param, query, ml=None):
            seen.append(query)
            return "custom-value"

        injector._extract_string_parallel = extract
        result = self._result()
        assert (
            injector._try_dbms_queries(
                "http://t.test/x", "q", "mysql", result, custom_queries={"custom": "CUSTOM_FN()"}
            )
            is True
        )
        assert "CUSTOM_FN()" in seen
        assert result["data"]["custom"] == "custom-value"

    def test_all_extractions_raise(self):
        injector = self._injector()
        injector.classifier = CalibrateStub(True)

        def boom(*args, **kwargs):
            raise RuntimeError("boom")

        injector._extract_string_parallel = boom
        injector._extract_via_error = boom
        result = self._result()
        assert injector._try_dbms_queries("http://t.test/x", "q", "mysql", result) is False
        assert result["data"] == {}


class TestConfidence:
    def _injector(self):
        return BlindInjector(FakeSession(), timeout=1.0)

    def test_boolean_gap_large(self):
        injector = self._injector()
        injector.classifier.calibrated = True
        injector.classifier.true_len = 100
        injector.classifier.false_len = 10
        result = injector._compute_confidence(
            {
                "vulnerable": True,
                "data": {"version": "8.0"},
                "technique": "boolean",
                "dbms": "mysql",
            }
        )
        assert result["confidence_score"] > 0.7
        assert "bool_length_gap:0.70" in result["confidence_votes"]

    def test_boolean_gap_small(self):
        injector = self._injector()
        injector.classifier.calibrated = True
        injector.classifier.true_len = 25
        injector.classifier.false_len = 10
        result = injector._compute_confidence(
            {
                "vulnerable": True,
                "data": {"version": "8.0"},
                "technique": "boolean",
                "dbms": "mysql",
            }
        )
        assert "bool_length_gap:0.50" in result["confidence_votes"]

    def test_time_confidence(self):
        injector = self._injector()
        injector.baseline_time = 0.1
        injector.sleep_time = 2
        result = injector._compute_confidence(
            {
                "vulnerable": True,
                "data": {"version": "8.0", "user": "root"},
                "technique": "time",
                "dbms": "mysql",
            }
        )
        assert "time_confidence:0.75" in result["confidence_votes"]
        assert "multi_field:0.50" in result["confidence_votes"]

    def test_error_confidence(self):
        injector = self._injector()
        result = injector._compute_confidence(
            {
                "vulnerable": True,
                "data": {"version": "5.7"},
                "technique": "error",
                "dbms": "mysql",
            }
        )
        assert "error_extract:0.85" in result["confidence_votes"]

    def test_not_vulnerable(self):
        injector = self._injector()
        result = injector._compute_confidence(
            {
                "vulnerable": False,
                "data": {},
                "technique": None,
                "dbms": None,
            }
        )
        assert result["confidence_score"] == 0.0
        assert result["confidence"] == "low"


class TestRun:
    def _injector(self):
        return BlindInjector(FakeSession(lambda u, k: FakeResp(200, "ok")), timeout=1.0)

    def test_forced_dbms_success(self):
        injector = self._injector()
        calls = []

        def fake_try(url, param, dbms, result, variants=None, custom_queries=None):
            calls.append(dbms)
            result.update(
                {
                    "vulnerable": True,
                    "data": {"version": "8.0"},
                    "technique": "error",
                }
            )
            return True

        injector._try_dbms_queries = fake_try
        result = injector.run("http://t.test/x?q=1", "q", forced_dbms="oracle", max_len=4)
        assert result["vulnerable"] is True
        assert calls == ["oracle"]
        assert "confidence_score" in result

    def test_auto_detect_and_fallback(self):
        injector = self._injector()
        tried = []

        def fake_try(url, param, dbms, result, variants=None, custom_queries=None):
            tried.append(dbms)
            if dbms == "mssql":
                result.update(
                    {
                        "vulnerable": True,
                        "data": {"version": "x"},
                        "technique": "error",
                    }
                )
                return True
            return False

        injector._auto_detect_dbms = lambda url, param: "mysql"
        injector._try_dbms_queries = fake_try
        result = injector.run("http://t.test/x?q=1", "q", max_len=4)
        assert result["vulnerable"] is True
        assert tried == ["mysql", "mssql"]

    def test_no_dbms_no_data(self):
        injector = self._injector()
        injector._auto_detect_dbms = lambda url, param: None
        injector._try_dbms_queries = lambda *a, **k: False
        result = injector.run("http://t.test/x?q=1", "q", max_len=4)
        assert result["vulnerable"] is False
        assert result["error"]
        assert result["confidence_score"] == 0.0

    def test_waf_variants(self, monkeypatch):
        seen = []

        def fake_gen(raw, name, max_payloads=30):
            seen.append((raw, name))
            return [{"payload": "P1"}, {"payload": ""}]

        monkeypatch.setattr("tools.waf_bypass.generate_sqli_payloads", fake_gen)
        injector = self._injector()
        injector._auto_detect_dbms = lambda url, param: None
        injector._try_dbms_queries = lambda *a, **k: False
        result = injector.run(
            "http://t.test/x?q=1",
            "q",
            max_len=4,
            waf_name="cloudflare",
        )
        assert result["waf_detected"] == "cloudflare"
        assert len(seen) == 2
        assert injector.classifier.baseline_len > 0


class TestOobDns:
    def test_requires_dbms(self, monkeypatch):
        monkeypatch.setattr(
            sqli_blind.BlindInjector, "_auto_detect_dbms", lambda self, url, param: None
        )
        result = check_oob_dns(
            "http://t.test/x", "q", "oob.example", sess=FakeSession(), timeout=1.0
        )
        assert result == {"vulnerable": False, "findings": []}

    def test_unknown_dbms(self, monkeypatch):
        monkeypatch.setattr(
            sqli_blind.BlindInjector,
            "_auto_detect_dbms",
            lambda self, url, param: "db2",
        )
        result = check_oob_dns(
            "http://t.test/x", "q", "oob.example", sess=FakeSession(), timeout=1.0
        )
        assert result["vulnerable"] is False
        assert result["dbms"] == "db2"

    def test_sends_payloads(self, monkeypatch):
        monkeypatch.setattr(
            sqli_blind.BlindInjector,
            "_auto_detect_dbms",
            lambda self, url, param: "mysql",
        )
        sess = FakeSession(lambda u, k: FakeResp(200, "ok"))
        result = check_oob_dns("http://t.test/x", "q", "oob.example", sess=sess, timeout=1.0)
        assert result["vulnerable"] is True
        assert len(result["findings"]) == 3
        assert len(sess.calls) == 3
        assert result["findings"][0]["oob_domain"] == "oob.example"

    def test_send_exception(self, monkeypatch):
        monkeypatch.setattr(
            sqli_blind.BlindInjector,
            "_auto_detect_dbms",
            lambda self, url, param: "mysql",
        )
        sess = _raising_session()
        result = check_oob_dns("http://t.test/x", "q", "oob.example", sess=sess, timeout=1.0)
        assert result["vulnerable"] is False
        assert result["findings"] == []


class TestCheck:
    def test_defaults_when_run_returns_empty(self, monkeypatch):
        monkeypatch.setattr(sqli_blind.BlindInjector, "run", lambda self, *a, **k: {})
        monkeypatch.setattr(
            sqli_blind, "fingerprint_waf", lambda url, sess, timeout: {"name": None}
        )
        result = check("http://t.test/x?q=1", "q", sess=FakeSession(), timeout=1.0)
        assert result["confidence_score"] == 0.0
        assert result["confidence"] == "low"
        assert result["confidence_votes"] == []

    def test_waf_detected(self, monkeypatch):
        seen = {}

        def fake_run(self, url, param, queries, waf_name=None):
            seen["waf_name"] = waf_name
            return {}

        monkeypatch.setattr(
            sqli_blind, "fingerprint_waf", lambda url, sess, timeout: {"name": "cloudflare"}
        )
        monkeypatch.setattr(sqli_blind.BlindInjector, "run", fake_run)
        check("http://t.test/x?q=1", "q", sess=FakeSession(), timeout=1.0)
        assert seen["waf_name"] == "cloudflare"

    def test_waf_detection_error(self, monkeypatch):
        def boom(url, sess, timeout):
            raise RuntimeError("no waf lib")

        monkeypatch.setattr(sqli_blind, "fingerprint_waf", boom)
        monkeypatch.setattr(sqli_blind.BlindInjector, "run", lambda self, *a, **k: {})
        result = check("http://t.test/x?q=1", "q", sess=FakeSession(), timeout=1.0)
        assert result["confidence_score"] == 0.0

    def test_auto_detect_waf_disabled(self, monkeypatch):
        called = {"n": 0}

        def fake_fingerprint(url, sess, timeout):
            called["n"] += 1
            return {"name": "cloudflare"}

        monkeypatch.setattr(sqli_blind, "fingerprint_waf", fake_fingerprint)
        monkeypatch.setattr(sqli_blind.BlindInjector, "run", lambda self, *a, **k: {})
        check(
            "http://t.test/x?q=1",
            "q",
            sess=FakeSession(),
            timeout=1.0,
            auto_detect_waf=False,
        )
        assert called["n"] == 0

    def test_session_created(self, monkeypatch):
        monkeypatch.setattr(sqli_blind.BlindInjector, "run", lambda self, *a, **k: {})
        monkeypatch.setattr(
            sqli_blind, "fingerprint_waf", lambda url, sess, timeout: {"name": None}
        )
        result = check("http://t.test/x?q=1", "q", timeout=1.0)
        assert "confidence_score" in result

    def test_oob_dns_session_created(self, monkeypatch):
        monkeypatch.setattr(
            sqli_blind.BlindInjector,
            "_auto_detect_dbms",
            lambda self, url, param: None,
        )
        result = check_oob_dns("http://t.test/x", "q", "oob.example", timeout=1.0)
        assert result["vulnerable"] is False
