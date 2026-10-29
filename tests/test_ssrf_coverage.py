import os
from unittest import mock

from tools import ssrf_chain, ssrf_pwn


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

    def _do(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        if self.handler is None:
            return FakeResp()
        return self.handler(method, url, kwargs)

    def get(self, url, **kwargs):
        return self._do("GET", url, kwargs)

    def put(self, url, **kwargs):
        return self._do("PUT", url, kwargs)


def _handler_raises(method, url, kwargs):
    raise RuntimeError("network down")


class TestHelpers:
    def test_build_url_without_query(self):
        assert ssrf_pwn._build_url("http://t.test/x", "url", "file:///etc/passwd") == (
            "http://t.test/x?url=file:///etc/passwd"
        )

    def test_build_url_with_query(self):
        assert ssrf_pwn._build_url("http://t.test/x?a=1", "url", "gopher://x") == (
            "http://t.test/x?a=1&url=gopher://x"
        )


class TestCheckFileRead:
    def test_found(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * 60))
        results = ssrf_pwn.check_file_read("http://t.test/fetch", "url", sess=sess)
        assert len(results) == 2
        assert all(r["size"] == 60 for r in results)
        assert all("target" in r for r in results)

    def test_too_short(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "ok"))
        assert ssrf_pwn.check_file_read("http://t.test/fetch", "url", sess=sess) == []

    def test_exception(self):
        sess = FakeSession(_handler_raises)
        assert ssrf_pwn.check_file_read("http://t.test/fetch", "url", sess=sess) == []


class TestCheckCloudMetadata:
    def test_cloud_evidence(self):
        body = "ami-id: ami-1 vmId: 42 google computeMetadata"
        sess = FakeSession(lambda m, u, k: FakeResp(200, body))
        result = ssrf_pwn.check_cloud_metadata("http://t.test/fetch", "url", sess=sess)
        assert set(result) == {"aws", "gcp", "azure"}
        assert result["aws"]["size"] == len(body)

    def test_no_match(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "ok"))
        assert ssrf_pwn.check_cloud_metadata("http://t.test/fetch", "url", sess=sess) == {}

    def test_exception(self):
        sess = FakeSession(_handler_raises)
        assert ssrf_pwn.check_cloud_metadata("http://t.test/fetch", "url", sess=sess) == {}


class TestPortScan:
    def test_default_ports_all_open(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * 30))
        results = ssrf_pwn.SSRFLateral(sess, 1.0).port_scan("http://t.test/fetch", "url")
        assert len(results) == 10
        assert {r["port"] for r in results} == {
            22,
            80,
            443,
            3306,
            6379,
            8080,
            9200,
            27017,
            11211,
            5000,
        }

    def test_filters_status_and_short_body(self):
        def handler(method, url, kwargs):
            if ":22/" in url:
                return FakeResp(502, "x" * 30)
            return FakeResp(200, "short")

        sess = FakeSession(handler)
        results = ssrf_pwn.SSRFLateral(sess, 1.0).port_scan(
            "http://t.test/fetch", "url", ports=[22, 80]
        )
        assert results == []

    def test_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).port_scan("http://t.test/fetch", "url", ports=[22])
            == []
        )


class TestImdsv2:
    def test_success(self):
        def handler(method, url, kwargs):
            if method == "PUT":
                return FakeResp(200, "TOKEN-ABC\n")
            if "user-data" in url:
                raise RuntimeError("blocked")
            return FakeResp(200, "meta " * 10)

        sess = FakeSession(handler)
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_aws_imdsv2("http://t.test/fetch", "url")
        assert result["imdsv2_token"] == "TOKEN-ABC"
        assert len(result) == 3
        assert result["http://169.254.169.254/latest/meta-data/"] == "meta " * 10

    def test_put_status_not_200(self):
        sess = FakeSession(lambda m, u, k: FakeResp(500, "no"))
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_aws_imdsv2("http://t.test/fetch", "url") == {}
        )

    def test_put_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_aws_imdsv2("http://t.test/fetch", "url") == {}
        )


class TestK8sDockerSpring:
    def test_kubernetes(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * 60))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_kubernetes("http://t.test/fetch", "url")
        assert len(result) == 5

    def test_kubernetes_forbidden_counts(self):
        sess = FakeSession(lambda m, u, k: FakeResp(403, "x" * 60))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_kubernetes("http://t.test/fetch", "url")
        assert len(result) == 5
        assert result["http://kubernetes.default.svc/api/v1/nodes"]["status"] == 403

    def test_kubernetes_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_kubernetes("http://t.test/fetch", "url") == {}
        )

    def test_docker(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * 30))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_docker("http://t.test/fetch", "url")
        assert len(result) == 5

    def test_docker_exception(self):
        sess = FakeSession(_handler_raises)
        assert ssrf_pwn.SSRFLateral(sess, 1.0).exploit_docker("http://t.test/fetch", "url") == {}

    def test_spring(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * 30))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_spring_actuator(
            "http://t.test/fetch", "url"
        )
        assert len(result) == 5

    def test_spring_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_spring_actuator("http://t.test/fetch", "url")
            == {}
        )


class TestEsMemcachedMysql:
    def test_elasticsearch_json_dict(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "", json_data={"status": 200}))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_elasticsearch("http://t.test/fetch", "url")
        assert result["http://127.0.0.1:9200/"] == ["status"]

    def test_elasticsearch_json_list(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "", json_data=[1, 2]))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_elasticsearch("http://t.test/fetch", "url")
        assert result["http://127.0.0.1:9200/"] == "json"

    def test_elasticsearch_plain_text(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "z" * 150))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_elasticsearch("http://t.test/fetch", "url")
        assert result["http://127.0.0.1:9200/"] == "z" * 100

    def test_elasticsearch_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_elasticsearch("http://t.test/fetch", "url")
            == {}
        )

    def test_memcached(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "STAT curr_items 3"))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_memcached("http://t.test/fetch", "url")
        assert "memcached" in result

    def test_memcached_short(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "ok"))
        assert ssrf_pwn.SSRFLateral(sess, 1.0).exploit_memcached("http://t.test/fetch", "url") == {}

    def test_memcached_exception(self):
        sess = FakeSession(_handler_raises)
        assert ssrf_pwn.SSRFLateral(sess, 1.0).exploit_memcached("http://t.test/fetch", "url") == {}

    def test_mysql(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "mysql handshake"))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_mysql_ssrf("http://t.test/fetch", "url")
        assert "mysql_probe" in result

    def test_mysql_short(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "ok"))
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_mysql_ssrf("http://t.test/fetch", "url") == {}
        )

    def test_mysql_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_mysql_ssrf("http://t.test/fetch", "url") == {}
        )


class TestGopherAndBypass:
    def test_gopher_protocols(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * 30))
        result = ssrf_pwn.SSRFLateral(sess, 1.0).exploit_gopher_protocols(
            "http://t.test/fetch", "url"
        )
        assert len(result) == 10
        assert "redis_info" in result
        assert "fastcgi_phpinfo" in result

    def test_gopher_protocols_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).exploit_gopher_protocols("http://t.test/fetch", "url")
            == {}
        )

    def test_bypass_variants(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * 60))
        results = ssrf_pwn.SSRFLateral(sess, 1.0).bypass_filter_variants(
            "http://t.test/fetch", "url"
        )
        assert len(results) == 12
        assert all(r["size"] == 60 for r in results)

    def test_bypass_variants_filtered(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "tiny"))
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).bypass_filter_variants("http://t.test/fetch", "url")
            == []
        )

    def test_bypass_variants_exception(self):
        sess = FakeSession(_handler_raises)
        assert (
            ssrf_pwn.SSRFLateral(sess, 1.0).bypass_filter_variants("http://t.test/fetch", "url")
            == []
        )


class TestRunAndCheck:
    def _open_session(self):
        return FakeSession(lambda m, u, k: FakeResp(200, "x" * 60))

    def test_run_all(self):
        sess = self._open_session()
        result = ssrf_pwn.SSRFLateral(sess, 1.0).run("http://t.test/fetch", "url")
        assert len(result["port_scan"]) == 10
        assert len(result["kubernetes"]) == 5
        assert len(result["docker"]) == 5
        assert len(result["elasticsearch"]) == 3
        assert "memcached" in result["memcached"]
        assert "mysql_probe" in result["mysql"]
        assert len(result["spring_actuator"]) == 5
        assert len(result["bypass_variants"]) == 12
        assert len(result["gopher_protocols"]) == 10
        assert result["imdsv2"]["imdsv2_token"] == "x" * 20
        assert set(result["cloud_metadata"]) == {"aws", "gcp", "azure", "do", "alibaba"}

    def test_run_module_function(self):
        sess = self._open_session()
        result = ssrf_pwn.run("http://t.test/fetch", "url", sess=sess)
        assert "port_scan" in result

    def test_check_vulnerable(self):
        sess = self._open_session()
        result = ssrf_pwn.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is True
        assert len(result["files"]) == 2
        assert len(result["findings"]) == 3
        assert set(result["internal_services"]) == {"port_scan", "bypass_variants"}

    def test_check_clean(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "ok"))
        result = ssrf_pwn.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is False
        assert result["findings"] == []
        assert result["internal_services"] == {}

    def test_run_cloud_loop_exception(self):
        def handler(method, url, kwargs):
            if "100.100.100.200" in url:
                raise RuntimeError("blocked")
            return FakeResp(200, "x" * 60)

        sess = FakeSession(handler)
        result = ssrf_pwn.SSRFLateral(sess, 1.0).run("http://t.test/fetch", "url")
        assert "aws" in result["cloud_metadata"]
        assert "alibaba" not in result["cloud_metadata"]


class TestSessionDefaults:
    def test_check_file_read_creates_session(self):
        fake = FakeSession(lambda m, u, k: FakeResp(200, "x" * 60))
        with mock.patch("tools.ssrf_pwn.requests.Session", return_value=fake):
            results = ssrf_pwn.check_file_read("http://t.test/fetch", "url")
        assert len(results) == 2

    def test_check_cloud_metadata_creates_session(self):
        fake = FakeSession(lambda m, u, k: FakeResp(200, "ami-id: ami-1 " + "x" * 20))
        with mock.patch("tools.ssrf_pwn.requests.Session", return_value=fake):
            result = ssrf_pwn.check_cloud_metadata("http://t.test/fetch", "url")
        assert "aws" in result

    def test_check_creates_session(self):
        fake = FakeSession(lambda m, u, k: FakeResp(200, "x" * 60))
        with mock.patch("tools.ssrf_pwn.requests.Session", return_value=fake):
            result = ssrf_pwn.check("http://t.test/fetch", "url", timeout=1.0)
        assert result["vulnerable"] is True


def _svc(host, port, proto):
    return {"host": host, "port": port, "protocol": proto}


class TestChainDataclasses:
    def test_hop_result_defaults(self):
        hop = ssrf_chain.HopResult(hop=1, protocol="redis", target="h:1", port=1, success=False)
        assert hop.response_preview == ""
        assert hop.chain_path == []

    def test_chain_result_defaults(self):
        res = ssrf_chain.SSRFChainResult(target="t", param="p")
        assert res.hops == []
        assert res.rce_achieved is False
        assert res.cloud_creds is None


class TestDiscovery:
    def test_finds_all_services(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x"))
        found = ssrf_chain.SSRFChainEngine(sess, 1.0)._discover_internal_services(
            "http://t.test/fetch?url=X", "url"
        )
        assert len(found) == len(ssrf_chain.INTERNAL_SERVICES)
        assert found[0]["host"] == "127.0.0.1"
        assert found[0]["protocol"] == "HTTP"
        assert found[0]["preview"] == "x"

    def test_filters_failures(self):
        def handler(method, url, kwargs):
            if "gopher://" in url:
                raise RuntimeError("no gopher")
            return FakeResp(502, "x")

        sess = FakeSession(handler)
        found = ssrf_chain.SSRFChainEngine(sess, 1.0)._discover_internal_services(
            "http://t.test/fetch?url=X", "url"
        )
        assert found == []


class TestChainRedis:
    def test_info_leak_and_evidence(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "redis_version:7.0.11\r\n"))
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        hop = engine._chain_redis("http://t.test/fetch?url=X", "url", "127.0.0.1", 6379)
        assert hop.success is True
        assert hop.chain_path == ["redis_info_leak"]
        result = ssrf_chain.SSRFChainResult(target="t", param="url")
        engine._extract_redis_evidence(hop, result)
        assert result.evidence == [{"type": "redis_version_leak", "version": "7.0.11", "hop": 1}]

    def test_ssh_key_injection(self, monkeypatch):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "generic response"))
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        monkeypatch.setattr(engine, "_get_ssh_key", lambda: "ssh-rsa AAA")
        hop = engine._chain_redis("http://t.test/fetch?url=X", "url", "127.0.0.1", 6379)
        assert hop.success is True
        assert hop.hop == 2
        assert "redis_ssh_key_inject" in hop.chain_path
        assert "ssh-rsa" in sess.calls[-1][1]
        result = ssrf_chain.SSRFChainResult(target="t", param="url")
        engine._extract_redis_evidence(hop, result)
        assert result.rce_achieved is True
        assert result.rce_method == "redis_gopher_ssh"
        assert result.ssh_keys == ["redis_authorized_keys_injected"]

    def test_failure_when_no_key(self, monkeypatch):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "generic response"))
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        monkeypatch.setattr(engine, "_get_ssh_key", lambda: "")
        hop = engine._chain_redis("http://t.test/fetch?url=X", "url", "127.0.0.1", 6379)
        assert hop.success is False
        assert hop.error == "redis_access_failed"

    def test_exception_then_no_key(self, monkeypatch):
        sess = FakeSession(_handler_raises)
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        monkeypatch.setattr(engine, "_get_ssh_key", lambda: "")
        hop = engine._chain_redis("http://t.test/fetch?url=X", "url", "127.0.0.1", 6379)
        assert hop.success is False

    def test_ssh_injection_request_exception(self, monkeypatch):
        calls = {"n": 0}

        def handler(method, url, kwargs):
            calls["n"] += 1
            if calls["n"] > 1:
                raise RuntimeError("blocked")
            return FakeResp(200, "generic response")

        sess = FakeSession(handler)
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        monkeypatch.setattr(engine, "_get_ssh_key", lambda: "ssh-rsa AAA")
        hop = engine._chain_redis("http://t.test/fetch?url=X", "url", "127.0.0.1", 6379)
        assert hop.success is False
        assert hop.error == "redis_access_failed"


class TestChainSql:
    def test_mysql_version(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "MySQL 5.7.31-log x"))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_sql(
            "http://t.test/fetch?url=X", "url", "127.0.0.1", 3306, "MySQL"
        )
        assert hop.success is True
        assert hop.response_preview == "5.7.31-log"
        assert hop.chain_path == ["sql_version_leak"]

    def test_postgres_and_mssql_payloads(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "no version here"))
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        assert engine._chain_sql("u", "url", "h", 5432, "PostgreSQL").success is False
        assert engine._chain_sql("u", "url", "h", 1433, "MSSQL").success is False

    def test_unknown_protocol_falls_back_to_mysql(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "1.2.3 build"))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_sql("u", "url", "h", 1521, "Oracle")
        assert hop.success is True
        assert hop.protocol == "oracle"

    def test_no_version(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "nothing"))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_sql("u", "url", "h", 3306, "MySQL")
        assert hop.success is False
        assert hop.error == "sql_probe_failed"

    def test_exception(self):
        sess = FakeSession(_handler_raises)
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_sql("u", "url", "h", 3306, "MySQL")
        assert hop.success is False


class TestChainDocker:
    def test_containers_list_success(self):
        # 修复: (name, path) 正确解包, 探测 URL 为 :2375/containers/json,
        # 列表响应即 Docker API 可达.
        sess = FakeSession(lambda m, u, k: FakeResp(200, "[]", json_data=[{"Id": "1"}]))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_docker(
            "http://t.test/fetch?url=X", "url", "127.0.0.1", 2375
        )
        assert hop.success is True
        assert hop.chain_path == ["docker_containers"]
        assert any("2375/containers/json" in call[1] for call in sess.calls)
        assert not any("2375containers" in call[1] for call in sess.calls)

    def test_non_list_json_does_not_succeed(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "{}", json_data={"ok": True}))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_docker(
            "http://t.test/fetch?url=X", "url", "127.0.0.1", 2375
        )
        assert hop.success is False
        assert hop.error == "docker_api_failed"
        assert "docker_containers" in hop.chain_path

    def test_non_json_body(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "not json"))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_docker(
            "http://t.test/fetch?url=X", "url", "127.0.0.1", 2375
        )
        assert hop.success is False
        assert hop.chain_path == []

    def test_exception(self):
        sess = FakeSession(_handler_raises)
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_docker(
            "http://t.test/fetch?url=X", "url", "127.0.0.1", 2375
        )
        assert hop.success is False


class TestChainK8s:
    def test_success(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "{}", json_data={"major": "1"}))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_k8s("u", "url", "127.0.0.1", 6443)
        assert hop.success is True
        assert hop.chain_path == ["k8s_api"]

    def test_non_json(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "not json"))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_k8s("u", "url", "127.0.0.1", 6443)
        assert hop.success is False
        assert hop.error == "k8s_probe_failed"

    def test_exception(self):
        sess = FakeSession(_handler_raises)
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_k8s("u", "url", "127.0.0.1", 6443)
        assert hop.success is False


class TestChainElasticsearch:
    def test_cluster_name(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "{}", json_data={"cluster_name": "prod"}))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_elasticsearch(
            "u", "url", "127.0.0.1", 9200
        )
        assert hop.success is True

    def test_json_without_markers(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "{}", json_data={"ok": 1}))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_elasticsearch(
            "u", "url", "127.0.0.1", 9200
        )
        assert hop.success is False

    def test_html_leak(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "You know, for Elastic Search"))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_elasticsearch(
            "u", "url", "127.0.0.1", 9200
        )
        assert hop.success is True
        assert "es_html_leak" in hop.chain_path

    def test_plain_text(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "zzz"))
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_elasticsearch(
            "u", "url", "127.0.0.1", 9200
        )
        assert hop.success is False

    def test_exception(self):
        sess = FakeSession(_handler_raises)
        hop = ssrf_chain.SSRFChainEngine(sess, 1.0)._chain_elasticsearch(
            "u", "url", "127.0.0.1", 9200
        )
        assert hop.success is False


class TestGetSshKey:
    def test_reads_existing_key(self, tmp_path, monkeypatch):
        key_file = tmp_path / "id_rsa.pub"
        key_file.write_text("ssh-rsa REALKEY\n", encoding="utf-8")
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(key_file))
        sess = FakeSession()
        key = ssrf_chain.SSRFChainEngine(sess, 1.0)._get_ssh_key()
        assert key == "ssh-rsa REALKEY"

    def test_fallback_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(tmp_path / "missing.pub"))
        sess = FakeSession()
        key = ssrf_chain.SSRFChainEngine(sess, 1.0)._get_ssh_key()
        assert key.startswith("ssh-rsa AAAAB3NzaC1yc2E")


def _mixed_handler(method, url, kwargs):
    if "6379" in url:
        return FakeResp(200, "redis_version:6.2.6\r\n")
    if "UNION" in url:
        return FakeResp(200, "MySQL 5.7.31-log")
    if "2375" in url:
        return FakeResp(200, "[{}]", json_data=[{"Id": "abc"}])
    if "6443" in url:
        return FakeResp(200, "{}", json_data={"major": "1"})
    if "9200" in url:
        return FakeResp(200, "{}", json_data={"cluster_name": "prod"})
    return FakeResp(200, "")


class TestChainFull:
    def test_mixed_services(self, monkeypatch):
        sess = FakeSession(_mixed_handler)
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        services = [
            _svc("127.0.0.1", 6379, "Redis"),
            _svc("127.0.0.1", 3306, "MySQL"),
            _svc("127.0.0.1", 6443, "K8s-API"),
            _svc("127.0.0.1", 9200, "Elasticsearch"),
            _svc("127.0.0.1", 80, "HTTP"),
        ]
        monkeypatch.setattr(engine, "_discover_internal_services", lambda u, p: services)
        result = engine.chain_full("http://t.test/fetch?url=X", "url", max_hops=3)
        assert result.total_hops == 4
        assert result.max_depth_reached == 1
        assert result.evidence[0]["type"] == "redis_version_leak"

    def test_docker_rce_branch(self, monkeypatch):
        sess = FakeSession(_mixed_handler)
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        services = [_svc("127.0.0.1", 2375, "Docker")]

        def fake_docker(base_url, param, host, port):
            return ssrf_chain.HopResult(
                hop=1,
                protocol="docker",
                target="%s:%d" % (host, port),
                port=port,
                success=True,
            )

        monkeypatch.setattr(engine, "_discover_internal_services", lambda u, p: services)
        monkeypatch.setattr(engine, "_chain_docker", fake_docker)
        result = engine.chain_full("http://t.test/fetch?url=X", "url", max_hops=1)
        assert result.rce_achieved is True
        assert result.rce_method == "docker_api"
        assert result.max_depth_reached == 1

    def test_dedup_across_depths(self, monkeypatch):
        sess = FakeSession(_mixed_handler)
        engine = ssrf_chain.SSRFChainEngine(sess, 1.0)
        monkeypatch.setattr(
            engine,
            "_discover_internal_services",
            lambda u, p: [_svc("127.0.0.1", 6379, "Redis")],
        )
        result = engine.chain_full("http://t.test/fetch?url=X", "url", max_hops=3)
        assert result.total_hops == 1
        assert result.max_depth_reached == 1


class TestChainSsrfWrapper:
    def test_no_services(self, monkeypatch):
        monkeypatch.setattr(
            ssrf_chain.SSRFChainEngine,
            "_discover_internal_services",
            lambda self, base_url, param: [],
        )
        sess = FakeSession()
        result = ssrf_chain.chain_ssrf("http://t.test/fetch?url=X", "url", sess, timeout=1.0)
        assert result["success"] is False
        assert result["total_hops"] == 0
        assert result["services_found"] == 0

    def test_with_redis(self, monkeypatch):
        monkeypatch.setattr(
            ssrf_chain.SSRFChainEngine,
            "_discover_internal_services",
            lambda self, base_url, param: [_svc("127.0.0.1", 6379, "Redis")],
        )
        sess = FakeSession(lambda m, u, k: FakeResp(200, "redis_version:6.0.0"))
        result = ssrf_chain.chain_ssrf(
            "http://t.test/fetch?url=X", "url", sess, timeout=1.0, max_hops=1
        )
        assert result["success"] is True
        assert result["services_found"] == 1
        assert result["hops"][0]["protocol"] == "redis"
        assert result["hops"][0]["preview"]
