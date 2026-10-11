"""Offline coverage tests for tools/context_memory.py.

Time is frozen/patched via tools.context_memory.time; storage is a MagicMock.
"""
from unittest.mock import MagicMock, patch

import pytest

from tools.context_memory import ContextMemory, MemoryEntry, get_memory


@pytest.fixture(autouse=True)
def _fresh_singleton():
    ContextMemory._instance = None
    yield
    ContextMemory._instance = None


def _frozen_time(value=1000.0):
    fake = MagicMock()
    fake.time.return_value = value
    return fake


class TestMemoryEntry:
    def test_is_expired_with_frozen_time(self):
        with patch("tools.context_memory.time", _frozen_time(1000.0)):
            entry = MemoryEntry(key="k", value="v", source="s", confidence=0.8,
                                timestamp=900.0, ttl=50.0)
            assert entry.is_expired() is True
            fresh = MemoryEntry(key="k", value="v", source="s", confidence=0.8,
                                timestamp=990.0, ttl=50.0)
            assert fresh.is_expired() is False

    def test_to_dict(self):
        with patch("tools.context_memory.time", _frozen_time(1000.0)):
            entry = MemoryEntry(key="k", value=[1, 2], source="s", confidence=0.85,
                                timestamp=900.0, tags=["a"])
            data = entry.to_dict()
        assert data == {
            "key": "k", "value": [1, 2], "source": "s",
            "confidence": 0.85, "age_seconds": 100.0, "tags": ["a"],
        }


class TestBasics:
    def test_singleton_and_helper(self):
        first = ContextMemory()
        assert get_memory() is first

    def test_set_get_entry_has_delete(self):
        memory = ContextMemory()
        memory.set("dbms", "MySQL", source="sqli", confidence=0.9, tags=["t"])
        assert memory.get("dbms") == "MySQL"
        entry = memory.get_entry("dbms")
        assert entry is not None and entry.source == "sqli" and entry.tags == ["t"]
        assert memory.has("dbms") is True
        assert memory.has("missing") is False
        memory.delete("dbms")
        assert memory.get("dbms") is None
        assert memory.get_entry("dbms") is None

    def test_get_missing_returns_default(self):
        assert ContextMemory().get("nope", "fallback") == "fallback"

    def test_clear_removes_store_and_history(self):
        memory = ContextMemory()
        memory.set("a", 1)
        memory.set("b", 2)
        memory.clear()
        assert memory.all_keys() == []
        assert memory.get_stats()["history_size"] == 0

    def test_confidence_precedence(self):
        memory = ContextMemory()
        memory.set("dbms", "MySQL", confidence=0.9)
        memory.set("dbms", "weaker", confidence=0.5)
        assert memory.get("dbms") == "MySQL"
        memory.set("dbms", "stronger", confidence=0.95)
        assert memory.get("dbms") == "stronger"

    def test_ttl_expiry_removes_key_on_get(self):
        memory = ContextMemory()
        fake = _frozen_time(1000.0)
        with patch("tools.context_memory.time", fake):
            memory.set("temp", "value", ttl=10.0)
            assert memory.has("temp") is True
            fake.time.return_value = 2000.0
            assert memory.get("temp", "gone") == "gone"
        assert "temp" not in memory._store

    def test_expired_entries_excluded_from_reads(self):
        memory = ContextMemory()
        fake = _frozen_time(1000.0)
        with patch("tools.context_memory.time", fake):
            memory.set("short", 1, ttl=10.0)
            memory.set("long", 2, ttl=1000.0)
            fake.time.return_value = 1100.0
            assert memory.all_keys() == ["long"]
            assert "short" not in memory.snapshot()
            assert memory.get_entry("short") is None
            assert memory.has("short") is False

    def test_cleanup_and_stats(self):
        memory = ContextMemory()
        fake = _frozen_time(1000.0)
        with patch("tools.context_memory.time", fake):
            memory.set("short", 1, ttl=10.0)
            memory.set("long", 2, ttl=1000.0)
            fake.time.return_value = 2000.0
            assert memory.cleanup() == 1
            assert memory.cleanup() == 0
            stats = memory.get_stats()
        assert stats["total_entries"] == 1
        assert stats["active_entries"] == 1
        assert stats["expired_entries"] == 0
        assert stats["keys"] == ["long"]


class TestRestore:
    def test_restore_defaults_and_confidence_gate(self):
        memory = ContextMemory()
        with patch("tools.context_memory.time", _frozen_time(1000.0)):
            memory.set("existing", "strong", source="x", confidence=0.9)
            memory.restore({
                "existing": {"value": "weak", "confidence": 0.5},
                "plain": {"value": 42},
                "tagged": {"value": "v", "source": "backup", "confidence": 0.7,
                           "timestamp": 980.0, "ttl": 500.0, "tags": ["t"]},
            })
            assert memory.get("existing") == "strong"
            assert memory.get("plain") == 42
            plain_entry = memory.get_entry("plain")
            assert plain_entry.source == "restored"
            assert plain_entry.confidence == 0.8
            tagged = memory.get_entry("tagged")
            assert tagged is not None and tagged.tags == ["t"]

    def test_restore_higher_confidence_overwrites(self):
        memory = ContextMemory()
        memory.set("k", "weak", confidence=0.4)
        memory.restore({"k": {"value": "strong", "confidence": 0.9}})
        assert memory.get("k") == "strong"


class TestStorage:
    def test_auto_save_calls_storage(self):
        memory = ContextMemory()
        storage = MagicMock()
        memory.set_storage(storage)
        memory.set("dbms", "MySQL", source="sqli", confidence=0.9, tags=["t"])
        storage.save_context.assert_called_once_with("dbms", "MySQL", "sqli", 0.9, ["t"])

    def test_auto_save_disabled(self):
        memory = ContextMemory()
        storage = MagicMock()
        memory.set_storage(storage, auto_save=False)
        memory.set("k", "v")
        storage.save_context.assert_not_called()

    def test_storage_errors_are_swallowed(self):
        memory = ContextMemory()
        storage = MagicMock()
        storage.save_context.side_effect = RuntimeError("disk full")
        memory.set_storage(storage)
        memory.set("k", "v")
        assert memory.get("k") == "v"


class TestSuggestions:
    def test_sqli(self):
        memory = ContextMemory()
        memory.set("dbms", "MySQL 8.0")
        memory.set("waf", "Cloudflare")
        memory.set("db_creds", {"user": "root"})
        suggestions = memory.get_suggestions("sqli")
        assert suggestions == {
            "dbms": "MySQL 8.0", "dialect": "mysql",
            "waf": "Cloudflare", "bypass_strategy": "cloudflare_bypass",
            "use_credentials": {"user": "root"},
        }

    def test_sqli_empty(self):
        assert ContextMemory().get_suggestions("sqli") == {}

    def test_ssti(self):
        memory = ContextMemory()
        memory.set("framework", "Spring Boot")
        memory.set("language", "java")
        assert memory.get_suggestions("ssti") == {
            "framework": "Spring Boot", "template_engine": "spel", "language": "java"}

    def test_ssrf(self):
        memory = ContextMemory()
        memory.set("cloud_provider", "AWS")
        memory.set("internal_services", ["http://10.0.0.5"])
        suggestions = memory.get_suggestions("ssrf")
        assert suggestions["cloud_provider"] == "AWS"
        assert suggestions["metadata_url"] == "http://169.254.169.254/latest/meta-data/"
        assert suggestions["internal_targets"] == ["http://10.0.0.5"]

    def test_cmdi(self):
        memory = ContextMemory()
        memory.set("os_type", "windows", confidence=0.95)
        assert memory.get_suggestions("cmdi") == {"os": "windows", "shell": "cmd"}
        memory.set("os_type", "linux", confidence=0.99)
        assert memory.get_suggestions("cmdi") == {"os": "linux", "shell": "bash"}

    def test_lfi(self):
        memory = ContextMemory()
        memory.set("os_type", "linux")
        memory.set("web_root", "/var/www")
        memory.set("php_version", "8.1")
        suggestions = memory.get_suggestions("lfi")
        assert suggestions["os"] == "linux"
        assert suggestions["web_root"] == "/var/www"
        assert suggestions["php_version"] == "8.1"
        assert "php://filter/convert.base64-encode/resource=" in suggestions["wrappers"]

    def test_auth_and_exploit(self):
        memory = ContextMemory()
        memory.set("creds", {"user": "admin"})
        memory.set("session_token", "tok")
        memory.set("ssh_keys", ["key"])
        memory.set("cloud_creds", {"ak": "sk"})
        assert memory.get_suggestions("auth") == {
            "credentials": {"user": "admin"}, "session": "tok"}
        assert memory.get_suggestions("exploit") == {
            "credentials": {"user": "admin"}, "ssh_keys": ["key"],
            "cloud_credentials": {"ak": "sk"}}

    def test_unknown_module(self):
        assert ContextMemory().get_suggestions("misc") == {}


class TestAutoLearn:
    def test_rules_recorded_per_key(self):
        memory = ContextMemory()
        memory.set("dbms", "PostgreSQL")
        memory.set("framework", "Django")
        memory.set("waf", "Akamai")
        memory.set("os_type", "linux")
        stats = memory.get_stats()
        assert stats["learnt_rules"] == {
            "sqli_dialect": 1, "ssti_engine": 1, "waf_bypass": 1, "os_specific": 1}
        assert memory._learnt_rules["sqli_dialect"][0]["dialect"] == "postgresql"
        assert memory._learnt_rules["ssti_engine"][0]["engine"] == "django_template"
        assert memory._learnt_rules["waf_bypass"][0]["strategy"] == "akamai_bypass"
        assert memory._learnt_rules["os_specific"][0]["os"] == "linux"

    def test_non_string_value_is_ignored(self):
        memory = ContextMemory()
        memory.set("dbms", 123)
        assert memory.get_stats()["learnt_rules"] == {}

    def test_unrelated_key_is_ignored(self):
        memory = ContextMemory()
        memory.set("other", "value")
        assert memory.get_stats()["learnt_rules"] == {}


class TestMappings:
    def test_dbms_to_dialect(self):
        memory = ContextMemory()
        cases = {
            "MySQL 8.0": "mysql",
            "PostgreSQL": "postgresql",
            "psql 14": "postgresql",
            "MSSQL": "mssql",
            "SQL Server 2019": "mssql",
            "Oracle Database": "oracle",
            "SQLite3": "sqlite",
            "MongoDB": "mongodb",
            "Mongo": "mongodb",
            "Unknown": "generic",
        }
        for name, expected in cases.items():
            assert memory._dbms_to_dialect(name) == expected

    def test_waf_to_strategy(self):
        memory = ContextMemory()
        cases = {
            "Cloudflare": "cloudflare_bypass",
            "Akamai": "akamai_bypass",
            "ModSecurity": "modsec_bypass",
            "AWS WAF": "aws_waf_bypass",
            "Imperva": "imperva_bypass",
            "F5 BIG-IP": "f5_bypass",
            "Unknown": "generic_bypass",
        }
        for name, expected in cases.items():
            assert memory._waf_to_strategy(name) == expected

    def test_framework_to_engine(self):
        memory = ContextMemory()
        cases = {
            "Spring Boot": "spel",
            "Django": "django_template",
            "Flask": "jinja2",
            "Jinja2": "jinja2",
            "Laravel": "blade",
            "ThinkPHP": "thinkphp",
            "Express": "ejs",
            "Handlebars": "handlebars",
            "Pug": "pug",
            "Freemarker": "freemarker",
            "Velocity": "velocity",
            "Thymeleaf": "thymeleaf",
            "Unknown": "generic",
        }
        for name, expected in cases.items():
            assert memory._framework_to_engine(name) == expected

    def test_cloud_metadata_url(self):
        memory = ContextMemory()
        assert memory._cloud_metadata_url("AWS") == \
            "http://169.254.169.254/latest/meta-data/"
        assert memory._cloud_metadata_url("GCP") == \
            "http://metadata.google.internal/computeMetadata/v1/"
        assert memory._cloud_metadata_url("Google Cloud") == \
            "http://metadata.google.internal/computeMetadata/v1/"
        assert "api-version" in memory._cloud_metadata_url("Azure")
        assert memory._cloud_metadata_url("Alibaba Cloud") == \
            "http://100.100.100.200/latest/meta-data/"
        assert memory._cloud_metadata_url("Aliyun") == \
            "http://100.100.100.200/latest/meta-data/"
        assert memory._cloud_metadata_url("Tencent") == \
            "http://metadata.tencentyun.com/latest/meta-data/"
        assert memory._cloud_metadata_url("QCloud") == \
            "http://metadata.tencentyun.com/latest/meta-data/"
        assert memory._cloud_metadata_url("Unknown") == \
            "http://169.254.169.254/latest/meta-data/"

    def test_php_wrappers_versions(self):
        memory = ContextMemory()
        full = memory._php_wrappers("7.4")
        assert "php://temp" in full
        assert "php://fd/3" in full
        older = memory._php_wrappers("7.2")
        assert "php://fd/3" in older
        assert "php://temp" not in older
        bare = memory._php_wrappers("7")
        assert len(bare) == 3
        invalid = memory._php_wrappers("not-a-version")
        assert invalid == [
            "php://filter/convert.base64-encode/resource=",
            "php://input",
            "php://stdin",
        ]

    def test_php_wrappers_major_eight_gets_all(self):
        # 修复后按 (major, minor) 元组比较: PHP 8.x 高于 7.4, 应拿到全部包装器.
        memory = ContextMemory()
        eight = memory._php_wrappers("8.0")
        assert len(eight) == 5
        assert "php://temp" in eight
        assert "php://fd/3" in eight
        assert "php://temp" in memory._php_wrappers("8.4")
