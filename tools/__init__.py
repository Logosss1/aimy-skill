"""Lazy public surface for the tools package.

Historically this module imported ~45 detector modules eagerly, which forced
every CLI command (including ``--help`` and ``list``) to pay the full import
cost.  Names are now resolved on first access through ``__getattr__``; the
public API is unchanged and ``from tools import auth_bypass`` still returns
the submodule.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict, Tuple

# name -> (module, attribute).  ``None`` attribute means "return the module".
_EXPORTS: Dict[str, Tuple[str, str]] = {
    "make_session": ("tools._session", "make_session"),
    "HttpClient": ("tools.http_client", "HttpClient"),
    "FakeResponse": ("tools.http_client", "FakeResponse"),
    "build_url": ("tools.http_client", "build_url"),
    "settings": ("tools.settings", "settings"),
    "get_logger": ("tools.log_utils", "get_logger"),
    "mode_echo": ("tools.log_utils", "mode_echo"),
    "show_banner": ("tools.mode", "show_banner"),
    "filter_vulnerabilities": ("tools.mode", "filter_vulnerabilities"),
    "enrich_result": ("tools.mode", "enrich_result"),
    "AimyError": ("tools.exceptions", "AimyError"),
    "NetworkError": ("tools.exceptions", "NetworkError"),
    "TimeoutError": ("tools.exceptions", "TimeoutError"),
    "ConnectionError": ("tools.exceptions", "ConnectionError"),
    "DNSError": ("tools.exceptions", "DNSError"),
    "TLSError": ("tools.exceptions", "TLSError"),
    "WAFBlockedError": ("tools.exceptions", "WAFBlockedError"),
    "DetectionError": ("tools.exceptions", "DetectionError"),
    "FalsePositiveError": ("tools.exceptions", "FalsePositiveError"),
    "ConfigurationError": ("tools.exceptions", "ConfigurationError"),
    "ValidationError": ("tools.exceptions", "ValidationError"),
    "OOBError": ("tools.exceptions", "OOBError"),
    "ChainError": ("tools.exceptions", "ChainError"),
    "PayloadError": ("tools.exceptions", "PayloadError"),
    "OOBServer": ("tools.oob_server", "OOBServer"),
    "ResponseProfiler": ("tools.response_profiler", "ResponseProfiler"),
    "VerificationOracle": ("tools.verification_oracle", "VerificationOracle"),
    "generate": ("tools.payload_engine", "generate"),
    "generate_sqli_error": ("tools.payload_engine", "generate_sqli_error"),
    "mutate_value": ("tools.payload_mutator", "mutate_value"),
    "encode_payload": ("tools.payload_mutator", "encode_payload"),
    "mine": ("tools.param_miner", "mine"),
    "crawl": ("tools.crawler", "crawl"),
    "check_sqli": ("tools.sql_injection", "check"),
    "check_xss": ("tools.xss_detector", "check"),
    "check_ssti": ("tools.ssti_detector", "check"),
    "check_cmdi": ("tools.cmdi_detector", "check"),
    "check_ssrf": ("tools.ssrf_detector", "check"),
    "check_nosqli": ("tools.nosqli_detector", "check"),
    "check_lfi": ("tools.lfi_scanner", "check"),
    "check_auth_bypass": ("tools.auth_bypass", "check"),
    "check_race": ("tools.race_condition", "check"),
    "check_jwt": ("tools.jwt_detector", "check"),
    "check_graphql": ("tools.graphql_scanner", "check"),
    "check_cors": ("tools.cors_scanner", "check"),
    "check_deser": ("tools.deserialization_detector", "check"),
    "check_proto": ("tools.proto_pollution", "check"),
    "check_waf": ("tools.waf_bypass", "check"),
    "fingerprint_waf": ("tools.waf_bypass", "fingerprint_waf"),
    "check_biz_logic": ("tools.biz_logic_scanner", "check"),
    "ChainEngine": ("tools.chain_engine", "ChainEngine"),
    "build_attack_plan": ("tools.attack_surface", "build_attack_plan"),
    "pivot_on_intermediate_result": (
        "tools.attack_surface",
        "pivot_on_intermediate_result",
    ),
    "ReasoningEngine": ("tools.reasoning_engine", "ReasoningEngine"),
    "Hypothesis": ("tools.reasoning_engine", "Hypothesis"),
    "AdaptiveFuzzer": ("tools.adaptive_fuzzer", "AdaptiveFuzzer"),
    "PayloadGroup": ("tools.adaptive_fuzzer", "PayloadGroup"),
    "KnowledgeGraph": ("tools.knowledge_graph", "KnowledgeGraph"),
    "knowledge_graph": ("tools.knowledge_graph", "kg"),
    "AttackTree": ("tools.attack_tree", "AttackTree"),
    "AttackTreeNode": ("tools.attack_tree", "AttackTreeNode"),
    "ActiveProber": ("tools.active_prober", "ActiveProber"),
    "enum_subdomains": ("tools.recon", "enum_subdomains"),
    "scan_ports": ("tools.recon", "scan_ports"),
    "fingerprint_tech": ("tools.recon", "fingerprint_tech"),
    "check_git_leak": ("tools.recon", "check_git_leak"),
    "fuzz_directories": ("tools.recon", "fuzz_directories"),
    "ProtocolFuzzer": ("tools.protocol_fuzzer", "ProtocolFuzzer"),
    "default_sender": ("tools.protocol_fuzzer", "default_sender"),
    "fuzz_ports": ("tools.protocol_fuzzer", "fuzz_ports"),
    "OPSECSession": ("tools.opsec_session", "OPSECSession"),
    "opsec_session": ("tools.opsec_session", "opsec_session"),
    "AuthStateMachine": ("tools.auth_state_machine", "AuthStateMachine"),
    "auth_replay": ("tools.auth_state_machine", "auth_replay"),
    "ProxyPool": ("tools.proxy_pool", "ProxyPool"),
    "Throttle": ("tools.proxy_pool", "Throttle"),
    "pool_session": ("tools.proxy_pool", "pool_session"),
    "map_service": ("tools.service_mapping", "map_service"),
    "map_open_ports": ("tools.service_mapping", "map_open_ports"),
    "default_creds": ("tools.service_mapping", "default_creds"),
    "asrep_roast": ("tools.domain_attacks", "asrep_roast"),
    "ldap_anonymous_enum": ("tools.domain_attacks", "ldap_anonymous_enum"),
    "kerberoast_skeleton": ("tools.domain_attacks", "kerberoast_skeleton"),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        module_name, attr = _EXPORTS[name]
        module = importlib.import_module(module_name)
        value = getattr(module, attr) if attr else module
        globals()[name] = value
        return value

    # Preserve ``from tools import <submodule>`` for modules not listed above.
    try:
        module = importlib.import_module("tools." + name)
    except ModuleNotFoundError as exc:
        raise AttributeError("module 'tools' has no attribute %r" % name) from exc
    globals()[name] = module
    return module


def __dir__() -> list:
    return sorted(set(globals()) | set(__all__))
