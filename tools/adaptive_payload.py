import json
from typing import Dict, List

from tools.log_utils import get_logger
from tools.vuln_context import VulnContextStore as VulnCtx

logger = get_logger("adaptive_payload")


def adapt_payload(vtype: str, ctx: VulnCtx) -> Dict:
    hints = {"preferred": [], "avoid": [], "custom": []}
    vc = ctx.get()

    if vtype == "sqli":
        if vc.dbms:
            db = vc.dbms.lower()
            if "mysql" in db:
                hints["preferred"] = ["sleep", "benchmark", "load_file", "into_outfile"]
                hints["avoid"] = ["pg_sleep", "waitfor"]
            elif "postgres" in db:
                hints["preferred"] = ["pg_sleep", "cast", "dblink"]
                hints["avoid"] = ["sleep", "waitfor"]
            elif "mssql" in db or "sql server" in db:
                hints["preferred"] = ["waitfor", "xp_cmdshell", "openrowset"]
                hints["avoid"] = ["sleep", "load_file"]
            elif "oracle" in db:
                hints["preferred"] = ["dbms_pipe", "utl_file", "xmltype"]
                hints["avoid"] = ["sleep", "load_file", "waitfor"]
        else:
            hints["preferred"] = ["sleep", "pg_sleep", "waitfor"]
        if vc.has_debug_mode:
            hints["custom"].append("stacked_queries_for_debug")

    elif vtype == "ssrf":
        if vc.cloud_provider:
            cp = vc.cloud_provider.lower()
            if "aws" in cp:
                hints["preferred"] = ["169.254.169.254", "instance-data"]
                hints["custom"] = ["imdsv2_token"]
            elif "gcp" in cp or "google" in cp:
                hints["preferred"] = ["metadata.google.internal"]
                hints["custom"] = ["Metadata-Flavor: Google"]
            elif "azure" in cp:
                hints["preferred"] = ["169.254.169.254/metadata/instance"]
                hints["custom"] = ["api-version=2021-02-01"]
            elif "alibaba" in cp:
                hints["preferred"] = ["100.100.100.200"]
        else:
            hints["preferred"] = [
                "169.254.169.254",
                "metadata.google.internal",
                "file:///etc/passwd",
            ]
        if vc.has_admin_panel:
            hints["custom"].append("internal_admin_portal_scan")

    elif vtype == "lfi":
        if vc.os_type and "windows" in vc.os_type.lower():
            hints["preferred"] = [
                "c:/windows/win.ini",
                "c:/boot.ini",
                "c:/windows/system32/drivers/etc/hosts",
            ]
        else:
            hints["preferred"] = ["/etc/passwd", "/etc/issue", "/proc/self/environ"]
            hints["custom"] = ["php://filter/convert.base64-encode/resource="]
        if vc.sqli_safe_chars:
            hints["custom"].append("use_sqli_safe_chars_in_path")

    elif vtype == "cmdi":
        if vc.os_type and "windows" in vc.os_type.lower():
            hints["preferred"] = ["whoami", "ipconfig", "systeminfo", "dir"]
        else:
            hints["preferred"] = ["id", "whoami", "uname -a", "ls -la"]
        if vc.waf_name:
            hints["custom"].append("waf_bypass_for_cmdi")

    elif vtype == "ssti":
        if vc.ssti_engine:
            engine = vc.ssti_engine.lower()
            if "jinja" in engine:
                hints["preferred"] = ["{{config}}", "{{''.__class__.__mro__}}"]
            elif "freemarker" in engine:
                hints["preferred"] = ["${7*7}", "<#assign ex=...>"]
            elif "velocity" in engine:
                hints["preferred"] = ["#set($x=7*7)$x", "#foreach"]
            elif "spel" in engine or "spring" in engine:
                hints["preferred"] = ["${7*7}", "#{7*7}", "T(java.lang.Runtime)"]
            elif "smarty" in engine:
                hints["preferred"] = ["{$smarty.version}", "{php}"]
        else:
            hints["preferred"] = ["{{7*7}}", "${7*7}", "{{7*'7'}}"]

    elif vtype == "deser":
        frameworks = vc.frameworks
        if any("spring" in f.lower() for f in frameworks):
            hints["preferred"] = ["jackson", "fastjson", "jndi"]
        elif any("struts" in f.lower() for f in frameworks):
            hints["preferred"] = ["ognl", "struts2"]
        elif any("shiro" in f.lower() for f in frameworks):
            hints["preferred"] = ["rememberme", "aes_gcm"]
        if vc.discovered_versions:
            for k, val in vc.discovered_versions.items():
                hints["custom"].append("%s=%s" % (k, val))

    return hints


def select_payloads(vtype: str, ctx: VulnCtx, payload_pool: List[Dict]) -> List[Dict]:
    hints = adapt_payload(vtype, ctx)
    preferred = hints.get("preferred", [])
    if not preferred:
        return payload_pool[:10]

    avoid = [k.lower() for k in hints.get("avoid", [])]
    scored = []
    for p in payload_pool:
        p_text = json.dumps(p).lower()
        score = 0
        for kw in preferred:
            if kw.lower() in p_text:
                score += 2
        avoided = any(kw in p_text for kw in avoid)
        if avoided:
            score -= 3
        for kw in hints.get("custom", []):
            if kw.lower() in p_text:
                score += 1
        scored.append((score, avoided, p))

    scored.sort(key=lambda x: -x[0])
    # avoid 命中直接排除 (旧逻辑仅降分, 错误 DBMS 的载荷仍会被执行).
    result = [p for s, av, p in scored if s > 0 and not av]
    result.extend([p for s, av, p in scored if s <= 0 and not av])
    return result[:10]


def suggest_additional_tests(vtype: str, ctx: VulnCtx) -> List[str]:
    suggestions = []
    vc = ctx.get()

    if vtype == "sqli":
        dbms = (vc.dbms or "").lower()
        if vc.has_debug_mode:
            suggestions.append("try_debug_sqli_stack")
        if "mssql" in dbms:
            suggestions.append("enable_xp_cmdshell")
        if "mysql" in dbms:
            suggestions.append("try_into_outfile")

    elif vtype == "ssrf":
        if vc.cloud_provider:
            suggestions.append("extract_cloud_credentials")
        if vc.has_admin_panel:
            suggestions.append("scan_internal_services")

    elif vtype == "lfi":
        if vc.lfi_readable_paths:
            if any("log" in p for p in vc.lfi_readable_paths):
                suggestions.append("try_log_poison_rce")
            if any("proc" in p or "environ" in p for p in vc.lfi_readable_paths):
                suggestions.append("try_ssh_key_extraction")
        if any("php" in f.lower() for f in vc.frameworks):
            suggestions.append("try_php_filter_wrapper")

    elif vtype == "cmdi":
        if vc.has_file_upload:
            suggestions.append("upload_reverse_shell")
        if vc.dbms:
            suggestions.append("try_os_command_via_database")

    return suggestions
