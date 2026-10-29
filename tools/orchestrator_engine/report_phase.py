"""Report phase for the orchestrator.

Extracted from ``orchestrator.py`` to keep the coordinator smaller.  The
mixin only depends on the orchestrator's public state (``target``, ``state``,
``attack_graph``, ``context_memory``, ``pipeline_result``) plus
``_save_phase`` and ``_storage``.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from tools.log_utils import get_logger

logger = get_logger("orchestrator.report")


class ReportPhaseMixin:
    def phase_report(self) -> Dict:
        report: Dict[str, Any] = {
            "target": self.target,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": {},
            "details": {},
        }
        detection = self.state["phases"].get("detect", {})
        findings = detection.get("findings", {})
        exploits = self.state["phases"].get("weaponize", {})
        auth_data = self.state["phases"].get("auth_bypass", {})
        recon = self.state["phases"].get("recon", {})
        crawl_summary = self.state["phases"].get("crawl", {}).get("summary", {})
        mine_data = self.state["phases"].get("param_mine", {})
        waf_info = self.state.get("waf", {})

        by_type, by_url = self._report_group(findings)

        report["summary"] = self._report_summary(findings, by_type, by_url, exploits, auth_data)
        report["details"] = {vt: flist for vt, flist in by_type.items()}
        report["exploits"] = exploits
        report["auth_bypass"] = {k: v for k, v in auth_data.items() if k != "vulnerable"}
        report["recon"] = self._report_recon(
            recon,
            detection,
            crawl_summary,
            mine_data,
            waf_info,
        )

        report["attack_graph"] = self.attack_graph.summary() if self.attack_graph else {}
        report["context_memory"] = self.context_memory.get_stats()
        if self.pipeline_result:
            report["pipeline"] = self.pipeline_result
        report["second_order_verified"] = sum(
            1 for f in findings.values() if f.get("second_order_verified")
        )

        self.state["phases"]["report"] = report
        self._save_phase("report")
        self._report_persist(report)
        return report

    @staticmethod
    def _report_group(findings: Dict) -> tuple:
        """按 type / url 聚合 findings."""
        by_type: Dict[str, List] = {}
        by_url: Dict[str, List[str]] = {}
        for f in findings.values():
            by_type.setdefault(f["type"], []).append(f)
            by_url.setdefault(f["url"], []).append(f["type"])
        return by_type, by_url

    @staticmethod
    def _report_summary(
        findings: Dict, by_type: Dict, by_url: Dict, exploits: Dict, auth_data: Dict
    ) -> Dict:
        vuln_count = len(findings)
        exploit_ready_details = [k for k, v in exploits.items() if v.get("exploit_ready")]
        auth_total = auth_data.get("total_bypasses", 0)
        if auth_total > 0:
            exploit_ready_details.append("auth_bypass(%d)" % auth_total)

        critical_flags = (
            "rce_available",
            "rce",
            "shell",
            "data_extracted",
            "credential_access",
            "exploit_ready",
        )
        is_critical = any(
            any(f.get("result", {}).get(k) for k in critical_flags) for f in findings.values()
        ) or bool(exploit_ready_details)

        return {
            "vulnerabilities": vuln_count,
            "by_type": {k: len(v) for k, v in by_type.items()},
            "by_url": {k: len(v) for k, v in by_url.items()},
            "exploit_ready": len(exploits),
            "exploit_ready_details": exploit_ready_details,
            "critical": is_critical,
            "affected_urls": list(by_url.keys()),
            "param_hits": [
                "%s?%s [%s]" % (f["url"], f["param"], f["type"]) for f in findings.values()
            ],
        }

    @staticmethod
    def _report_recon(
        recon: Dict,
        detection: Dict,
        crawl_summary: Dict,
        mine_data: Dict,
        waf_info: Dict,
    ) -> Dict:
        techs = recon.get("technologies", {})
        ports = recon.get("open_ports", {})
        git = recon.get("git_leak", {})
        dirs = recon.get("directories", {})
        total_mined = sum(
            len(pd.get("all_params", [])) for pd in mine_data.values() if isinstance(pd, dict)
        )
        risk_score = 0
        attack_plan = recon.get("attack_plan") or {}
        if isinstance(attack_plan, dict):
            risk_score = attack_plan.get("risk_score", 0)
        return {
            "technologies": [t["name"] for t in techs.get("technologies", [])],
            "open_ports": [p["port"] for p in ports.get("open_ports", [])],
            "git_exposed": git.get("git_exposed", False),
            "git_sensitive": len(git.get("sensitive_finds", [])),
            "directories": len(dirs.get("interesting", [])),
            "pages_crawled": crawl_summary.get("pages_crawled", 0),
            "endpoints": crawl_summary.get("endpoints_found", 0),
            "params_mined": total_mined,
            "test_points": detection.get("test_points", 0),
            "is_spa": crawl_summary.get("is_spa", False),
            "js_api_discovered": crawl_summary.get("js_api_discovered", 0),
            "waf": waf_info.get("name"),
            "risk_score": risk_score,
        }

    def _report_persist(self, report: Dict) -> None:
        if not self._storage:
            return
        try:
            cur = self._storage._conn.cursor()
            cur.execute(
                "UPDATE sessions SET report=?, updated_at=? WHERE id=?",
                (json.dumps(report), time.time(), self._storage.session_id()),
            )
            self._storage._conn.commit()
        except Exception as e:
            logger.debug("save report: %s", e)
