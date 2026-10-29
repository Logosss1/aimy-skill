"""Orchestrator 中无状态 helper 的提取.

历史: _run_detector / _cross_verify 原为 Orchestrator 的私有方法,
但二者只依赖 self.sess / self.timeout / self.oracle, 没有内部状态.

把它们抽到本模块:
- 减少 orchestrator.py 行数 (~55 行)
- 允许脱离 Orchestrator 实例单独单测
- 便于未来替换实现 (例如换 verify oracle)

_test_single_point 仍保留为 Orchestrator 的方法, 因为它紧密依赖
self._lock / self.vuln_ctx / self._backtrack_findings / self.context_memory
等大量状态, 完整抽出需要传 15+ 参数, 反而降低可读性.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from tools.orchestrator_engine.helpers import (
    _run_detector_by_name,
)

logger = logging.getLogger(__name__)


def run_detector(
    vtype: str,
    url: str,
    param: str,
    sess: Any,
    waf_name: Optional[str],
    oob: dict,
    effective_timeout: float,
    post_data: Optional[dict] = None,
    method: str = "GET",
) -> Optional[Dict]:
    """调用单个 detector, 返回结果 dict (附 _vtype) 或 None.

    Args:
        vtype: detector 名 (e.g. "sqli", "xss")
        url: 目标 URL
        param: 测试参数
        sess: requests.Session
        waf_name: 已识别 WAF 名 (用于绕过), 空字符串表示无 WAF
        oob: OOB 配置 dict (oob_url / oob_domain)
        effective_timeout: 本次探测超时 (秒)
        post_data: POST body (GET 请求时为 None)
        method: HTTP method

    Returns:
        detector 返回 dict (附 _vtype 字段); 不在注册表或异常时返回 None.
    """
    from tools.orchestrator_engine.helpers import ALL_DETECTOR_NAMES, ALL_DETECTORS

    waf_name = waf_name or ""
    if vtype not in ALL_DETECTOR_NAMES and vtype not in ALL_DETECTORS:
        return None
    try:
        r = _run_detector_by_name(
            vtype,
            url,
            param,
            sess,
            effective_timeout,
            waf_name,
            oob,
            post_data=post_data,
            method=method,
        )
        if isinstance(r, dict):
            r["_vtype"] = vtype
            return r
    except Exception as e:
        logger.debug("detect %s on %s?%s: %s", vtype, url, param, e)
    return None


def cross_verify(
    vtype: str,
    url: str,
    param: str,
    waf_name: str,
    oob: dict,
    first_result: dict,
    oracle: Any,
    sess: Any,
    timeout: float,
    post_data: Optional[dict] = None,
    method: str = "GET",
) -> dict:
    """独立复验: 换一个编码表示重新触发 detector + oracle 确认.

    与首轮检测不同, 复验使用独立的 payload 表示 (WAF 编码策略),
    只有当信号在不同表示下可复现且通过 oracle 验证才计入 cross_verified.

    Returns:
        原地修改 first_result, 增加 cross_verified / cross_count / confirmed 字段.
    """
    from tools.payload_mutator import encode_payload
    from tools.session import build_session

    cross: List[str] = []
    payload = first_result.get("result", {}).get("payload") or param
    encoders = ["url", "double_url", "b64", "hex", "unicode"]
    variant = encode_payload(payload, encoders[hash((vtype, url, param)) % len(encoders)])

    for attempt in (variant, None):
        if attempt is None and cross:
            break
        try:
            r2 = _run_detector_by_name(
                vtype,
                url,
                param,
                sess,
                timeout,
                waf_name,
                oob,
                post_data=post_data,
                method=method,
            )
            if isinstance(r2, dict) and not r2.get("error") and r2.get("vulnerable"):
                cv = oracle.verify(
                    vtype,
                    r2,
                    url,
                    param,
                    sess if sess is not None else build_session(),
                    timeout,
                )
                if cv.get("verified") is not False:
                    cross.append(vtype)
                    break
        except Exception as e:
            logger.debug("cross_verify %s: %s", vtype, e)

    first_result["cross_verified"] = cross
    first_result["cross_count"] = len(cross)
    first_result["confirmed"] = len(cross) >= 1
    return first_result
