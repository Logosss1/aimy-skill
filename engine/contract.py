"""Check() 返回值契约校验 (v1).

为 AI Agent 提供稳定的 check() 输出 shape 约定:
    - REQUIRED: vulnerable: bool
    - OPTIONAL: type, evidence, findings, confidence, payload, ...

本模块只产出告警, 不抛异常, 不强制修改现有 detector. 新 detector
应按本契约返回; 老 detector 可渐进迁移.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONFIDENCE_LEVELS = ("low", "medium", "high")


@dataclass
class CheckResult:
    """check() 返回值的最小骨架 + 自由 extras.

    detector 仍可返回任意 dict; CheckResult.from_dict() 做软转换,
    extras 字段保留所有未在 dataclass 中声明的键.
    """

    vulnerable: bool = False

    type: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    payload: Optional[str] = None
    error: Optional[str] = None
    note: Optional[str] = None

    confidence: Optional[str] = None
    confidence_score: Optional[float] = None
    confidence_votes: List[Dict[str, Any]] = field(default_factory=list)
    confirmed: Optional[bool] = None

    vector: Optional[str] = None
    dbms: Optional[str] = None
    engine: Optional[str] = None
    rce_available: Optional[bool] = None

    oob_tested: Optional[bool] = None
    oob_methods: List[str] = field(default_factory=list)
    oob_server_used: Optional[str] = None

    extras: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "CheckResult":
        if not isinstance(d, dict):
            return cls()
        known = {f.name for f in cls.__dataclass_fields__.values() if f.name != "extras"}
        extras = {k: v for k, v in d.items() if k not in known}
        known_subset = {k: v for k, v in d.items() if k in known}
        return cls(extras=extras, **known_subset)

    def to_dict(self) -> Dict[str, Any]:
        base = {k: getattr(self, k) for k in self.__dataclass_fields__ if k != "extras"}
        base.update(self.extras)
        keep_vulnerable = base.pop("vulnerable", False)
        cleaned = {k: v for k, v in base.items() if v not in (None, [], {}, "")}
        cleaned["vulnerable"] = keep_vulnerable
        return cleaned

    def validate(self) -> List[str]:
        """返回告警列表, 不抛异常."""
        warnings: List[str] = []
        if not isinstance(self.vulnerable, bool):
            warnings.append(
                "vulnerable must be bool, got %s" % type(self.vulnerable).__name__
            )
        if self.confidence is not None and self.confidence not in CONFIDENCE_LEVELS:
            warnings.append(
                "confidence must be one of %s, got %r" % (CONFIDENCE_LEVELS, self.confidence)
            )
        if self.confidence_score is not None:
            try:
                score = float(self.confidence_score)
            except (TypeError, ValueError):
                warnings.append("confidence_score not numeric: %r" % self.confidence_score)
            else:
                if not (0.0 <= score <= 1.0):
                    warnings.append("confidence_score out of [0,1]: %r" % self.confidence_score)
        if self.evidence and self.findings:
            warnings.append(
                "both 'evidence' (str list) and 'findings' (dict list) present; "
                "agent should prefer 'findings' for structured access"
            )
        return warnings


def check_return_shape(
    result: Optional[Dict[str, Any]], *, strict: bool = False
) -> List[str]:
    """便利函数: 直接校验 detector 返回的 dict, 返回告警列表."""
    if result is None:
        return ["check() returned None (must return Dict)"]
    if not isinstance(result, dict):
        return ["check() returned %s (must return Dict)" % type(result).__name__]
    cr = CheckResult.from_dict(result)
    warnings = cr.validate()
    if strict and "vulnerable" not in result:
        warnings.append("missing REQUIRED field 'vulnerable'")
    return warnings


def is_vulnerable(result: Optional[Dict[str, Any]]) -> bool:
    """安全读取 vulnerable 字段. 处理 'unauth_scan' 把 int 当 vulnerable 的旧坑."""
    if not isinstance(result, dict):
        return False
    val = result.get("vulnerable")
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val > 0
    return False
