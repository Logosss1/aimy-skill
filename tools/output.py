import json
import sys

from tools._finding import Finding
from tools.log_utils import get_logger
from tools.mode import enrich_result, filter_vulnerabilities

logger = get_logger("output")

_JSON_MODE = False
_QUIET = False


def configure(json_mode: bool = False, quiet: bool = False) -> None:
    """Configure machine-readable output and progress verbosity."""
    global _JSON_MODE, _QUIET
    _JSON_MODE = bool(json_mode)
    _QUIET = bool(quiet or json_mode)


def progress(message="", *args, **kwargs) -> None:
    """Emit human progress on stderr so stdout stays pure JSON."""
    if _QUIET:
        return
    text = message % args if args else str(message)
    kwargs.pop("file", None)
    kwargs.setdefault("flush", True)
    print(text, file=sys.stderr, **kwargs)


def _serialize(item):
    """统一转可 JSON 序列化的 dict。

    - Finding 实例 -> to_dict()
    - 普通字典 -> 原样返回 (保留旧检测器的输出结构, 平滑过渡)
    - 其他对象 -> 尽力转 dict, 兜底 str
    """
    if isinstance(item, dict):
        return item
    if isinstance(item, Finding):
        return item.to_dict()
    if hasattr(item, "to_dict"):
        try:
            return item.to_dict()
        except Exception:
            pass
    if hasattr(item, "__dict__"):
        return dict(item.__dict__)
    return {"raw": str(item)}


def _prepare(items):
    """veteran 过滤 -> rookie 富化 -> 统一序列化。"""
    enriched = [enrich_result(v) for v in filter_vulnerabilities(list(items))]
    return [_serialize(v) for v in enriched]


def _enforce_contract(result):
    """Normalize detector results to the shared CheckResult shape.

    Unknown fields are preserved in ``extras``; missing ``vulnerable`` becomes
    ``False`` and malformed confidence fields are logged instead of crashing.
    """
    if not isinstance(result, dict):
        return result
    if "vulnerable" not in result and "type" not in result:
        return result
    from engine.contract import CheckResult, check_return_shape

    for warning in check_return_shape(result, strict=True):
        logger.warning("detector contract: %s", warning)
    return CheckResult.from_dict(result).to_dict()


def output(result) -> None:
    result = _enforce_contract(result)
    if isinstance(result, dict) and "vulnerabilities" in result:
        vulns = result["vulnerabilities"]
        result["vulnerabilities"] = _prepare(vulns if isinstance(vulns, list) else [])
        result_json = json.dumps(result, ensure_ascii=False, default=str)
    elif isinstance(result, list):
        result_json = json.dumps(
            {"vulnerabilities": _prepare(result)}, ensure_ascii=False, default=str
        )
    else:
        result_json = json.dumps(result, ensure_ascii=False, default=str)

    print(result_json)


def error(message: str, code: str = "error", **extra) -> None:
    """Emit a structured error envelope (stdout in JSON mode, stderr otherwise)."""
    payload = {"ok": False, "error": str(message), "code": code}
    payload.update(extra)
    stream = sys.stdout if _JSON_MODE else sys.stderr
    print(json.dumps(payload, ensure_ascii=False, default=str), file=stream)


__all__ = ["configure", "progress", "output", "error"]
