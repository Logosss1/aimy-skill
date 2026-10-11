"""JWT base64url 编解码 + token 解析 (单一真相源).

历史问题: jwt_exploiter / jwt_attacker / jwt_detector 三个模块各自实现
base64url encode/decode, 函数名不一致 (b64_encode vs b64url_encode),
实现细节略有差异但语义等价. 抽取到本模块后, 三个 detector 统一调用.

向后兼容:
- jwt_exploiter.b64_encode/decode 重命名为 b64url_encode/decode (新名)
  并保留原名作为 deprecated alias, 内部调用本模块
- jwt_attacker.b64url_encode/decode 改为直接 re-export 本模块
- jwt_detector.decode_jwt_header/payload 继续导出 (测试依赖),
  内部委托本模块
"""
from __future__ import annotations

import base64
import json
from typing import Dict, Optional, Tuple


def b64url_encode(data: bytes) -> str:
    """Base64url 编码 (无 padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(s: str) -> bytes:
    """Base64url 解码 (自动补 padding)."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def parse_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    """解析 JWT 三段: 返回 (header, payload, signature_b64), 失败返 (None,None,None)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None, None, None


def decode_jwt_payload(token: str) -> Optional[Dict]:
    """便捷: 只解码 payload."""
    _, payload, _ = parse_jwt(token)
    return payload


def decode_jwt_header(token: str) -> Optional[Dict]:
    """便捷: 只解码 header."""
    header, _, _ = parse_jwt(token)
    return header
