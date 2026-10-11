"""利用链调度表 (单一真相源).

历史问题: 原 orchestrator.py 里有两张对偶表, 且已经分叉:
  - _maybe_backtrack_chain 用 vtype -> (chain_name, fn)   (5 项)
  - phase_pivot            用 chain_name -> (vtype, fn)   (6 项, 多 auth_bypass)
导致 backtrack 路径永远不触发 auth_bypass chain.

本模块提供唯一规范表 CHAIN_TABLE, 并由 by_vtype() / by_name() 导出两个视图,
确保两条路径永远同步.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Tuple

# (chain_name, trigger_vtype, ChainEngine method name)
CHAIN_TABLE: List[Tuple[str, str, str]] = [
    ("ssrf_to_rce", "ssrf", "chain_ssrf_to_rce"),
    ("lfi_to_rce", "lfi", "chain_lfi_to_rce"),
    ("sqli_to_rce", "sqli", "chain_sqli_to_rce"),
    ("xss_to_hijack", "xss", "chain_xss_to_hijack"),
    ("deser_to_rce", "deser", "chain_deser_to_rce"),
    ("auth_bypass_to_rce", "auth_bypass", "chain_auth_to_admin"),
]


def by_vtype(chain_engine) -> Dict[str, Tuple[str, Callable]]:
    """vtype -> (chain_name, bound_method)."""
    return {
        vtype: (name, getattr(chain_engine, method))
        for name, vtype, method in CHAIN_TABLE
    }


def by_name(chain_engine) -> Dict[str, Tuple[str, Callable]]:
    """chain_name -> (trigger_vtype, bound_method)."""
    return {
        name: (vtype, getattr(chain_engine, method))
        for name, vtype, method in CHAIN_TABLE
    }
