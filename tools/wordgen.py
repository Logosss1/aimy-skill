"""Custom wordlist generation and maintenance for authorized testing.

- ``load_bundled`` reads the packaged wordlists/ files (works in wheels).
- ``generate_wordlist`` builds a target-specific dictionary from keywords:
  case variants, leet substitutions, numeric/year suffixes, short glue.
- ``merge_wordlists`` deduplicates and sorts multiple sources, preserving order.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from tools.log_utils import get_logger
from tools.resources import iter_text_files

logger = get_logger("wordgen")

_LEET_MAP = {
    "a": "@",
    "s": "$",
    "e": "3",
    "i": "1",
    "o": "0",
    "t": "7",
    "b": "8",
    "g": "9",
}

_DEFAULT_GLUE = ("!", "@", "#", ".", "_")


def apply_leet(word: str) -> str:
    """Apply common leet substitutions once (only when present).

    Returns the original word when nothing changed, so upstream callers can
    skip the redundant entry cleanly.
    """
    out = "".join(_LEET_MAP.get(ch, ch) for ch in word.lower())
    return out if out != word else word


def casing_variants(word: str) -> List[str]:
    seen = []
    for variant in (word, word.capitalize(), word.upper(), word.lower()):
        if variant not in seen:
            seen.append(variant)
    return seen


def _dedup_preserving_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        item = item.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def generate_wordlist(
    keywords: Sequence[str],
    years: Sequence[int] = (),
    max_suffix: int = 99,
    leet: bool = True,
    glue: Sequence[str] = _DEFAULT_GLUE,
    domains: Sequence[str] = (),
) -> List[str]:
    """Build a target-specific dictionary from keywords.

    Args:
        keywords: seed words (company/product/username/pinyin).
        years: years to append (e.g. 2020-2026).
        max_suffix: append 0..max_suffix numeric suffixes.
        leet: include leet variants.
        glue: short separators appended to key words.
        domains: corporate/email domains; user@domain forms appended.
    """
    seeds: List[str] = []
    for keyword in keywords:
        for text in (keyword.strip(), keyword.strip().lower()):
            if not text:
                continue
            seeds.extend(casing_variants(text))
            if leet:
                seeds.append(apply_leet(text))
        for g in glue:
            if keyword.strip():
                seeds.append("%s%s" % (keyword.strip(), g))

    out: List[str] = []
    base = _dedup_preserving_order(seeds)
    out.extend(base)

    suffixed: List[str] = []
    for word in base:
        for num in range(0, max_suffix + 1):
            suffixed.append("%s%d" % (word, num))
        for year in years:
            suffixed.append("%s%d" % (word, int(year)))
    out.extend(_dedup_preserving_order(suffixed))

    domain_forms = []
    for domain in domains:
        for user in (k.strip() for k in keywords if k.strip()):
            if "@" not in user:
                domain_forms.append("%s@%s" % (user, domain.strip().lstrip("@")))
    out.extend(_dedup_preserving_order(domain_forms))

    logger.info("wordlist generated: %d candidates from %d keywords", len(out), len(keywords))
    return out


def load_bundled(name: str) -> List[str]:
    """Read a bundled wordlist file (without extension or with it)."""
    if not name.endswith(".txt"):
        name = name + ".txt"
    from tools.resources import read_text

    text = read_text("wordlists", name)
    return _dedup_preserving_order(text.splitlines())


def list_bundled() -> List[str]:
    """Names of the bundled dictionaries."""
    names = sorted(fname[:-4] for fname, _ in iter_text_files("wordlists", ".txt"))
    return names


def merge_wordlists(paths: Sequence[str], out: Optional[str] = None) -> List[str]:
    """Deduplicate-sort multiple text files; optionally write the merge."""
    merged: List[str] = []
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            merged.extend(line.strip() for line in f if line.strip())
    result = _dedup_preserving_order(merged)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(result) + "\n")
        logger.info("merged %d words into %s", len(result), out)
    return result


def sum_bundled() -> Tuple[int, List[str]]:
    """Total entries and file names across bundled dictionaries."""
    total = 0
    names = []
    for name in list_bundled():
        total += len(load_bundled(name))
        names.append(name)
    return total, names


__all__ = [
    "apply_leet",
    "casing_variants",
    "generate_wordlist",
    "load_bundled",
    "list_bundled",
    "merge_wordlists",
    "sum_bundled",
]
