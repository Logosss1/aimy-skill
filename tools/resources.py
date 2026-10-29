"""Helpers for reading bundled data in both source checkouts and wheels."""

from __future__ import annotations

from importlib import resources
from typing import Iterator, Tuple


def read_text(package: str, filename: str) -> str:
    """Read a bundled text file from a package (works in editable and wheel installs)."""
    return resources.files(package).joinpath(filename).read_text(encoding="utf-8")


def iter_text_files(package: str, suffix: str) -> Iterator[Tuple[str, str]]:
    """Yield ``(filename, text)`` for files ending with ``suffix`` in a package."""
    try:
        root = resources.files(package)
    except (ModuleNotFoundError, TypeError):
        return
    for entry in root.iterdir():
        if entry.is_file() and entry.name.endswith(suffix):
            yield entry.name, entry.read_text(encoding="utf-8")


__all__ = ["read_text", "iter_text_files"]
