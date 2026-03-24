"""Filesystem helpers."""

from __future__ import annotations

import re
from pathlib import Path


def sanitize_sample_name(path: Path) -> str:
    """Return a filesystem-safe output directory name for a sample."""
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.stem).strip("._")
    return safe_name or "sample"


def ensure_directory(path: Path) -> Path:
    """Create a directory if needed and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_lines(path: Path, lines: list[str]) -> None:
    """Write a deterministic text file with one line per entry."""
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
