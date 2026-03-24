"""Text exporters for list-based artifacts."""

from __future__ import annotations

from pathlib import Path

from staticprep.utils.files import write_lines


def export_plaintext_list(path: Path, values: list[str]) -> None:
    """Write a text artifact containing one value per line."""
    write_lines(path, values)
