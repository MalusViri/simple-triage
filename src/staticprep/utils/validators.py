"""Input validation helpers."""

from __future__ import annotations

from pathlib import Path


def validate_input_file(path: Path) -> Path:
    """Validate that the input path exists and is a file."""
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Input file does not exist: {resolved}")
    if not resolved.is_file():
        raise ValueError(f"Input path is not a file: {resolved}")
    return resolved
