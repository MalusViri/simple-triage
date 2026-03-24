"""Configuration loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CAPABILITY_MAP = PACKAGE_ROOT / "config" / "capability_map.json"
DEFAULT_SUSPICIOUS_PATTERNS = PACKAGE_ROOT / "config" / "suspicious_patterns.json"
DEFAULT_ANALYSIS_SETTINGS = PACKAGE_ROOT / "config" / "analysis_settings.json"
DEFAULT_RULES_DIR = PACKAGE_ROOT / "rules" / "yara"


def load_json_file(path: Path) -> dict[str, Any]:
    """Load a JSON file from disk."""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_capability_map(path: Path | None = None) -> dict[str, Any]:
    """Load capability mapping configuration."""
    return load_json_file(path or DEFAULT_CAPABILITY_MAP)


def load_suspicious_patterns(path: Path | None = None) -> dict[str, str]:
    """Load suspicious string pattern configuration."""
    return load_json_file(path or DEFAULT_SUSPICIOUS_PATTERNS)


def load_analysis_settings(path: Path | None = None) -> dict[str, Any]:
    """Load analysis scoring and threshold configuration."""
    return load_json_file(path or DEFAULT_ANALYSIS_SETTINGS)
