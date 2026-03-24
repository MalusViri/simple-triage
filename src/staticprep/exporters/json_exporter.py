"""JSON exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def export_json(path: Path, payload: dict[str, Any]) -> None:
    """Write a deterministic JSON artifact."""
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
