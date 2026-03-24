"""Local YARA scanning helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any


try:
    import yara
except ImportError:  # pragma: no cover - dependency may be absent in some environments
    yara = None


def _collect_rule_files(rules_dir: Path) -> list[Path]:
    return sorted(
        [
            path
            for path in rules_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in {".yar", ".yara", ".rule"}
        ]
    )


def run_yara_scan(path: Path, rules_dir: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Scan a file with local YARA rules and return match data with structured errors."""
    if yara is None:
        return {"enabled": False, "matches": []}, [
            {
                "stage": "yara",
                "message": "yara-python is not installed; skipping YARA scanning.",
                "severity": "warning",
            }
        ]

    if not rules_dir.exists():
        return {"enabled": True, "matches": []}, [
            {
                "stage": "yara",
                "message": f"Rules directory does not exist: {rules_dir}",
                "severity": "warning",
            }
        ]

    rule_files = _collect_rule_files(rules_dir)
    if not rule_files:
        return {"enabled": True, "matches": []}, [
            {
                "stage": "yara",
                "message": f"No YARA rules found in: {rules_dir}",
                "severity": "warning",
            }
        ]

    errors: list[dict[str, str]] = []
    compiled_namespaces: dict[str, str] = {}
    for index, rule_file in enumerate(rule_files):
        namespace = f"rule_{index}"
        try:
            yara.compile(filepath=str(rule_file))
        except Exception as exc:  # pragma: no cover - depends on yara parsing errors
            errors.append(
                {
                    "stage": "yara",
                    "message": f"Invalid YARA rule {rule_file}: {exc}",
                    "severity": "warning",
                }
            )
            continue
        compiled_namespaces[namespace] = str(rule_file)

    if not compiled_namespaces:
        return {"enabled": True, "matches": []}, errors

    rules = yara.compile(filepaths=compiled_namespaces)
    matches = []
    for match in rules.match(str(path)):
        matches.append(
            {
                "rule": match.rule,
                "tags": sorted(match.tags),
                "meta": dict(sorted(match.meta.items())),
            }
        )
    matches.sort(key=lambda item: item["rule"])
    return {"enabled": True, "matches": matches}, errors
