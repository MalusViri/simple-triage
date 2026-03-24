"""Markdown exporter."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_summary_markdown(report: dict[str, Any]) -> str:
    """Build a concise analyst-facing markdown summary."""
    sample = report["sample"]
    hashes = report["hashes"]
    pe = report["pe"]
    yara = report["yara"]
    matched_caps = [
        name for name, result in report["capabilities"].items() if result["matched"]
    ]

    lines = [
        "# staticprep Summary",
        "",
        f"- Sample: `{sample['name']}`",
        f"- Path: `{sample['path']}`",
        f"- Size: `{sample['size']}` bytes",
        f"- MIME hint: `{sample['type_hint']}`",
        f"- MD5: `{hashes['md5']}`",
        f"- SHA1: `{hashes['sha1']}`",
        f"- SHA256: `{hashes['sha256']}`",
        f"- PE detected: `{pe['is_pe']}`",
        f"- YARA matches: `{len(yara['matches'])}`",
        f"- Matched capabilities: `{', '.join(matched_caps) if matched_caps else 'none'}`",
        "",
    ]

    if pe["is_pe"]:
        lines.extend(
            [
                "## PE Metadata",
                "",
                f"- Machine: `{pe.get('machine_type', 'unknown')}`",
                f"- Compile timestamp: `{pe.get('compile_timestamp', 'unknown')}`",
                f"- Subsystem: `{pe.get('subsystem', 'unknown')}`",
                f"- Entry point: `{pe.get('entry_point', 'unknown')}`",
                f"- Image base: `{pe.get('image_base', 'unknown')}`",
                "",
            ]
        )

    if report["errors"]:
        lines.extend(["## Errors and Warnings", ""])
        for error in report["errors"]:
            lines.append(
                f"- `{error['severity']}` during `{error['stage']}`: {error['message']}"
            )
        lines.append("")

    return "\n".join(lines)


def export_markdown(path: Path, report: dict[str, Any]) -> None:
    """Write the markdown summary artifact."""
    path.write_text(build_summary_markdown(report), encoding="utf-8")
