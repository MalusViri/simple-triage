"""Markdown exporter."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_summary_markdown(report: dict[str, Any]) -> str:
    """Build a concise analyst-facing markdown summary."""
    sample = report["sample"]
    environment = report["environment"]
    hashes = report["hashes"]
    pe = report["pe"]
    strings = report["strings"]
    yara = report["yara"]
    matched_caps = sorted(
        [
            (name, result["confidence"])
            for name, result in report["capabilities"].items()
            if result["matched"]
        ],
        key=lambda item: {"high": 0, "medium": 1, "low": 2}[item[1]],
    )
    suspicious = strings["suspicious"]["categorized"]
    suspicious_summary = []
    for category in [
        "urls",
        "ips",
        "domains",
        "registry_paths",
        "file_paths",
        "commands_or_lolbins",
        "powershell",
        "appdata_or_temp",
        "other",
    ]:
        values = suspicious.get(category, [])
        if values:
            suspicious_summary.append(f"- {category.replace('_', ' ').title()}: `{', '.join(values[:3])}`")

    lines = [
        "# staticprep Summary",
        "",
        "## Sample Overview",
        "",
        f"- Sample: `{sample['name']}`",
        f"- Output folder suffix: `{hashes['sha256'][:8]}`",
        f"- Path: `{sample['path']}`",
        f"- Size: `{sample['size']}` bytes",
        f"- MIME hint: `{sample['type_hint']}`",
        "",
        "## Hashes",
        "",
        f"- MD5: `{hashes['md5']}`",
        f"- SHA1: `{hashes['sha1']}`",
        f"- SHA256: `{hashes['sha256']}`",
        "",
        "## Environment and Degraded Mode",
        "",
        f"- `pefile` available: `{environment['pefile_available']}`",
        f"- `yara-python` available: `{environment['yara_available']}`",
        f"- Degraded mode: `{environment['degraded_mode']}`",
        f"- Reasons: `{', '.join(environment['degraded_reasons']) if environment['degraded_reasons'] else 'none'}`",
        "",
        "## PE Analysis Status",
        "",
        f"- Attempted: `{pe['attempted']}`",
        f"- Succeeded: `{pe['succeeded']}`",
        f"- Skipped: `{pe['skipped']}`",
        f"- Error: `{pe['error'] or 'none'}`",
        f"- PE detected: `{pe['is_pe']}`",
        "",
    ]

    if pe["succeeded"] and pe["is_pe"]:
        lines.extend(
            [
                f"- Machine: `{pe.get('machine_type', 'unknown')}`",
                f"- Compile timestamp: `{pe.get('compile_timestamp', 'unknown')}`",
                f"- Subsystem: `{pe.get('subsystem', 'unknown')}`",
                f"- Entry point: `{pe.get('entry_point', 'unknown')}`",
                f"- Image base: `{pe.get('image_base', 'unknown')}`",
                f"- Sections: `{pe.get('number_of_sections', 0)}`",
                "",
            ]
        )

    lines.extend(
        [
            "## Suspicious Strings Highlights",
            "",
            f"- Total suspicious strings: `{strings['suspicious_count']}`",
        ]
    )
    lines.extend(suspicious_summary or ["- No suspicious string highlights identified."])
    lines.extend(
        [
            "",
            "## Top Capabilities Inferred",
            "",
        ]
    )
    if matched_caps:
        for name, confidence in matched_caps[:5]:
            lines.append(f"- `{name}` with `{confidence}` confidence")
    else:
        lines.append("- No capabilities matched configured indicators.")
    lines.extend(
        [
            "",
            "## YARA Highlights",
            "",
            f"- Attempted: `{yara['attempted']}`",
            f"- Succeeded: `{yara['succeeded']}`",
            f"- Skipped: `{yara['skipped']}`",
            f"- Error: `{yara['error'] or 'none'}`",
            f"- Match count: `{yara['match_count']}`",
        ]
    )
    if yara["matches"]:
        for match in yara["matches"][:5]:
            lines.append(f"- `{match['rule']}` tags=`{', '.join(match['tags']) if match['tags'] else 'none'}`")
    lines.append("")

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
