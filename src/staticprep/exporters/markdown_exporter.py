"""Markdown exporter."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_summary_markdown(report: dict[str, Any]) -> str:
    """Build a concise analyst-facing markdown summary."""
    sample = report["sample"]
    analysis_summary = report["analysis_summary"]
    environment = report["environment"]
    packed_assessment = report["packed_assessment"]
    iocs = report["iocs"]
    preview = report["interesting_strings_preview"]
    hashes = report["hashes"]
    strings = report["strings"]
    yara = report["yara"]
    matched_caps = sorted(
        [
            (name, result["confidence"], result["evidence"][:3])
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
        "## Quick Assessment",
        "",
        f"- Worth deeper investigation: `{analysis_summary['recommended_next_step'] != 'archive'}`",
        f"- Severity: `{analysis_summary['severity']}`",
        f"- Score: `{analysis_summary['score']}`",
        f"- Recommended next step: `{analysis_summary['recommended_next_step']}`",
        "",
        "## Top Findings",
        "",
    ]
    lines.extend(
        [f"- {finding}" for finding in analysis_summary["top_findings"]]
        or ["- No strong static findings identified."]
    )
    lines.extend(
        [
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
            "## Likely Packed Assessment",
            "",
            f"- Attempted: `{packed_assessment['attempted']}`",
            f"- Succeeded: `{packed_assessment['succeeded']}`",
            f"- Likely packed: `{packed_assessment['likely_packed']}`",
            f"- Threshold used: `{packed_assessment['threshold_used']}`",
            f"- Rationale: `{packed_assessment['rationale']}`",
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
    if preview:
        lines.append(f"- Interesting preview: `{', '.join(preview[:5])}`")
    lines.extend(
        [
            "",
            "## Capability Highlights",
            "",
        ]
    )
    if matched_caps:
        for name, confidence, evidence in matched_caps[:5]:
            lines.append(
                f"- `{name}` with `{confidence}` confidence"
                + (f" from `{', '.join(evidence)}`" if evidence else "")
            )
    else:
        lines.append("- No capabilities matched configured indicators.")
    lines.extend(
        [
            "",
            "## IOC Highlights",
            "",
            f"- URLs: `{', '.join(iocs['urls'][:3]) if iocs['urls'] else 'none'}`",
            f"- Domains: `{', '.join(iocs['domains'][:3]) if iocs['domains'] else 'none'}`",
            f"- Registry paths: `{', '.join(iocs['registry_paths'][:3]) if iocs['registry_paths'] else 'none'}`",
            f"- Commands: `{', '.join(iocs['commands'][:3]) if iocs['commands'] else 'none'}`",
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
        lines.extend(["## Warnings and Errors", ""])
        for error in report["errors"]:
            lines.append(
                f"- `{error['severity']}` during `{error['stage']}`: {error['message']}"
            )
        lines.append("")

    return "\n".join(lines)


def export_markdown(path: Path, report: dict[str, Any]) -> None:
    """Write the markdown summary artifact."""
    path.write_text(build_summary_markdown(report), encoding="utf-8")
