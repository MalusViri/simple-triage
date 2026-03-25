"""Markdown exporter."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _format_artifact_entries(entries: list[dict[str, Any]]) -> str:
    """Return a short artifact summary string for markdown output."""
    if not entries:
        return "none"
    formatted = []
    for entry in entries[:3]:
        formatted.append(f"{entry['value']} ({entry['classification']})")
    return ", ".join(formatted)


def build_summary_markdown(report: dict[str, Any]) -> str:
    """Build a curated analyst-facing markdown summary."""
    sample = report["sample"]
    analysis_summary = report["analysis_summary"]
    findings = report["findings"]
    interpretation = report["interpretation"]
    environment = report["environment"]
    packed_assessment = report["packed_assessment"]
    iocs = report["iocs"]
    preview = report["interesting_strings_preview"]
    hashes = report["hashes"]
    strings = report["strings"]
    yara = report["yara"]

    lines = [
        "# staticprep Summary",
        "",
        "## Quick Assessment",
        "",
        f"- Worth deeper investigation: `{findings['executive_summary']['worth_deeper_investigation']}`",
        f"- Severity: `{analysis_summary['severity']}`",
        f"- Score: `{analysis_summary['score']}`",
        f"- Recommended next step: `{analysis_summary['recommended_next_step']}`",
        f"- Analysis degraded: `{findings['executive_summary']['analysis_degraded']}`",
        f"- Likely packed: `{packed_assessment['likely_packed']}`",
        "",
        "## Top Findings",
        "",
    ]
    lines.extend(
        [f"- {finding}" for finding in findings["executive_summary"]["top_findings"]]
        or ["- No strong static findings identified."]
    )

    lines.extend(
        [
            "",
            "## Analyst-Ready Findings",
            "",
        ]
    )
    if findings["analyst_ready"]:
        for finding in findings["analyst_ready"]:
            evidence = ", ".join(finding.get("evidence", [])[:3]) or "none"
            lines.append(
                f"- `{finding['type']}` `{finding['name']}` confidence=`{finding['confidence']}` evidence=`{evidence}`"
            )
    else:
        lines.append("- No analyst-ready high-confidence findings were identified.")

    lines.extend(
        [
            "",
            "## Contextual / Low-Confidence Findings",
            "",
        ]
    )
    if findings["contextual"]:
        for finding in findings["contextual"]:
            evidence = ", ".join(finding.get("evidence", [])[:3]) or "none"
            notes = ", ".join(finding.get("notes", [])[:2]) or "none"
            lines.append(
                f"- `{finding['type']}` `{finding['name']}` evidence=`{evidence}` notes=`{notes}`"
            )
    else:
        lines.append("- No contextual findings were recorded.")

    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "",
        ]
    )
    if interpretation["notes"]:
        for note in interpretation["notes"]:
            evidence = ", ".join(note.get("evidence", [])[:3]) or "none"
            lines.append(f"- `{note['code']}`: {note['summary']} Evidence: `{evidence}`")
    else:
        lines.append("- No benign-context guardrail notes were triggered.")

    lines.extend(
        [
            "",
            "## IOC Highlights",
            "",
            f"- High-confidence URLs: `{_format_artifact_entries(iocs['high_confidence']['urls'])}`",
            f"- High-confidence domains: `{_format_artifact_entries(iocs['high_confidence']['domains'])}`",
            f"- High-confidence registry paths: `{_format_artifact_entries(iocs['high_confidence']['registry_paths'])}`",
            f"- High-confidence commands: `{_format_artifact_entries(iocs['high_confidence']['commands'])}`",
            f"- Contextual URLs: `{_format_artifact_entries(iocs['contextual']['urls'])}`",
            f"- Contextual file paths: `{_format_artifact_entries(iocs['contextual']['file_paths'])}`",
            f"- Raw IOC count: `{iocs['raw_summary']['total']}`",
            "",
            "## YARA Status",
            "",
            f"- Scan status: `{yara['scan_status']}`",
            f"- Attempted: `{yara['attempted']}`",
            f"- Succeeded: `{yara['succeeded']}`",
            f"- Match count: `{yara['match_count']}`",
            f"- Rule stats: `discovered={yara['rule_stats']['discovered']} valid={yara['rule_stats']['valid']} invalid={yara['rule_stats']['invalid']}`",
        ]
    )
    if yara["matches"]:
        lines.append(
            f"- Matches: `{', '.join(match['rule'] for match in yara['matches'][:5])}`"
        )
    else:
        lines.append("- Matches: `none`")
    if yara["warnings"]:
        lines.append(f"- Warnings: `{'; '.join(yara['warnings'][:5])}`")
    else:
        lines.append("- Warnings: `none`")

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
            "## Raw Findings References",
            "",
            f"- Suspicious string count: `{strings['suspicious_count']}`",
            f"- Interesting preview: `{', '.join(preview[:5]) if preview else 'none'}`",
            f"- Raw artifacts: `{', '.join(findings['raw_references']['artifact_files'])}`",
            "",
        ]
    )

    if report["errors"]:
        lines.extend(["## Warnings / Errors", ""])
        for error in report["errors"]:
            lines.append(f"- `{error['severity']}` during `{error['stage']}`: {error['message']}")
        lines.append("")

    return "\n".join(lines)


def export_markdown(path: Path, report: dict[str, Any]) -> None:
    """Write the markdown summary artifact."""
    path.write_text(build_summary_markdown(report), encoding="utf-8")
