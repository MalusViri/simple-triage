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
    context = report["context"]
    analysis_summary = report["analysis_summary"]
    findings = report["findings"]
    interpretation = report["interpretation"]
    environment = report["environment"]
    behavior_chains = report["behavior_chains"]
    intent_inference = report["intent_inference"]
    packed_assessment = report["packed_assessment"]
    iocs = report["iocs"]
    preview = report["interesting_strings_preview"]
    hashes = report["hashes"]
    strings = report["strings"]
    yara = report["yara"]
    ioc_quality = iocs.get(
        "raw_summary",
        {},
    ).get(
        "by_quality",
        {"clean": 0, "noisy": 0, "malformed": 0, "contextual_only": 0},
    )
    reasoning_quality = strings.get(
        "reasoning",
        {},
    ).get(
        "quality_summary",
        {"reasoning_eligible_count": 0, "suppressed_count": 0},
    )

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
        f"- Primary likely intent: `{intent_inference['primary']}`",
        f"- Secondary intents: `{', '.join(intent_inference.get('secondary', [])) if intent_inference.get('secondary') else 'none'}`",
        f"- Quick assessment: {interpretation.get('quick_assessment', 'none')}",
        f"- YARA health: `{yara.get('yara_health', 'unknown')}`",
        "",
        "## Binary Context",
        "",
        f"- .NET indicators: `{context['is_dotnet']}`",
        f"- Go indicators: `{context['is_go']}`",
        f"- Installer-like: `{context['installer_like']}`",
        f"- Sparse imports: `{context['has_sparse_imports']}`",
        f"- High runtime noise: `{context['has_high_runtime_noise']}`",
        f"- Context rationale: `{'; '.join(context['rationale']) if context['rationale'] else 'none'}`",
        "",
        "## Interpretation",
        "",
        f"- Analyst summary: {interpretation.get('analyst_summary', 'none')}",
        f"- Strongest evidence: `{', '.join(interpretation.get('strongest_evidence', [])) or 'none'}`",
        f"- Suppressed or contextual evidence: `{', '.join(interpretation.get('suppressed_or_contextual_evidence', [])) or 'none'}`",
        "",
        "## Top Findings",
        "",
    ]
    lines.extend(
        [f"- {finding}" for finding in findings["executive_summary"]["top_findings"]]
        or ["- No strong static findings identified."]
    )

    lines.extend(["", "## Behavior Chains", ""])
    matched_chains = [chain for chain in behavior_chains.values() if chain["matched"]]
    if matched_chains:
        for name, chain in sorted(behavior_chains.items()):
            if not chain["matched"]:
                continue
            evidence = ", ".join(chain.get("evidence", [])[:3]) or "none"
            sources = ", ".join(chain.get("evidence_sources", [])[:3]) or "none"
            lines.append(
                f"- `{name}` confidence=`{chain['confidence']}` evidence=`{evidence}` sources=`{sources}`"
            )
    else:
        lines.append("- No composed behavior chains were identified.")

    lines.extend(["", "## Likely Intent", ""])
    if intent_inference["candidates"]:
        for candidate in intent_inference["candidates"]:
            evidence = ", ".join(candidate.get("evidence", [])[:3]) or "none"
            rationale = ", ".join(candidate.get("rationale", [])[:2]) or "none"
            suppressed = ", ".join(candidate.get("suppressed_by_context", [])[:2]) or "none"
            lines.append(
                f"- `{candidate['name']}` score=`{candidate.get('score', 0)}` confidence=`{candidate['confidence']}` evidence=`{evidence}` rationale=`{rationale}` suppressed=`{suppressed}`"
            )
    else:
        lines.append("- No intent hypotheses were recorded.")

    lines.extend(["", "## Signal Scoring", ""])
    lines.append(
        f"- Dominant signal classes: `{', '.join(analysis_summary.get('dominant_signal_classes', [])) or 'none'}`"
    )
    lines.append(
        f"- Suppressed signal classes: `{', '.join(analysis_summary.get('suppressed_signal_classes', [])) or 'none'}`"
    )
    for item in analysis_summary.get("score_breakdown", [])[:8]:
        lines.append(
            f"- `{item['signal_class']}` tier=`{item['tier']}` delta=`{item['delta']}` suppressed=`{item['suppressed']}` reason=`{item['reason']}`"
        )

    lines.extend(["", "## Analyst-Ready Findings", ""])
    if findings["analyst_ready"]:
        for finding in findings["analyst_ready"]:
            evidence = ", ".join(finding.get("evidence", [])[:3]) or "none"
            lines.append(
                f"- `{finding['type']}` `{finding['name']}` confidence=`{finding['confidence']}` evidence=`{evidence}`"
            )
    else:
        lines.append("- No analyst-ready high-confidence findings were identified.")

    lines.extend(["", "## Contextual / Low-Confidence Findings", ""])
    if findings["contextual"]:
        for finding in findings["contextual"]:
            evidence = ", ".join(finding.get("evidence", [])[:3]) or "none"
            notes = ", ".join(finding.get("notes", [])[:2]) or "none"
            lines.append(
                f"- `{finding['type']}` `{finding['name']}` evidence=`{evidence}` notes=`{notes}`"
            )
    else:
        lines.append("- No contextual findings were recorded.")

    lines.extend(["", "## Interpretation Notes", ""])
    if interpretation["notes"]:
        for note in interpretation["notes"]:
            evidence = ", ".join(note.get("evidence", [])[:3]) or "none"
            lines.append(f"- `{note['code']}`: {note['summary']} Evidence: `{evidence}`")
    else:
        lines.append("- No benign-context guardrail notes were triggered.")

    lines.extend(["", "## Grouped String Evidence", ""])
    grouped_domains = strings["grouped_domains"]
    matched_domains = [item for item in grouped_domains.values() if item["matched"]]
    if matched_domains:
        for name, domain in sorted(grouped_domains.items()):
            if not domain["matched"]:
                continue
            evidence = ", ".join(domain["evidence"][:3]) or "none"
            categories = ", ".join(domain["source_categories"]) or "none"
            lines.append(
                f"- `{name}` count=`{domain['count']}` categories=`{categories}` evidence=`{evidence}`"
            )
    else:
        lines.append("- No grouped string domains were matched.")

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
            f"- Suppressed file paths: `{_format_artifact_entries(iocs.get('suppressed', {}).get('file_paths', []))}`",
            f"- Suppressed commands: `{_format_artifact_entries(iocs.get('suppressed', {}).get('commands', []))}`",
            f"- Raw IOC count: `{iocs['raw_summary']['total']}`",
            f"- IOC quality counts: `clean={ioc_quality['clean']} noisy={ioc_quality['noisy']} malformed={ioc_quality['malformed']} contextual_only={ioc_quality['contextual_only']}`",
            "",
            "## YARA Status",
            "",
            f"- Health: `{yara.get('yara_health', 'unknown')}`",
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
            f"- Reasoning-eligible strings: `{reasoning_quality['reasoning_eligible_count']}`",
            f"- Suppressed strings: `{reasoning_quality['suppressed_count']}`",
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
