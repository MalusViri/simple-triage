"""Compact CLI triage summary formatting."""

from __future__ import annotations

from typing import Any


NEXT_STEP_LABELS = {
    "archive": "archive",
    "review_manually": "review manually",
    "investigate_deeper": "investigate deeper",
}


def _first_matched_behavior(report: dict[str, Any]) -> dict[str, Any] | None:
    """Return the highest-priority correlated behavior if present."""
    for behavior in report.get("correlated_behaviors", []):
        if behavior.get("matched"):
            return behavior
    return None


def _format_iocs(report: dict[str, Any], limit: int) -> list[str]:
    """Return a compact analyst-relevant IOC list."""
    iocs = report["iocs"]
    ordered_values: list[str] = []
    seen: set[str] = set()
    groups = [
        iocs.get("high_confidence", {}).get("urls", []),
        iocs.get("high_confidence", {}).get("domains", []),
        iocs.get("high_confidence", {}).get("commands", []),
        iocs.get("high_confidence", {}).get("file_paths", []),
        [
            entry
            for entry in iocs.get("classified", {}).get("file_paths", [])
            if entry.get("allowed_for_reasoning", False)
            and entry.get("classification") in {"low_confidence", "high_confidence"}
        ],
    ]
    for group in groups:
        for entry in group:
            value = entry["value"]
            if value not in seen:
                ordered_values.append(value)
                seen.add(value)
            if len(ordered_values) >= limit:
                return ordered_values
    return ordered_values


def build_cli_triage_summary(report: dict[str, Any]) -> str:
    """Return a compact plain-text triage summary for single-sample analysis."""
    settings = report.get("cli_summary", {})
    primary_behavior = _first_matched_behavior(report)
    analysis_summary = report["analysis_summary"]
    interpretation = report["interpretation"]
    context = report["context"]

    likely_behavior = (
        primary_behavior["summary_label"]
        if primary_behavior
        else report["intent_inference"]["primary"].replace("_", " ")
    )
    next_step = (
        primary_behavior["recommended_next_step"]
        if primary_behavior
        else analysis_summary["recommended_next_step"]
    )
    findings = analysis_summary.get("top_findings", [])[: settings.get("max_top_findings", 4)]
    ioc_values = _format_iocs(report, settings.get("max_iocs", 3))
    next_analysis_path = (
        primary_behavior.get("analyst_next_steps", [])[: settings.get("max_next_steps", 3)]
        if primary_behavior
        else []
    )
    if not next_analysis_path:
        next_analysis_path = [interpretation.get("quick_assessment", "Review the structured artifacts.")]

    lines = [
        f"Sample: {report['sample']['name']}",
        f"SHA256: {report['hashes']['sha256']}",
        "",
        f"Severity: {analysis_summary['severity'].upper()}",
        f"Likely Behavior: {likely_behavior}",
        f"Recommended Next Step: {NEXT_STEP_LABELS.get(next_step, next_step)}",
        "",
        "Top Findings:",
    ]
    lines.extend(f"- {item}" for item in findings or ["No strong static indicators were identified"])

    if ioc_values:
        lines.extend(["", "Notable IOCs:"])
        lines.extend(f"- {value}" for value in ioc_values)

    lines.extend(
        [
            "",
            "Context:",
            f"- .NET: {'yes' if context.get('is_dotnet') else 'no'}",
            f"- Go: {'yes' if context.get('is_go') else 'no'}",
            f"- Packed: {'likely' if context.get('likely_packed') else 'no'}",
            f"- Degraded analysis: {'yes' if report['environment'].get('degraded_mode') else 'no'}",
            "",
            "Next Analysis Path:",
        ]
    )
    lines.extend(f"- {item}" for item in next_analysis_path)
    return "\n".join(lines)
