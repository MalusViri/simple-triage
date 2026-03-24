"""Analysis summary and entropy assessment helpers."""

from __future__ import annotations

from typing import Any


def assess_packed_status(
    pe_info: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Assess whether a PE appears packed based on high-entropy sections."""
    threshold = analysis_settings["entropy"]["high_entropy_threshold"]
    min_sections = analysis_settings["entropy"]["min_high_entropy_sections_for_likely_packed"]

    if not pe_info.get("attempted", False):
        return {
            "attempted": False,
            "succeeded": False,
            "skipped": True,
            "error": pe_info.get("error") or "Entropy assessment skipped.",
            "high_entropy_sections": [],
            "likely_packed": False,
            "rationale": "PE analysis was skipped, so entropy-based packing assessment was not performed.",
            "threshold_used": threshold,
        }

    if not pe_info.get("succeeded", False) or not pe_info.get("is_pe", False):
        return {
            "attempted": True,
            "succeeded": False,
            "skipped": False,
            "error": pe_info.get("error") or "PE metadata unavailable.",
            "high_entropy_sections": [],
            "likely_packed": False,
            "rationale": "Entropy-based packing assessment requires successful PE parsing.",
            "threshold_used": threshold,
        }

    high_entropy_sections = sorted(
        [
            {"name": section["name"], "entropy": section["entropy"]}
            for section in pe_info.get("sections", [])
            if section.get("entropy", 0.0) >= threshold
        ],
        key=lambda item: (-item["entropy"], item["name"]),
    )
    likely_packed = len(high_entropy_sections) >= min_sections
    rationale = (
        f"{len(high_entropy_sections)} section(s) met or exceeded entropy threshold {threshold}."
        if high_entropy_sections
        else f"No sections met entropy threshold {threshold}."
    )
    if likely_packed:
        rationale = (
            f"Likely packed because {len(high_entropy_sections)} section(s) met or exceeded "
            f"entropy threshold {threshold}."
        )

    return {
        "attempted": True,
        "succeeded": True,
        "skipped": False,
        "error": None,
        "high_entropy_sections": high_entropy_sections,
        "likely_packed": likely_packed,
        "rationale": rationale,
        "threshold_used": threshold,
    }


def build_analysis_summary(
    capabilities: dict[str, dict[str, Any]],
    suspicious_categories: dict[str, list[str]],
    yara_results: dict[str, Any],
    packed_assessment: dict[str, Any],
    environment: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build a deterministic top-level triage summary."""
    weights = analysis_settings["scoring"]["weights"]
    thresholds = analysis_settings["scoring"]["severity_thresholds"]

    score = 0
    reasons: list[str] = []
    top_findings: list[str] = []

    high_caps = sorted(
        [name for name, data in capabilities.items() if data["matched"] and data["confidence"] == "high"]
    )
    medium_caps = sorted(
        [name for name, data in capabilities.items() if data["matched"] and data["confidence"] == "medium"]
    )
    low_caps = sorted(
        [name for name, data in capabilities.items() if data["matched"] and data["confidence"] == "low"]
    )

    if high_caps:
        score += len(high_caps) * weights["high_confidence_capability"]
        reasons.append(f"{len(high_caps)} high-confidence capability match(es)")
        top_findings.append(f"High-confidence capabilities: {', '.join(high_caps[:3])}")
    if medium_caps:
        score += len(medium_caps) * weights["medium_confidence_capability"]
        reasons.append(f"{len(medium_caps)} medium-confidence capability match(es)")
    if low_caps:
        score += len(low_caps) * weights["low_confidence_capability"]
        reasons.append(f"{len(low_caps)} low-confidence capability match(es)")

    if yara_results.get("match_count", 0):
        score += yara_results["match_count"] * weights["yara_hit"]
        reasons.append(f"{yara_results['match_count']} YARA match(es)")
        top_findings.append(f"YARA hits: {', '.join(match['rule'] for match in yara_results['matches'][:3])}")

    high_entropy_sections = packed_assessment.get("high_entropy_sections", [])
    if high_entropy_sections:
        score += len(high_entropy_sections) * weights["high_entropy_section"]
        reasons.append(f"{len(high_entropy_sections)} high-entropy PE section(s)")
        top_findings.append(
            "High-entropy sections: "
            + ", ".join(section["name"] for section in high_entropy_sections[:3])
        )

    if packed_assessment.get("likely_packed"):
        score += weights["likely_packed"]
        reasons.append("Entropy profile suggests the sample may be packed")
        top_findings.append("Likely packed based on PE section entropy")

    if suspicious_categories.get("urls"):
        score += len(suspicious_categories["urls"]) * weights["suspicious_url"]
        reasons.append(f"{len(suspicious_categories['urls'])} URL indicator(s)")
    if suspicious_categories.get("registry_paths"):
        score += len(suspicious_categories["registry_paths"]) * weights["suspicious_registry_path"]
        reasons.append(f"{len(suspicious_categories['registry_paths'])} registry path indicator(s)")
    if suspicious_categories.get("commands_or_lolbins"):
        score += len(suspicious_categories["commands_or_lolbins"]) * weights["suspicious_command"]
        reasons.append(
            f"{len(suspicious_categories['commands_or_lolbins'])} command or LOLBin indicator(s)"
        )
    if suspicious_categories.get("powershell"):
        score += len(suspicious_categories["powershell"]) * weights["suspicious_powershell"]
        reasons.append(f"{len(suspicious_categories['powershell'])} PowerShell indicator(s)")
        top_findings.append("PowerShell-related strings were identified")

    if environment.get("degraded_mode"):
        score += weights["degraded_mode_penalty"]
        reasons.append("Runtime degraded mode reduced available evidence")
        top_findings.append("Analysis ran in degraded mode")

    score = max(0, min(score, 100))
    if score >= thresholds["high"]:
        severity = "high"
        recommended_next_step = "investigate_deeper"
    elif score >= thresholds["medium"]:
        severity = "medium"
        recommended_next_step = "review_manually"
    else:
        severity = "low"
        recommended_next_step = "archive"

    if not top_findings:
        top_findings.append("No strong static indicators were identified")

    return {
        "severity": severity,
        "score": score,
        "top_findings": top_findings[:5],
        "reasons": reasons[:10],
        "recommended_next_step": recommended_next_step,
    }
