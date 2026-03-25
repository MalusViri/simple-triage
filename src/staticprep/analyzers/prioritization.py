"""Analysis summary and analyst-facing finding helpers."""

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
    iocs: dict[str, Any],
    yara_results: dict[str, Any],
    packed_assessment: dict[str, Any],
    environment: dict[str, Any],
    analysis_settings: dict[str, Any],
    context: dict[str, Any] | None = None,
    behavior_chains: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic top-level triage summary."""
    weights = analysis_settings["scoring"]["weights"]
    thresholds = analysis_settings["scoring"]["severity_thresholds"]
    adjustments = analysis_settings["scoring"].get("context_adjustments", {})
    context = context or {}
    behavior_chains = behavior_chains or {}

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

    high_iocs = iocs.get("high_confidence", {})
    contextual_iocs = iocs.get("contextual", {})

    url_count = len(high_iocs.get("urls", []))
    registry_count = len(high_iocs.get("registry_paths", []))
    command_count = len(high_iocs.get("commands", []))

    if url_count:
        score += url_count * weights["suspicious_url"]
        reasons.append(f"{url_count} high-confidence URL indicator(s)")
        top_findings.append("High-confidence network indicators were identified")
    if registry_count:
        score += registry_count * weights["suspicious_registry_path"]
        reasons.append(f"{registry_count} high-confidence registry path indicator(s)")
        top_findings.append("Persistence-relevant registry paths were identified")
    if command_count:
        score += command_count * weights["suspicious_command"]
        reasons.append(f"{command_count} high-confidence command indicator(s)")
        top_findings.append("Strong suspicious command strings were identified")
    if contextual_iocs.get("commands"):
        score += len(contextual_iocs["commands"]) * weights["contextual_command"]
        reasons.append(f"{len(contextual_iocs['commands'])} low-confidence command indicator(s)")
        top_findings.append("Command-like strings were identified but some are contextual only")

    for chain_name, chain in sorted(behavior_chains.items()):
        if chain.get("matched"):
            score += weights["behavior_chain"]
            reasons.append(f"Behavior chain matched: {chain_name}")
            top_findings.append(
                chain_name.replace("_", " ")
            )

    if context.get("is_go") and packed_assessment.get("likely_packed"):
        score += adjustments["go_high_entropy_penalty"]
        reasons.append("Go runtime context reduced confidence in entropy-only packing suspicion")

    if (
        context.get("is_dotnet")
        and context.get("has_sparse_imports")
        and (
            packed_assessment.get("likely_packed")
            or capabilities.get("anti_analysis", {}).get("matched")
        )
    ):
        score += adjustments["dotnet_sparse_obfuscated_bonus"]
        reasons.append(".NET plus sparse imports and obfuscation indicators increased suspicion")
        top_findings.append(".NET sparse-import profile with obfuscation indicators")

    if context.get("installer_like"):
        score += adjustments["installer_like_penalty"]
        reasons.append("Installer-like context reduced severity absent stronger corroboration")

    if context.get("has_high_runtime_noise"):
        score += adjustments["runtime_noise_penalty"]
        reasons.append("High runtime-noise context reduced confidence in generic string hits")

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


def build_findings(
    analysis_summary: dict[str, Any],
    capabilities: dict[str, dict[str, Any]],
    iocs: dict[str, Any],
    interpretation: dict[str, Any],
    yara_results: dict[str, Any],
    packed_assessment: dict[str, Any],
    errors: list[dict[str, Any]],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build curated analyst-ready and contextual finding groups."""
    limit = analysis_settings["analyst_highlight_limits"]["top_findings"]
    contextual_limit = analysis_settings["analyst_highlight_limits"]["contextual_findings"]

    analyst_ready: list[dict[str, Any]] = []
    contextual: list[dict[str, Any]] = []

    for capability, data in sorted(capabilities.items()):
        if not data["matched"]:
            continue
        finding = {
            "type": "capability",
            "name": capability,
            "confidence": data["confidence"],
            "evidence": data["evidence"][:3],
            "score": data.get("score", 0),
            "notes": data.get("notes", []),
        }
        if data["confidence"] in {"high", "medium"}:
            analyst_ready.append(finding)
        else:
            contextual.append(finding)

    for artifact_type, entries in sorted(iocs.get("high_confidence", {}).items()):
        for entry in entries:
            analyst_ready.append(
                {
                    "type": "ioc",
                    "name": artifact_type,
                    "confidence": "high",
                    "evidence": [entry["value"]],
                    "classification": entry["classification"],
                    "notes": entry["reasons"],
                }
            )

    for artifact_type, entries in sorted(iocs.get("contextual", {}).items()):
        for entry in entries:
            contextual.append(
                {
                    "type": "ioc",
                    "name": artifact_type,
                    "confidence": "contextual",
                    "evidence": [entry["value"]],
                    "classification": entry["classification"],
                    "notes": entry["reasons"],
                }
            )

    for note in interpretation.get("notes", []):
        contextual.append(
            {
                "type": "interpretation",
                "name": note["code"],
                "confidence": "contextual",
                "evidence": note.get("evidence", [])[:3],
                "notes": [note["summary"]],
            }
        )

    if yara_results.get("match_count", 0):
        analyst_ready.append(
            {
                "type": "yara",
                "name": "yara_matches",
                "confidence": "high",
                "evidence": [match["rule"] for match in yara_results["matches"][:3]],
                "notes": ["Local YARA rules matched the sample"],
            }
        )

    if packed_assessment.get("likely_packed"):
        contextual.append(
            {
                "type": "packing",
                "name": "likely_packed",
                "confidence": "contextual",
                "evidence": [
                    section["name"] for section in packed_assessment.get("high_entropy_sections", [])[:3]
                ],
                "notes": [packed_assessment["rationale"]],
            }
        )

    executive_summary = {
        "worth_deeper_investigation": analysis_summary["recommended_next_step"] != "archive",
        "recommended_next_step": analysis_summary["recommended_next_step"],
        "severity": analysis_summary["severity"],
        "score": analysis_summary["score"],
        "analysis_degraded": any(error["stage"] == "environment" for error in errors),
        "top_findings": analysis_summary["top_findings"],
    }

    raw_references = {
        "suspicious_string_count": iocs["raw_summary"]["total"],
        "ioc_raw_summary": iocs["raw_summary"],
        "artifact_files": [
            "report.json",
            "strings_ascii.txt",
            "strings_utf16.txt",
            "suspicious_strings.txt",
            "imports.json",
            "yara_matches.json",
        ],
    }

    return {
        "executive_summary": executive_summary,
        "analyst_ready": analyst_ready[:limit],
        "contextual": contextual[:contextual_limit],
        "raw_references": raw_references,
    }
