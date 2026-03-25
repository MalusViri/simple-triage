"""Interpretation helpers for analyst-facing cautious reasoning."""

from __future__ import annotations

from typing import Any


def _find_matching_terms(values: list[str], patterns: list[str]) -> list[str]:
    """Return deterministic pattern matches observed in a list of strings."""
    matches: set[str] = set()
    lowered_values = [value.lower() for value in values]
    for pattern in patterns:
        lowered_pattern = pattern.lower()
        if any(lowered_pattern in value for value in lowered_values):
            matches.add(pattern)
    return sorted(matches)


def build_interpretation(
    all_strings: list[str],
    iocs: dict[str, Any],
    context: dict[str, Any],
    behavior_chains: dict[str, Any],
    intent_inference: dict[str, Any],
    analysis_summary: dict[str, Any],
    packed_assessment: dict[str, Any],
    capabilities: dict[str, dict[str, Any]],
    yara_results: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build cautious interpretation notes and concise analyst prose."""
    interpretation_settings = analysis_settings["interpretation"]

    notes: list[dict[str, Any]] = []
    installer_signals = _find_matching_terms(
        all_strings,
        list(interpretation_settings["installer_or_packager_patterns"]),
    )
    certificate_signals = _find_matching_terms(
        all_strings,
        list(interpretation_settings["certificate_or_signing_patterns"]),
    )

    trusted_pki_count = iocs["raw_summary"]["by_classification"]["trusted_pki"]
    installer_artifact_count = iocs["raw_summary"]["by_classification"]["likely_installer_artifact"]
    strong_capability_count = sum(
        1
        for capability in capabilities.values()
        if capability["matched"] and capability["confidence"] in {"high", "medium"}
    )

    if len(installer_signals) >= interpretation_settings["minimum_installer_signals"] or installer_artifact_count >= 2:
        notes.append(
            {
                "code": "likely_installer_or_packaged_app",
                "summary": "Installer or packaged-application strings are present.",
                "evidence": installer_signals[:4],
            }
        )

    if any(term in installer_signals for term in ["electron", "tauri", "nsis", "nullsoft", "squirrel"]):
        notes.append(
            {
                "code": "possible_electron_nsis_tauri_characteristics",
                "summary": "Observed strings overlap with common Electron, NSIS, Squirrel, or Tauri packaging artifacts.",
                "evidence": installer_signals[:4],
            }
        )

    if trusted_pki_count or certificate_signals:
        notes.append(
            {
                "code": "certificate_or_signing_infrastructure_present",
                "summary": "Certificate, revocation, or signing infrastructure artifacts were observed and may be normal packaging noise.",
                "evidence": sorted({*certificate_signals[:3], f"trusted_pki_iocs={trusted_pki_count}"}),
            }
        )

    if (
        packed_assessment.get("likely_packed")
        and strong_capability_count == 0
        and yara_results.get("match_count", 0) == 0
    ):
        notes.append(
            {
                "code": "suspiciousness_may_reflect_compression_or_installer_behavior",
                "summary": "High entropy may reflect compression, bundling, or installer behavior rather than stronger malicious corroboration.",
                "evidence": [
                    section["name"] for section in packed_assessment.get("high_entropy_sections", [])[:3]
                ],
            }
        )

    primary_intent = intent_inference.get("primary", "ambiguous_requires_manual_review")
    strongest_evidence: list[str] = []
    suppressed_evidence: list[str] = []
    for chain_name, chain in sorted(behavior_chains.items()):
        if chain.get("matched"):
            strongest_evidence.extend(chain.get("evidence", [])[:2])
    strongest_evidence.extend(analysis_summary.get("top_findings", [])[:2])
    strongest_evidence = list(dict.fromkeys(item for item in strongest_evidence if item))[
        : interpretation_settings["max_strongest_evidence_items"]
    ]

    for item in analysis_summary.get("suppressed_signal_classes", []):
        suppressed_evidence.append(item.replace("_", " "))
    for artifact_type, entries in sorted(iocs.get("suppressed", {}).items()):
        if entries:
            suppressed_evidence.append(
                f"{artifact_type} suppressed for evidence hygiene"
            )
    suppressed_evidence = list(dict.fromkeys(suppressed_evidence))[
        : interpretation_settings["max_suppressed_evidence_items"]
    ]

    if primary_intent == "likely_downloader" and behavior_chains.get("download_write_execute_chain", {}).get("matched"):
        analyst_summary = (
            "This sample demonstrates a clear download, write, and execute chain supported by "
            f"{', '.join(strongest_evidence[:3]) or 'corroborated static evidence'}, which strongly suggests downloader-like behavior."
        )
    elif primary_intent == "likely_installer_or_packaged_app":
        analyst_summary = (
            "This sample appears to be a packaged or installer-like application. "
            "High entropy or generic network residue is present, but the stronger context is packaging or runtime related rather than a clear malicious chain."
        )
    elif primary_intent == "likely_packed_loader":
        analyst_summary = (
            "This sample appears compressed or packed and also shows corroborating execution-oriented evidence, which keeps loader-like behavior in scope."
        )
    elif primary_intent == "likely_managed_obfuscated_payload":
        analyst_summary = (
            "This sample shows managed-code context with sparse imports and additional suspicious corroboration, which is consistent with an obfuscated .NET payload."
        )
    else:
        analyst_summary = (
            "This sample contains mixed static evidence without a single dominant interpretation. "
            "Manual review should focus on the strongest corroborated findings and the evidence that was intentionally suppressed."
        )

    if context.get("installer_like") and not behavior_chains.get("download_write_execute_chain", {}).get("matched"):
        quick_assessment = "Installer or packaged-app context is dominant; suspicious residue appears limited or weak."
    elif behavior_chains.get("download_write_execute_chain", {}).get("matched"):
        quick_assessment = "Corroborated execution-oriented behavior is present and outweighs generic context."
    elif context.get("is_go") and packed_assessment.get("likely_packed"):
        quick_assessment = "Go runtime context weakens entropy-only packing suspicion."
    else:
        quick_assessment = "Suspicion is driven by a limited set of static indicators and should be interpreted cautiously."

    return {
        "notes": notes,
        "codes": [note["code"] for note in notes],
        "summary": [note["summary"] for note in notes],
        "quick_assessment": quick_assessment,
        "analyst_summary": analyst_summary,
        "strongest_evidence": strongest_evidence,
        "suppressed_or_contextual_evidence": suppressed_evidence,
    }
