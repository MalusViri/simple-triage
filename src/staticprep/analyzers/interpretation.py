"""Interpretation helpers for benign-context and false-positive guardrails."""

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
    packed_assessment: dict[str, Any],
    capabilities: dict[str, dict[str, Any]],
    yara_results: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build cautious interpretation notes that explain likely benign context."""
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

    return {
        "notes": notes,
        "codes": [note["code"] for note in notes],
        "summary": [note["summary"] for note in notes],
    }
