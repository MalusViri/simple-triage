"""Capability inference based on local configuration."""

from __future__ import annotations

from typing import Any

from staticprep.models import CapabilityResult


def _indicator_weight(
    indicator: str,
    source: str,
    capability_settings: dict[str, Any],
) -> tuple[int, str | None]:
    """Return the deterministic weight and note for an indicator."""
    base_weight = capability_settings["source_weights"][source]
    lowered = indicator.lower()
    if lowered in {value.lower() for value in capability_settings["weak_indicators"]}:
        return max(1, base_weight - 1), "weak_generic_indicator"
    if lowered in {value.lower() for value in capability_settings["contextual_indicators"]}:
        return base_weight, "contextual_indicator"
    return base_weight, None


def _confidence_from_score(
    capability: str,
    total_score: int,
    unique_sources: list[str],
    thresholds: dict[str, Any],
) -> str:
    """Return a deterministic confidence value from score and source breadth."""
    overrides = thresholds["per_capability_overrides"].get(capability, {})
    medium_threshold = overrides.get(
        "minimum_score_for_medium",
        thresholds["thresholds"]["minimum_score_for_medium"],
    )
    high_threshold = overrides.get(
        "minimum_score_for_high",
        thresholds["thresholds"]["minimum_score_for_high"],
    )
    high_sources = overrides.get(
        "minimum_sources_for_high",
        thresholds["thresholds"]["minimum_sources_for_high"],
    )

    if total_score >= high_threshold and len(unique_sources) >= high_sources:
        return "high"
    if total_score >= medium_threshold:
        return "medium"
    return "low"


def infer_capabilities(
    capability_map: dict[str, Any],
    apis: list[str],
    strings: list[str],
    yara_matches: list[dict[str, Any]],
    capability_settings: dict[str, Any],
) -> dict[str, CapabilityResult]:
    """Infer capabilities from configured API, string, and YARA indicators."""
    api_set = {api.lower() for api in apis}
    string_values = [value.lower() for value in strings]
    yara_rule_names = {match["rule"].lower() for match in yara_matches}
    yara_tags = {tag.lower() for match in yara_matches for tag in match.get("tags", [])}

    results: dict[str, CapabilityResult] = {}
    for capability, mapping in sorted(capability_map.items()):
        evidence: list[str] = []
        sources: list[str] = []
        notes: list[str] = []
        total_score = 0

        for api in mapping.get("api", []):
            if api.lower() in api_set:
                weight, note = _indicator_weight(api, "API", capability_settings)
                evidence.append(api)
                sources.append("API")
                total_score += weight
                if note and note not in notes:
                    notes.append(note)

        for indicator in mapping.get("strings", []):
            if any(indicator.lower() in value for value in string_values):
                weight, note = _indicator_weight(indicator, "string", capability_settings)
                evidence.append(indicator)
                sources.append("string")
                total_score += weight
                if note and note not in notes:
                    notes.append(note)

        for yara_indicator in mapping.get("yara", []):
            lowered = yara_indicator.lower()
            if lowered in yara_rule_names or lowered in yara_tags:
                weight, note = _indicator_weight(yara_indicator, "YARA", capability_settings)
                evidence.append(yara_indicator)
                sources.append("YARA")
                total_score += weight
                if note and note not in notes:
                    notes.append(note)

        unique_sources = list(dict.fromkeys(sources))
        results[capability] = CapabilityResult(
            matched=bool(evidence),
            evidence=evidence,
            evidence_source=unique_sources,
            evidence_sources=unique_sources,
            confidence=_confidence_from_score(
                capability=capability,
                total_score=total_score,
                unique_sources=unique_sources,
                thresholds=capability_settings,
            ),
            score=total_score,
            notes=notes,
        )

    return results
