"""Capability inference based on local configuration."""

from __future__ import annotations

from typing import Any

from staticprep.models import CapabilityResult


def infer_capabilities(
    capability_map: dict[str, Any],
    apis: list[str],
    strings: list[str],
    yara_matches: list[dict[str, Any]],
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

        for api in mapping.get("api", []):
            if api.lower() in api_set:
                evidence.append(api)
                sources.append("API")

        for indicator in mapping.get("strings", []):
            if any(indicator.lower() in value for value in string_values):
                evidence.append(indicator)
                sources.append("string")

        for yara_indicator in mapping.get("yara", []):
            lowered = yara_indicator.lower()
            if lowered in yara_rule_names or lowered in yara_tags:
                evidence.append(yara_indicator)
                sources.append("YARA")

        results[capability] = CapabilityResult(
            matched=bool(evidence),
            evidence=evidence,
            evidence_source=sources,
        )

    return results
