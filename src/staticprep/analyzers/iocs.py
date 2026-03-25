"""IOC extraction, classification, and analyst-facing curation helpers."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from staticprep.analyzers.evidence import assess_evidence_quality


IOC_TYPES = (
    "urls",
    "ips",
    "domains",
    "registry_paths",
    "file_paths",
    "mutexes",
    "commands",
)

CONTEXTUAL_CLASSES = {
    "low_confidence",
    "trusted_pki",
    "likely_build_artifact",
    "likely_installer_artifact",
    "contextual_only",
}


def _normalize_value(value: str) -> str:
    """Normalize extracted indicator text for deterministic output."""
    return value.strip().strip("\"'")


def _normalize_command(match: dict[str, str]) -> str:
    """Normalize suspicious command-like strings without keeping surrounding prose."""
    raw_value = _normalize_value(match["value"])
    matched_value = _normalize_value(match.get("match", raw_value))
    lowered = raw_value.lower()
    command_prefixes = (
        "powershell",
        "cmd",
        "rundll32",
        "regsvr32",
        "mshta",
        "certutil",
        "bitsadmin",
        "wmic",
        "schtasks",
        "wscript",
        "cscript",
        "msiexec",
    )
    if lowered.startswith(command_prefixes):
        return raw_value
    return matched_value


def extract_iocs(
    suspicious_matches: list[dict[str, str]],
    categorized_strings: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Build a normalized raw IOC view from suspicious string analysis."""
    mutexes = sorted(
        {
            _normalize_value(match.get("match", match["value"]))
            for match in suspicious_matches
            if match["pattern"] == "mutex_like"
        }
    )

    commands = sorted(
        {
            _normalize_command(match)
            for match in suspicious_matches
            if match["pattern"] in {"powershell", "lolbin", "wscript"}
        }
    )

    return {
        "urls": sorted({_normalize_value(value) for value in categorized_strings.get("urls", [])}),
        "ips": sorted({_normalize_value(value) for value in categorized_strings.get("ips", [])}),
        "domains": sorted(
            {_normalize_value(value.lower()) for value in categorized_strings.get("domains", [])}
        ),
        "registry_paths": sorted(
            {_normalize_value(value) for value in categorized_strings.get("registry_paths", [])}
        ),
        "file_paths": sorted(
            {_normalize_value(value) for value in categorized_strings.get("file_paths", [])}
        ),
        "mutexes": mutexes,
        "commands": commands,
    }
def _safe_parse_url(value: str) -> tuple[object | None, list[str]]:
    """Parse URL candidates without allowing malformed authorities to abort analysis."""
    try:
        return urlparse(value), []
    except ValueError:
        return None, ["invalid_url_structure"]


def _contains_any(value: str, patterns: list[str]) -> bool:
    lowered = value.lower()
    return any(pattern.lower() in lowered for pattern in patterns)


def _context_matches(value: str, context_strings: list[str], patterns: list[str]) -> bool:
    """Return whether the IOC value appears near contextual language markers."""
    lowered_value = value.lower()
    for candidate in context_strings:
        lowered_candidate = candidate.lower()
        if lowered_value in lowered_candidate and _contains_any(lowered_candidate, patterns):
            return True
    return False


def _classify_url(value: str, settings: dict[str, object]) -> tuple[str, list[str]]:
    parsed, parse_errors = _safe_parse_url(value)
    if parsed is None:
        return "malformed", parse_errors

    try:
        host = (parsed.hostname or "").lower()
    except ValueError:
        return "malformed", ["invalid_url_structure"]

    combined = f"{host}{parsed.path}".lower()
    reasons: list[str] = []

    if not host or "." not in host:
        return "malformed", ["missing_or_invalid_host"]

    if _contains_any(combined, list(settings["trusted_pki_domains_or_patterns"])):
        return "trusted_pki", ["certificate_or_revocation_infrastructure"]

    if _contains_any(combined, list(settings["installer_artifact_patterns"])):
        return "likely_installer_artifact", ["installer_or_packager_keyword"]

    if _contains_any(combined, list(settings["build_artifact_patterns"])):
        return "likely_build_artifact", ["build_or_debugging_artifact"]

    if parsed.scheme.lower() not in {"http", "https"}:
        return "low_confidence", ["non_http_scheme"]

    reasons.append("valid_network_indicator")
    return "high_confidence", reasons


def _classify_domain(value: str, settings: dict[str, object]) -> tuple[str, list[str]]:
    lowered = value.lower()
    if ".." in lowered or lowered.startswith((".", "-")) or lowered.endswith((".", "-")):
        return "malformed", ["invalid_domain_structure"]
    if ".-" in lowered or "-." in lowered:
        return "malformed", ["invalid_domain_label"]
    if _contains_any(lowered, list(settings["trusted_pki_domains_or_patterns"])):
        return "trusted_pki", ["certificate_or_revocation_infrastructure"]
    if _contains_any(lowered, list(settings["installer_artifact_patterns"])):
        return "likely_installer_artifact", ["installer_or_packager_keyword"]
    if _contains_any(lowered, list(settings["build_artifact_patterns"])):
        return "likely_build_artifact", ["build_or_debugging_artifact"]
    return "high_confidence", ["valid_domain_indicator"]


def _classify_ip(
    value: str,
    settings: dict[str, object],
    context_strings: list[str],
    binary_context: dict[str, object] | None,
) -> tuple[str, list[str]]:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return "malformed", ["invalid_ipv4_address"]

    semantic = settings.get("semantic_ip_rules", {})

    if value in settings["contextual_ip_values"]:
        return "contextual_only", ["manifest_or_version_like_value"]
    if value in semantic.get("local_only_ip_values", []):
        return "contextual_only", ["local_only_address"]
    if _context_matches(value, context_strings, semantic.get("version_context_terms", [])) and (
        binary_context or {}
    ).get("is_dotnet", False):
        return "contextual_only", ["version_like_runtime_value"]
    if _context_matches(value, context_strings, semantic.get("ping_context_terms", [])):
        return "low_confidence", ["command_or_connectivity_test_context"]
    if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
        return "contextual_only", ["non_routable_special_address"]
    if parsed.is_private:
        return "low_confidence", ["private_address_only"]
    return "high_confidence", ["valid_ipv4_indicator"]


def _classify_registry_path(value: str, settings: dict[str, object]) -> tuple[str, list[str]]:
    lowered = value.lower()
    if "<" in value or ">" in value:
        return "malformed", ["contains_markup_characters"]
    if _contains_any(lowered, list(settings["installer_artifact_patterns"])):
        return "likely_installer_artifact", ["installer_or_packager_keyword"]
    if _contains_any(lowered, list(settings["build_artifact_patterns"])):
        return "likely_build_artifact", ["build_or_debugging_artifact"]
    if "currentversion\\run" in lowered or "\\runonce" in lowered:
        return "high_confidence", ["persistence_related_registry_key"]
    return "low_confidence", ["registry_path_without_strong_context"]


def _classify_file_path(value: str, settings: dict[str, object]) -> tuple[str, list[str]]:
    lowered = value.lower()
    if "<" in value or ">" in value or len(value) < 4:
        return "malformed", ["contains_markup_or_truncated_content"]
    if not (":\\" in value or value.startswith("\\\\")):
        return "malformed", ["invalid_windows_path_structure"]
    if _contains_any(lowered, list(settings["installer_artifact_patterns"])):
        return "likely_installer_artifact", ["installer_or_packager_keyword"]
    if _contains_any(lowered, list(settings["build_artifact_patterns"])):
        return "likely_build_artifact", ["build_or_debugging_artifact"]
    if "\\appdata\\" in lowered or "\\temp\\" in lowered:
        return "low_confidence", ["common_user_writable_path"]
    return "contextual_only", ["path_observed_without_behavioral_context"]


def _classify_command(value: str, settings: dict[str, object]) -> tuple[str, list[str]]:
    lowered = value.lower()
    if _contains_any(lowered, list(settings["command_high_confidence_terms"])):
        return "high_confidence", ["strong_suspicious_command_pattern"]
    if _contains_any(lowered, list(settings["command_contextual_terms"])):
        return "likely_installer_artifact", ["installer_or_packager_command"]
    if lowered.startswith(("powershell", "cmd", "rundll32", "regsvr32", "mshta", "certutil")):
        return "low_confidence", ["generic_lolbin_or_script_host_usage"]
    return "contextual_only", ["command_without_additional_context"]


def _classify_mutex(value: str, settings: dict[str, object]) -> tuple[str, list[str]]:
    lowered = value.lower()
    if _contains_any(lowered, list(settings["mutex_contextual_terms"])):
        return "likely_installer_artifact", ["installer_or_packager_mutex_name"]
    if len(value) < 8:
        return "malformed", ["too_short_for_reliable_mutex"]
    return "low_confidence", ["mutex_like_string_without_behavioral_context"]


def _classify_artifact(
    artifact_type: str,
    value: str,
    settings: dict[str, object],
    context_strings: list[str],
    binary_context: dict[str, object] | None,
) -> tuple[str, list[str]]:
    if artifact_type == "urls":
        return _classify_url(value, settings)
    if artifact_type == "domains":
        return _classify_domain(value, settings)
    if artifact_type == "ips":
        return _classify_ip(value, settings, context_strings, binary_context)
    if artifact_type == "registry_paths":
        return _classify_registry_path(value, settings)
    if artifact_type == "file_paths":
        return _classify_file_path(value, settings)
    if artifact_type == "commands":
        return _classify_command(value, settings)
    if artifact_type == "mutexes":
        return _classify_mutex(value, settings)
    return "contextual_only", ["uncategorized_artifact_type"]


def classify_iocs(
    raw_iocs: dict[str, list[str]],
    analysis_settings: dict[str, object],
    context_strings: list[str] | None = None,
    binary_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Classify raw IOC values into analyst-facing confidence buckets."""
    settings = analysis_settings["artifact_filters"]
    per_type_limit = analysis_settings["analyst_highlight_limits"]["default_per_type"]
    context_strings = context_strings or []

    classified: dict[str, list[dict[str, object]]] = {artifact_type: [] for artifact_type in IOC_TYPES}
    high_confidence: dict[str, list[dict[str, object]]] = {artifact_type: [] for artifact_type in IOC_TYPES}
    contextual: dict[str, list[dict[str, object]]] = {artifact_type: [] for artifact_type in IOC_TYPES}
    suppressed: dict[str, list[dict[str, object]]] = {artifact_type: [] for artifact_type in IOC_TYPES}
    raw_summary = {
        "total": 0,
        "by_type": {artifact_type: 0 for artifact_type in IOC_TYPES},
        "by_classification": {
            "high_confidence": 0,
            "low_confidence": 0,
            "malformed": 0,
            "trusted_pki": 0,
            "likely_build_artifact": 0,
            "likely_installer_artifact": 0,
            "contextual_only": 0,
        },
        "by_quality": {
            "clean": 0,
            "noisy": 0,
            "malformed": 0,
            "contextual_only": 0,
        },
    }

    for artifact_type in IOC_TYPES:
        for value in raw_iocs.get(artifact_type, []):
            classification, reasons = _classify_artifact(
                artifact_type,
                value,
                settings,
                context_strings,
                binary_context,
            )
            quality_type = (
                "file_path"
                if artifact_type == "file_paths"
                else "command"
                if artifact_type == "commands"
                else "mutex"
                if artifact_type == "mutexes"
                else "suspicious_string"
            )
            quality = assess_evidence_quality(value, quality_type, analysis_settings)
            entry = {
                "value": value,
                "classification": classification,
                "reasons": reasons,
                "artifact_type": artifact_type,
                "quality": quality["quality"],
                "allowed_for_reasoning": quality["allowed_for_reasoning"],
                "quality_reasons": quality["quality_reasons"],
            }
            classified[artifact_type].append(entry)
            raw_summary["total"] += 1
            raw_summary["by_type"][artifact_type] += 1
            raw_summary["by_classification"][classification] += 1
            raw_summary["by_quality"][quality["quality"]] += 1
            if not quality["allowed_for_reasoning"]:
                suppressed[artifact_type].append(entry)
            if classification == "high_confidence" and quality["allowed_for_reasoning"]:
                high_confidence[artifact_type].append(entry)
            elif classification in CONTEXTUAL_CLASSES:
                contextual[artifact_type].append(entry)

    for artifact_type in IOC_TYPES:
        classified[artifact_type] = sorted(classified[artifact_type], key=lambda item: item["value"])
        high_confidence[artifact_type] = sorted(
            high_confidence[artifact_type],
            key=lambda item: item["value"],
        )[:per_type_limit]
        contextual[artifact_type] = sorted(
            contextual[artifact_type],
            key=lambda item: item["value"],
        )[:per_type_limit]
        suppressed[artifact_type] = sorted(
            suppressed[artifact_type],
            key=lambda item: item["value"],
        )[:per_type_limit]

    return {
        "classified": classified,
        "high_confidence": high_confidence,
        "contextual": contextual,
        "suppressed": suppressed,
        "raw_summary": raw_summary,
    }


def build_interesting_strings_preview(
    categorized_strings: dict[str, list[str]],
    iocs: dict[str, object],
    limit: int = 8,
) -> list[str]:
    """Return a short deterministic preview that favors analyst-ready strings."""
    high_confidence = iocs.get("high_confidence", {})
    contextual = iocs.get("contextual", {})
    reasoning_categories = iocs.get("reasoning_categories", categorized_strings)
    ordered_groups = [
        [entry["value"] for entry in high_confidence.get("urls", [])],
        [entry["value"] for entry in high_confidence.get("commands", [])],
        reasoning_categories.get("powershell", []),
        [entry["value"] for entry in high_confidence.get("registry_paths", [])],
        [entry["value"] for entry in high_confidence.get("domains", [])],
        [entry["value"] for entry in contextual.get("commands", [])],
        reasoning_categories.get("commands_or_lolbins", []),
        reasoning_categories.get("file_paths", []),
    ]

    preview: list[str] = []
    seen: set[str] = set()
    for group in ordered_groups:
        for value in group:
            normalized = _normalize_value(value)
            if normalized and normalized not in seen:
                preview.append(normalized)
                seen.add(normalized)
            if len(preview) >= limit:
                return preview
    return preview
