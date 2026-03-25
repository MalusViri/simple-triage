"""Evidence hygiene helpers used before higher-level reasoning."""

from __future__ import annotations

import re
from typing import Any


WINDOWS_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:\\")
WINDOWS_UNC_PATH_RE = re.compile(r"^\\\\[^\\]+\\[^\\]+")
MUTEX_PREFIX_RE = re.compile(r"^(global|local)\\", re.IGNORECASE)
KNOWN_COMMAND_PREFIXES = (
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


def _symbol_ratio(value: str) -> float:
    visible = [char for char in value if not char.isspace()]
    if not visible:
        return 1.0
    symbol_count = sum(1 for char in visible if not char.isalnum() and char not in "\\/:._-%")
    return symbol_count / len(visible)


def _alpha_ratio(value: str) -> float:
    visible = [char for char in value if not char.isspace()]
    if not visible:
        return 0.0
    alpha_count = sum(1 for char in visible if char.isalpha())
    return alpha_count / len(visible)


def _max_symbol_run(value: str) -> int:
    longest = 0
    current = 0
    for char in value:
        if not char.isalnum() and char not in "\\/:._-% ":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _path_segments(value: str) -> list[str]:
    cleaned = value.replace("/", "\\")
    if WINDOWS_DRIVE_PATH_RE.match(cleaned):
        cleaned = cleaned[3:]
    elif cleaned.startswith("\\\\"):
        parts = cleaned.split("\\")
        cleaned = "\\".join(parts[4:]) if len(parts) > 4 else ""
    return [segment for segment in cleaned.split("\\") if segment]


def _looks_binary_noise(value: str, settings: dict[str, Any]) -> bool:
    trimmed = value.strip()
    if not trimmed:
        return True
    symbol_ratio = _symbol_ratio(trimmed)
    alpha_ratio = _alpha_ratio(trimmed)
    max_symbol_run = _max_symbol_run(trimmed)
    if symbol_ratio >= settings["noise_symbol_ratio"]:
        return True
    if max_symbol_run >= settings["max_symbol_run"]:
        return True
    if (
        len(trimmed) >= settings["binary_noise_min_length"]
        and alpha_ratio <= settings["binary_noise_max_alpha_ratio"]
        and symbol_ratio >= settings["binary_noise_symbol_ratio"]
    ):
        return True
    return False


def _is_path_segment_implausible(segment: str, settings: dict[str, Any]) -> bool:
    if not segment:
        return True
    if len(segment) > settings["max_path_segment_length"]:
        return True
    if _looks_binary_noise(segment, settings):
        return True
    return False


def assess_evidence_quality(
    value: str,
    artifact_type: str,
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Return deterministic quality metadata for a reasoning artifact."""
    settings = analysis_settings["evidence_hygiene"]
    normalized = value.strip()
    reasons: list[str] = []
    quality = "clean"
    allowed_for_reasoning = True

    if not normalized:
        return {
            "quality": "malformed",
            "allowed_for_reasoning": False,
            "quality_reasons": ["empty_or_whitespace_only"],
        }

    if _looks_binary_noise(normalized, settings):
        quality = "noisy"
        allowed_for_reasoning = False
        reasons.append("binary_or_symbol_heavy_noise")

    if artifact_type == "suspicious_string":
        lowered = normalized.lower()
        if quality == "clean" and len(normalized) >= settings["contextual_only_min_length"] and lowered in {
            "http://",
            "https://",
        }:
            quality = "contextual_only"
            allowed_for_reasoning = False
            reasons.append("bare_scheme_without_host")

    elif artifact_type == "file_path":
        normalized = normalized.replace("/", "\\")
        if not (
            WINDOWS_DRIVE_PATH_RE.match(normalized) or WINDOWS_UNC_PATH_RE.match(normalized)
        ):
            quality = "malformed"
            allowed_for_reasoning = False
            reasons.append("invalid_windows_path_shape")
        else:
            segments = _path_segments(normalized)
            if not segments:
                quality = "malformed"
                allowed_for_reasoning = False
                reasons.append("missing_path_segments")
            elif any(_is_path_segment_implausible(segment, settings) for segment in segments):
                quality = "malformed"
                allowed_for_reasoning = False
                reasons.append("implausible_or_noise_heavy_path_segment")

    elif artifact_type == "command":
        lowered = normalized.lower()
        if not any(lowered.startswith(prefix) for prefix in KNOWN_COMMAND_PREFIXES):
            if quality == "clean":
                quality = "contextual_only"
                allowed_for_reasoning = False
                reasons.append("command_like_text_without_known_invocation_prefix")
        elif len(normalized) < settings["minimum_command_length"]:
            quality = "malformed"
            allowed_for_reasoning = False
            reasons.append("truncated_command_like_string")

    elif artifact_type == "mutex":
        lowered = normalized.lower()
        if len(normalized) < settings["minimum_mutex_length"]:
            quality = "malformed"
            allowed_for_reasoning = False
            reasons.append("too_short_for_reliable_mutex")
        elif not (
            MUTEX_PREFIX_RE.match(normalized)
            or "\\" in normalized
            or normalized.count("_") >= 1
        ):
            quality = "contextual_only"
            allowed_for_reasoning = False
            reasons.append("weak_mutex_shape")
        elif quality == "clean" and _symbol_ratio(normalized) >= settings["mutex_symbol_ratio"]:
            quality = "noisy"
            allowed_for_reasoning = False
            reasons.append("symbol_heavy_mutex_name")

    if not reasons and quality == "clean":
        reasons.append("reasoning_eligible")

    return {
        "quality": quality,
        "allowed_for_reasoning": allowed_for_reasoning,
        "quality_reasons": reasons,
    }


def annotate_suspicious_string_matches(
    matches: list[dict[str, str]],
    analysis_settings: dict[str, Any],
) -> list[dict[str, Any]]:
    """Annotate suspicious string matches with evidence-quality metadata."""
    annotated: list[dict[str, Any]] = []
    for match in matches:
        metadata = assess_evidence_quality(
            match["value"],
            "suspicious_string",
            analysis_settings,
        )
        annotated.append({**match, **metadata})
    return annotated


def filter_reasoning_strings(
    strings: list[str],
    analysis_settings: dict[str, Any],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Return reasoning-eligible strings plus per-string quality metadata."""
    allowed: list[str] = []
    metadata_entries: list[dict[str, Any]] = []
    seen_allowed: set[str] = set()

    for value in strings:
        metadata = assess_evidence_quality(value, "suspicious_string", analysis_settings)
        metadata_entries.append({"value": value, **metadata})
        if metadata["allowed_for_reasoning"] and value not in seen_allowed:
            allowed.append(value)
            seen_allowed.add(value)

    return allowed, metadata_entries
