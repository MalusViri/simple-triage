"""IOC extraction helpers."""

from __future__ import annotations


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
    )
    if lowered.startswith(command_prefixes):
        return raw_value
    return matched_value


def extract_iocs(
    suspicious_matches: list[dict[str, str]],
    categorized_strings: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Build a normalized IOC view from suspicious string analysis."""
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


def build_interesting_strings_preview(
    categorized_strings: dict[str, list[str]],
    iocs: dict[str, list[str]],
    limit: int = 8,
) -> list[str]:
    """Return a short deterministic preview of the most useful strings."""
    ordered_groups = [
        categorized_strings.get("urls", []),
        categorized_strings.get("powershell", []),
        iocs.get("commands", []),
        categorized_strings.get("registry_paths", []),
        categorized_strings.get("commands_or_lolbins", []),
        categorized_strings.get("appdata_or_temp", []),
        categorized_strings.get("file_paths", []),
        categorized_strings.get("domains", []),
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
