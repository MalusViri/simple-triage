"""String extraction helpers."""

from __future__ import annotations

import re
from pathlib import Path


ASCII_RE_TEMPLATE = rb"[ -~]{%d,}"
UTF16_RE_TEMPLATE = rb"(?:(?:[ -~]\x00)){%d,}"


def extract_ascii_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings from bytes."""
    pattern = re.compile(ASCII_RE_TEMPLATE % min_length)
    return [match.decode("ascii", errors="ignore") for match in pattern.findall(data)]


def extract_utf16le_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract UTF-16LE strings from bytes."""
    pattern = re.compile(UTF16_RE_TEMPLATE % min_length)
    return [match.decode("utf-16le", errors="ignore") for match in pattern.findall(data)]


def extract_strings_from_file(path: Path, min_length: int = 4) -> tuple[list[str], list[str]]:
    """Extract ASCII and UTF-16LE strings from a file."""
    data = path.read_bytes()
    return extract_ascii_strings(data, min_length), extract_utf16le_strings(data, min_length)


def _normalize_patterns_config(config: dict[str, object]) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Normalize suspicious string config from disk."""
    if "patterns" in config:
        patterns = config.get("patterns", {})
        categories = config.get("categories", {})
        return dict(patterns), {
            name: list(values) for name, values in dict(categories).items()
        }

    legacy_patterns = {name: str(value) for name, value in config.items()}
    return legacy_patterns, {"other": sorted(legacy_patterns)}


def filter_suspicious_strings(
    strings: list[str],
    patterns_config: dict[str, object],
) -> tuple[list[dict[str, str]], dict[str, list[str]]]:
    """Return suspicious strings matched against configured regex patterns."""
    matches: list[dict[str, str]] = []
    patterns, categories = _normalize_patterns_config(patterns_config)
    compiled = {name: re.compile(pattern) for name, pattern in sorted(patterns.items())}
    for value in strings:
        for name, regex in compiled.items():
            found = regex.search(value)
            if found:
                matches.append(
                    {
                        "pattern": name,
                        "value": value,
                        "match": found.group(0),
                    }
                )
    matches.sort(key=lambda item: (item["pattern"], item["value"]))
    categorized = categorize_suspicious_strings(matches, categories)
    return matches, categorized


def categorize_suspicious_strings(
    matches: list[dict[str, str]],
    categories: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Group suspicious string matches into analyst-facing categories."""
    pattern_to_categories: dict[str, list[str]] = {}
    for category, pattern_names in sorted(categories.items()):
        for pattern_name in pattern_names:
            pattern_to_categories.setdefault(pattern_name, []).append(category)

    results = {
        "urls": [],
        "ips": [],
        "domains": [],
        "registry_paths": [],
        "file_paths": [],
        "commands_or_lolbins": [],
        "powershell": [],
        "appdata_or_temp": [],
        "other": [],
    }

    seen: dict[str, set[str]] = {name: set() for name in results}
    for match in matches:
        assigned = False
        for category in pattern_to_categories.get(match["pattern"], []):
            highlighted_value = match["value"] if category in {"powershell", "commands_or_lolbins"} else match.get("match", match["value"])
            if highlighted_value not in seen[category]:
                results[category].append(highlighted_value)
                seen[category].add(highlighted_value)
            assigned = True
        highlighted_value = match.get("match", match["value"])
        if not assigned and highlighted_value not in seen["other"]:
            results["other"].append(highlighted_value)
            seen["other"].add(highlighted_value)

    for key in results:
        results[key].sort()
    return results
