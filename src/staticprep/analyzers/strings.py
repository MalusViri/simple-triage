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


def filter_suspicious_strings(
    strings: list[str],
    patterns: dict[str, str],
) -> list[dict[str, str]]:
    """Return suspicious strings matched against configured regex patterns."""
    matches: list[dict[str, str]] = []
    compiled = {name: re.compile(pattern) for name, pattern in sorted(patterns.items())}
    for value in strings:
        for name, regex in compiled.items():
            if regex.search(value):
                matches.append({"pattern": name, "value": value})
    matches.sort(key=lambda item: (item["pattern"], item["value"]))
    return matches
