"""Tests for string extraction helpers."""

from __future__ import annotations

from staticprep.analyzers.strings import (
    categorize_suspicious_strings,
    extract_ascii_strings,
    extract_utf16le_strings,
    filter_suspicious_strings,
)


def test_extract_ascii_strings():
    data = b"\x00Hello\x00cmd.exe\x00tiny\x00"
    assert extract_ascii_strings(data, min_length=4) == ["Hello", "cmd.exe", "tiny"]


def test_extract_utf16le_strings():
    data = "PowerShell".encode("utf-16le") + b"\x00\x00"
    assert extract_utf16le_strings(data, min_length=4) == ["PowerShell"]


def test_filter_suspicious_strings():
    strings = ["hello", "powershell.exe -enc aaa", "http://example.com"]
    patterns = {
        "patterns": {
            "powershell": "(?i)powershell(?:\\.exe)?",
            "url": "(?i)https?://[^\\s]+",
        },
        "categories": {
            "powershell": ["powershell"],
            "urls": ["url"],
        },
    }

    result, categorized = filter_suspicious_strings(strings, patterns)

    assert result == [
        {
            "pattern": "powershell",
            "value": "powershell.exe -enc aaa",
            "match": "powershell.exe",
        },
        {
            "pattern": "url",
            "value": "http://example.com",
            "match": "http://example.com",
        },
    ]
    assert categorized["powershell"] == ["powershell.exe -enc aaa"]
    assert categorized["urls"] == ["http://example.com"]


def test_categorize_suspicious_strings_groups_expected_buckets():
    matches = [
        {"pattern": "url", "value": "http://example.com"},
        {"pattern": "file_path", "value": "C:\\Temp\\dropper.exe"},
        {"pattern": "lolbin", "value": "cmd.exe /c whoami"},
        {"pattern": "mutex_like", "value": "Global\\Mutex1234"},
    ]
    categories = {
        "urls": ["url"],
        "file_paths": ["file_path"],
        "commands_or_lolbins": ["lolbin"],
        "other": ["mutex_like"],
    }

    result = categorize_suspicious_strings(matches, categories)

    assert result["urls"] == ["http://example.com"]
    assert result["file_paths"] == ["C:\\Temp\\dropper.exe"]
    assert result["commands_or_lolbins"] == ["cmd.exe /c whoami"]
    assert result["other"] == ["Global\\Mutex1234"]
