"""Tests for string extraction helpers."""

from __future__ import annotations

from staticprep.analyzers.strings import (
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
        "powershell": "(?i)powershell(?:\\.exe)?",
        "url": "(?i)https?://[^\\s]+",
    }

    result = filter_suspicious_strings(strings, patterns)

    assert result == [
        {"pattern": "powershell", "value": "powershell.exe -enc aaa"},
        {"pattern": "url", "value": "http://example.com"},
    ]
