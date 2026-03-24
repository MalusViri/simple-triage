"""Tests for IOC extraction and string previews."""

from __future__ import annotations

from staticprep.analyzers.iocs import build_interesting_strings_preview, extract_iocs


def test_extract_iocs_deduplicates_and_normalizes():
    suspicious_matches = [
        {"pattern": "url", "value": "http://example.com", "match": "http://example.com"},
        {"pattern": "url", "value": "http://example.com", "match": "http://example.com"},
        {"pattern": "powershell", "value": "powershell.exe -enc AAA", "match": "powershell.exe"},
        {"pattern": "mutex_like", "value": "Global\\Mutex123", "match": "Global\\Mutex123"},
    ]
    categorized = {
        "urls": ["http://example.com"],
        "ips": [],
        "domains": ["Example.COM"],
        "registry_paths": [],
        "file_paths": [],
        "commands_or_lolbins": [],
        "powershell": ["powershell.exe"],
        "appdata_or_temp": [],
        "other": [],
    }

    result = extract_iocs(suspicious_matches, categorized)

    assert result["urls"] == ["http://example.com"]
    assert result["domains"] == ["example.com"]
    assert result["mutexes"] == ["Global\\Mutex123"]
    assert result["commands"] == ["powershell.exe -enc AAA"]


def test_interesting_strings_preview_prefers_high_value_categories():
    categorized = {
        "urls": ["http://example.com"],
        "ips": [],
        "domains": ["example.com"],
        "registry_paths": ["HKEY_CURRENT_USER\\Software\\Test"],
        "file_paths": ["C:\\Temp\\dropper.exe"],
        "commands_or_lolbins": ["cmd.exe"],
        "powershell": ["powershell.exe"],
        "appdata_or_temp": ["AppData\\Roaming"],
        "other": [],
    }
    iocs = {
        "urls": ["http://example.com"],
        "ips": [],
        "domains": ["example.com"],
        "registry_paths": ["HKEY_CURRENT_USER\\Software\\Test"],
        "file_paths": ["C:\\Temp\\dropper.exe"],
        "mutexes": [],
        "commands": ["powershell.exe -enc AAA", "cmd.exe /c whoami"],
    }

    result = build_interesting_strings_preview(categorized, iocs, limit=4)

    assert result == [
        "http://example.com",
        "powershell.exe",
        "powershell.exe -enc AAA",
        "cmd.exe /c whoami",
    ]
