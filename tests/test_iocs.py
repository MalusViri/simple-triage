"""Tests for IOC extraction, filtering, and string previews."""

from __future__ import annotations

from staticprep.analyzers.iocs import (
    build_interesting_strings_preview,
    classify_iocs,
    extract_iocs,
)
from staticprep.config import load_analysis_settings


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


def test_classify_iocs_downgrades_trusted_pki_and_manifest_like_noise():
    settings = load_analysis_settings()
    raw_iocs = {
        "urls": ["http://ocsp.digicert.com/status"],
        "ips": ["1.0.0.0"],
        "domains": ["example-.com"],
        "registry_paths": [],
        "file_paths": ["C:\\build\\release\\app.pdb"],
        "mutexes": [],
        "commands": ["powershell.exe -enc AAA"],
    }

    result = classify_iocs(raw_iocs, settings)

    assert result["classified"]["urls"][0]["classification"] == "trusted_pki"
    assert result["classified"]["ips"][0]["classification"] == "contextual_only"
    assert result["classified"]["domains"][0]["classification"] == "malformed"
    assert result["classified"]["file_paths"][0]["classification"] == "likely_build_artifact"
    assert result["high_confidence"]["urls"] == []
    assert result["high_confidence"]["commands"][0]["classification"] == "high_confidence"


def test_config_driven_ioc_filtering_can_reclassify_entries():
    settings = load_analysis_settings()
    settings["artifact_filters"]["trusted_pki_domains_or_patterns"].append("example.com")
    raw_iocs = {
        "urls": ["https://example.com/crl"],
        "ips": [],
        "domains": ["example.com"],
        "registry_paths": [],
        "file_paths": [],
        "mutexes": [],
        "commands": [],
    }

    result = classify_iocs(raw_iocs, settings)

    assert result["classified"]["urls"][0]["classification"] == "trusted_pki"
    assert result["classified"]["domains"][0]["classification"] == "trusted_pki"


def test_classify_iocs_marks_malformed_url_candidates_without_crashing():
    settings = load_analysis_settings()
    raw_iocs = {
        "urls": ["http://[::1", "https://example.com/path"],
        "ips": [],
        "domains": [],
        "registry_paths": [],
        "file_paths": [],
        "mutexes": [],
        "commands": [],
    }

    result = classify_iocs(raw_iocs, settings)

    assert result["classified"]["urls"] == [
        {
            "value": "http://[::1",
            "classification": "malformed",
            "reasons": ["invalid_url_structure"],
            "artifact_type": "urls",
        },
        {
            "value": "https://example.com/path",
            "classification": "high_confidence",
            "reasons": ["valid_network_indicator"],
            "artifact_type": "urls",
        },
    ]
    assert result["high_confidence"]["urls"] == [
        {
            "value": "https://example.com/path",
            "classification": "high_confidence",
            "reasons": ["valid_network_indicator"],
            "artifact_type": "urls",
        }
    ]
    assert result["contextual"]["urls"] == []
    assert result["raw_summary"]["by_classification"]["malformed"] == 1


def test_classify_iocs_marks_invalid_ipv6_style_url_host_as_malformed():
    settings = load_analysis_settings()
    raw_iocs = {
        "urls": ["http://[fe80::1"],
        "ips": [],
        "domains": [],
        "registry_paths": [],
        "file_paths": [],
        "mutexes": [],
        "commands": [],
    }

    result = classify_iocs(raw_iocs, settings)

    assert result["classified"]["urls"] == [
        {
            "value": "http://[fe80::1",
            "classification": "malformed",
            "reasons": ["invalid_url_structure"],
            "artifact_type": "urls",
        }
    ]
    assert result["high_confidence"]["urls"] == []
    assert result["contextual"]["urls"] == []


def test_interesting_strings_preview_prefers_high_value_categories():
    categorized = {
        "urls": ["http://example.com"],
        "ips": [],
        "domains": ["example.com"],
        "registry_paths": ["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "file_paths": ["C:\\Temp\\dropper.exe"],
        "commands_or_lolbins": ["cmd.exe"],
        "powershell": ["powershell.exe"],
        "appdata_or_temp": ["AppData\\Roaming"],
        "other": [],
    }
    iocs = {
        "high_confidence": {
            "urls": [{"value": "http://example.com", "classification": "high_confidence"}],
            "ips": [],
            "domains": [{"value": "example.com", "classification": "high_confidence"}],
            "registry_paths": [
                {
                    "value": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "classification": "high_confidence",
                }
            ],
            "file_paths": [],
            "mutexes": [],
            "commands": [{"value": "powershell.exe -enc AAA", "classification": "high_confidence"}],
        },
        "contextual": {
            "urls": [],
            "ips": [],
            "domains": [],
            "registry_paths": [],
            "file_paths": [],
            "mutexes": [],
            "commands": [{"value": "cmd.exe /c whoami", "classification": "low_confidence"}],
        },
    }

    result = build_interesting_strings_preview(categorized, iocs, limit=4)

    assert result == [
        "http://example.com",
        "powershell.exe -enc AAA",
        "powershell.exe",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
