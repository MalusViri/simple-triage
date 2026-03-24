"""Tests for triage scoring and entropy assessment."""

from __future__ import annotations

from staticprep.analyzers.prioritization import assess_packed_status, build_analysis_summary
from staticprep.config import load_analysis_settings


def test_assess_packed_status_flags_high_entropy_sections():
    settings = load_analysis_settings()
    pe_info = {
        "attempted": True,
        "succeeded": True,
        "skipped": False,
        "error": None,
        "is_pe": True,
        "sections": [
            {"name": ".text", "entropy": 7.8},
            {"name": ".rdata", "entropy": 4.2},
        ],
    }

    result = assess_packed_status(pe_info, settings)

    assert result["likely_packed"] is True
    assert result["high_entropy_sections"] == [{"name": ".text", "entropy": 7.8}]
    assert result["threshold_used"] == 7.2


def test_build_analysis_summary_is_deterministic():
    settings = load_analysis_settings()
    capabilities = {
        "networking": {
            "matched": True,
            "confidence": "high",
            "evidence": ["connect", "http://", "networking"],
        },
        "persistence": {
            "matched": True,
            "confidence": "medium",
            "evidence": ["Run\\"],
        },
    }
    suspicious_categories = {
        "urls": ["http://example.com"],
        "ips": [],
        "domains": ["example.com"],
        "registry_paths": ["HKEY_CURRENT_USER\\Software\\Test"],
        "file_paths": [],
        "commands_or_lolbins": ["cmd.exe"],
        "powershell": ["powershell.exe"],
        "appdata_or_temp": [],
        "other": [],
    }
    yara_results = {
        "match_count": 1,
        "matches": [{"rule": "SuspiciousRule", "tags": [], "meta": {}}],
    }
    packed_assessment = {
        "high_entropy_sections": [{"name": ".text", "entropy": 7.8}],
        "likely_packed": True,
    }
    environment = {"degraded_mode": False}

    result = build_analysis_summary(
        capabilities=capabilities,
        suspicious_categories=suspicious_categories,
        yara_results=yara_results,
        packed_assessment=packed_assessment,
        environment=environment,
        analysis_settings=settings,
    )

    assert result["severity"] == "high"
    assert result["score"] == 98
    assert result["recommended_next_step"] == "investigate_deeper"
    assert "1 YARA match(es)" in result["reasons"]


def test_build_analysis_summary_accounts_for_degraded_mode():
    settings = load_analysis_settings()
    result = build_analysis_summary(
        capabilities={},
        suspicious_categories={
            "urls": [],
            "ips": [],
            "domains": [],
            "registry_paths": [],
            "file_paths": [],
            "commands_or_lolbins": [],
            "powershell": [],
            "appdata_or_temp": [],
            "other": [],
        },
        yara_results={"match_count": 0, "matches": []},
        packed_assessment={"high_entropy_sections": [], "likely_packed": False},
        environment={"degraded_mode": True},
        analysis_settings=settings,
    )

    assert result["severity"] == "low"
    assert result["score"] == 0
    assert result["top_findings"] == ["Analysis ran in degraded mode"]
