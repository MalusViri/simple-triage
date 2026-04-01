"""Tests for triage scoring, findings, entropy assessment, and interpretation."""

from __future__ import annotations

from staticprep.analyzers.interpretation import build_interpretation
from staticprep.analyzers.prioritization import (
    assess_packed_status,
    build_analysis_summary,
    build_findings,
)
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


def test_build_analysis_summary_uses_curated_ioc_views():
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
    iocs = {
        "high_confidence": {
            "urls": [{"value": "http://evil.example", "classification": "high_confidence"}],
            "ips": [],
            "domains": [],
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
            "urls": [{"value": "http://ocsp.digicert.com", "classification": "trusted_pki"}],
            "ips": [],
            "domains": [],
            "registry_paths": [],
            "file_paths": [],
            "mutexes": [],
            "commands": [],
        },
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
        iocs=iocs,
        yara_results=yara_results,
        packed_assessment=packed_assessment,
        environment=environment,
        analysis_settings=settings,
    )

    assert result["severity"] == "high"
    assert result["score"] == 85
    assert result["recommended_next_step"] == "investigate_deeper"
    assert "1 validated external URL/domain indicator(s)" in result["reasons"]
    assert "score_breakdown" in result
    assert "dominant_signal_classes" in result


def test_build_analysis_summary_accounts_for_degraded_mode():
    settings = load_analysis_settings()
    result = build_analysis_summary(
        capabilities={},
        iocs={
            "high_confidence": {
                "urls": [],
                "ips": [],
                "domains": [],
                "registry_paths": [],
                "file_paths": [],
                "mutexes": [],
                "commands": [],
            },
            "contextual": {
                "urls": [],
                "ips": [],
                "domains": [],
                "registry_paths": [],
                "file_paths": [],
                "mutexes": [],
                "commands": [],
            },
        },
        yara_results={"match_count": 0, "matches": []},
        packed_assessment={"high_entropy_sections": [], "likely_packed": False},
        environment={"degraded_mode": True},
        analysis_settings=settings,
    )

    assert result["severity"] == "low"
    assert result["score"] == 0
    assert result["top_findings"] == ["Analysis ran in degraded mode"]


def test_build_interpretation_adds_packager_guardrails():
    settings = load_analysis_settings()
    interpretation = build_interpretation(
        all_strings=["Nullsoft Installer", "Electron", "OCSP", "CRL", "app.asar"],
        iocs={
            "suppressed": {
                "urls": [],
                "ips": [],
                "domains": [],
                "registry_paths": [],
                "file_paths": [],
                "mutexes": [],
                "commands": [],
            },
            "raw_summary": {
                "by_classification": {
                    "trusted_pki": 2,
                    "likely_installer_artifact": 2,
                }
            }
        },
        context={
            "installer_like": True,
            "is_go": False,
            "is_dotnet": False,
        },
        behavior_chains={"download_write_execute_chain": {"matched": False}},
        correlated_behaviors=[],
        intent_inference={"primary": "likely_installer_or_packaged_app"},
        analysis_summary={"top_findings": ["Likely packed"], "suppressed_signal_classes": []},
        packed_assessment={"likely_packed": True, "high_entropy_sections": [{"name": ".ndata"}]},
        capabilities={"networking": {"matched": False, "confidence": "low"}},
        yara_results={"match_count": 0},
        analysis_settings=settings,
    )

    assert "likely_installer_or_packaged_app" in interpretation["codes"]
    assert "possible_electron_nsis_tauri_characteristics" in interpretation["codes"]
    assert "certificate_or_signing_infrastructure_present" in interpretation["codes"]
    assert "suspiciousness_may_reflect_compression_or_installer_behavior" in interpretation["codes"]
    assert interpretation["analyst_summary"]


def test_build_findings_separates_analyst_ready_and_contextual_views():
    settings = load_analysis_settings()
    analysis_summary = {
        "recommended_next_step": "review_manually",
        "severity": "medium",
        "score": 42,
        "top_findings": ["High-confidence capabilities: networking"],
    }
    findings = build_findings(
        analysis_summary=analysis_summary,
        capabilities={
            "networking": {
                "matched": True,
                "confidence": "high",
                "evidence": ["connect"],
                "score": 7,
                "notes": [],
            },
            "persistence": {
                "matched": True,
                "confidence": "low",
                "evidence": ["startup"],
                "score": 1,
                "notes": ["weak_generic_indicator"],
            },
        },
        iocs={
            "high_confidence": {
                "urls": [{"value": "http://evil.example", "classification": "high_confidence", "reasons": ["valid_network_indicator"]}],
                "ips": [],
                "domains": [],
                "registry_paths": [],
                "file_paths": [],
                "mutexes": [],
                "commands": [],
            },
            "contextual": {
                "urls": [{"value": "http://ocsp.digicert.com", "classification": "trusted_pki", "reasons": ["certificate_or_revocation_infrastructure"]}],
                "ips": [],
                "domains": [],
                "registry_paths": [],
                "file_paths": [],
                "mutexes": [],
                "commands": [],
            },
            "raw_summary": {"total": 2},
        },
        interpretation={
            "notes": [
                {
                    "code": "certificate_or_signing_infrastructure_present",
                    "summary": "PKI artifacts are present.",
                    "evidence": ["trusted_pki_iocs=1"],
                }
            ]
        },
        yara_results={"match_count": 0, "matches": []},
        packed_assessment={"likely_packed": False, "high_entropy_sections": [], "rationale": "none"},
        errors=[],
        analysis_settings=settings,
    )

    assert findings["executive_summary"]["worth_deeper_investigation"] is True
    assert any(item["type"] == "capability" for item in findings["analyst_ready"])
    assert any(item["type"] == "ioc" for item in findings["analyst_ready"])
    assert any(item["type"] == "interpretation" for item in findings["contextual"])
