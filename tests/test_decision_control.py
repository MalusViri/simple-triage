"""Regression tests for Phase 7.1 decision control and false-positive reduction."""

from __future__ import annotations

from staticprep.analyzers.behavior_correlation import correlate_behaviors
from staticprep.analyzers.contextual_analysis import infer_behavior_chains
from staticprep.analyzers.decision_control import build_final_decision
from staticprep.analyzers.iocs import classify_iocs
from staticprep.cli_summary import build_cli_triage_summary
from staticprep.config import load_analysis_settings


def _ioc_bucket() -> dict[str, list[dict[str, object]]]:
    return {
        "urls": [],
        "ips": [],
        "domains": [],
        "registry_paths": [],
        "file_paths": [],
        "mutexes": [],
        "commands": [],
    }


def _ioc_views() -> dict[str, object]:
    return {
        "classified": _ioc_bucket(),
        "high_confidence": _ioc_bucket(),
        "contextual": _ioc_bucket(),
        "suppressed": _ioc_bucket(),
        "raw_summary": {
            "total": 0,
            "by_type": {name: 0 for name in _ioc_bucket()},
            "by_classification": {
                "high_confidence": 0,
                "low_confidence": 0,
                "malformed": 0,
                "trusted_pki": 0,
                "trusted_platform": 0,
                "likely_build_artifact": 0,
                "likely_installer_artifact": 0,
                "contextual_only": 0,
            },
            "by_quality": {
                "clean": 0,
                "noisy": 0,
                "malformed": 0,
                "contextual_only": 0,
            },
        },
    }


def test_benign_installer_regression_is_suppressed_to_low_archive_and_hides_trusted_iocs():
    settings = load_analysis_settings()
    iocs = classify_iocs(
        raw_iocs={
            "urls": [
                "https://schemas.microsoft.com/appx/manifest/foundation/windows10",
                "https://go.microsoft.com/fwlink/?LinkId=12345",
            ],
            "ips": [],
            "domains": ["schemas.microsoft.com"],
            "registry_paths": [],
            "file_paths": ["C:\\Program Files\\7-Zip\\7zFM.exe"],
            "mutexes": [],
            "commands": ["msiexec /i 7zsetup.msi"],
        },
        analysis_settings=settings,
        context_strings=["Nullsoft Installer", "Electron", "app.asar"],
        binary_context={"installer_like": True, "is_dotnet": False, "likely_packed": False},
    )
    correlated_behaviors = [
        {
            "name": "likely_downloader_or_dropper",
            "matched": True,
            "confidence": "medium",
            "score": 9,
            "summary_label": "downloader or dropper",
            "recommended_next_step": "investigate_deeper",
            "severity_hint": "high",
            "evidence": ["CreateProcessW"],
            "rationale": ["weak URL residue was present"],
            "analyst_next_steps": [],
        },
        {
            "name": "likely_installer_or_packaged_app",
            "matched": True,
            "confidence": "high",
            "score": 12,
            "summary_label": "installer or packaged application",
            "recommended_next_step": "archive",
            "severity_hint": "low",
            "evidence": ["Nullsoft", "app.asar"],
            "rationale": ["installer or packager context is dominant"],
            "analyst_next_steps": ["Archive if no stronger static evidence emerges"],
        },
    ]

    final_decision = build_final_decision(
        analysis_summary={
            "severity": "high",
            "recommended_next_step": "investigate_deeper",
            "reasons": ["weak URL residue was retained"],
            "top_findings": [],
        },
        correlated_behaviors=correlated_behaviors,
        intent_inference={"primary": "likely_downloader", "candidates": []},
        interpretation={"quick_assessment": "Suspicion is driven by a limited set of static indicators and should be interpreted cautiously."},
        context={
            "installer_like": True,
            "is_dotnet": False,
            "is_go": False,
            "likely_packed": False,
            "has_high_runtime_noise": True,
        },
        iocs=iocs,
        behavior_chains={
            "download_write_execute_chain": {"matched": False},
            "credential_access_chain": {"matched": False},
            "persistence_chain": {"matched": False},
        },
        analysis_settings=settings,
    )

    assert final_decision["headline_behavior"] == "installer or packaged application"
    assert final_decision["normalized_severity"] == "low"
    assert final_decision["normalized_next_step"] == "archive"
    assert final_decision["notable_iocs"] == []
    assert "installer_context_without_strong_malicious_chain" in final_decision["suppression_reasons"]


def test_managed_contradiction_regression_removes_managed_wording_without_dotnet():
    settings = load_analysis_settings()

    final_decision = build_final_decision(
        analysis_summary={
            "severity": "medium",
            "recommended_next_step": "review_manually",
            "reasons": ["sparse imports were observed"],
            "top_findings": [],
        },
        correlated_behaviors=[],
        intent_inference={
            "primary": "likely_managed_obfuscated_payload",
            "candidates": [
                {
                    "name": "likely_managed_obfuscated_payload",
                    "score": 9,
                    "confidence": "medium",
                    "rationale": ["sparse import table"],
                    "evidence": ["_CorExeMain"],
                }
            ],
        },
        interpretation={"quick_assessment": "Suspicion is driven by a limited set of static indicators and should be interpreted cautiously."},
        context={
            "installer_like": False,
            "is_dotnet": False,
            "is_go": False,
            "likely_packed": False,
            "has_high_runtime_noise": False,
        },
        iocs=_ioc_views(),
        behavior_chains={
            "download_write_execute_chain": {"matched": False},
            "credential_access_chain": {"matched": False},
            "persistence_chain": {"matched": False},
        },
        analysis_settings=settings,
    )

    assert "managed" not in final_decision["headline_behavior"]


def test_next_analysis_path_regression_uses_actionable_fallback_guidance():
    settings = load_analysis_settings()

    final_decision = build_final_decision(
        analysis_summary={
            "severity": "medium",
            "recommended_next_step": "review_manually",
            "reasons": ["mixed evidence is present"],
            "top_findings": [],
        },
        correlated_behaviors=[],
        intent_inference={"primary": "ambiguous_requires_manual_review", "candidates": []},
        interpretation={"quick_assessment": "Suspicion is driven by a limited set of static indicators and should be interpreted cautiously."},
        context={
            "installer_like": False,
            "is_dotnet": False,
            "is_go": False,
            "likely_packed": False,
            "has_high_runtime_noise": False,
        },
        iocs=_ioc_views(),
        behavior_chains={
            "download_write_execute_chain": {"matched": False},
            "credential_access_chain": {"matched": False},
            "persistence_chain": {"matched": False},
        },
        analysis_settings=settings,
    )

    assert final_decision["actionable_next_steps"]
    assert all(
        step.startswith(("Review", "Check", "No further"))
        for step in final_decision["actionable_next_steps"]
    )


def test_downloader_strictness_regression_blocks_installer_like_weak_url_residue():
    settings = load_analysis_settings()
    result = correlate_behaviors(
        capabilities={
            "downloader_behavior": {"matched": True, "confidence": "low", "evidence": ["https://schemas.microsoft.com"]},
            "networking": {"matched": True, "confidence": "low", "evidence": ["InternetConnectW"]},
            "process_execution": {"matched": True, "confidence": "medium", "evidence": ["CreateProcessW"]},
        },
        grouped_strings={
            "network": {"matched": True, "evidence": ["https://schemas.microsoft.com/appx/manifest"]},
            "execution": {"matched": True, "evidence": ["msiexec /i setup.msi"]},
            "filesystem": {"matched": False, "evidence": []},
            "crypto_or_encoding": {"matched": False, "evidence": []},
        },
        iocs={
            **_ioc_views(),
            "contextual": {
                **_ioc_bucket(),
                "urls": [
                    {
                        "value": "https://schemas.microsoft.com/appx/manifest",
                        "classification": "trusted_platform",
                        "allowed_for_reasoning": True,
                    }
                ],
            },
        },
        behavior_chains={
            "download_write_execute_chain": {"matched": False, "evidence": []},
            "anti_analysis_chain": {"matched": False, "evidence": []},
            "credential_access_chain": {"matched": False, "evidence": []},
            "persistence_chain": {"matched": False, "evidence": []},
        },
        context={
            "installer_like": True,
            "likely_packed": False,
            "has_high_runtime_noise": True,
            "is_dotnet": False,
            "is_go": False,
            "evidence": {},
        },
        imports={"flat": ["InternetConnectW", "CreateProcessW"]},
        analysis_settings=settings,
    )

    assert result[0]["name"] != "likely_downloader_or_dropper"
    assert all(
        not (behavior["name"] == "likely_downloader_or_dropper" and behavior["matched"])
        for behavior in result
    )


def test_trusted_ioc_suppression_regression_keeps_schema_references_out_of_notable_iocs():
    settings = load_analysis_settings()
    iocs = classify_iocs(
        raw_iocs={
            "urls": ["https://schemas.microsoft.com/winfx/2006/xaml/presentation"],
            "ips": [],
            "domains": ["schemas.microsoft.com"],
            "registry_paths": [],
            "file_paths": [],
            "mutexes": [],
            "commands": [],
        },
        analysis_settings=settings,
    )

    assert iocs["classified"]["urls"][0]["classification"] == "trusted_platform"
    assert iocs["high_confidence"]["urls"] == []


def test_persistence_strictness_regression_requires_explicit_autorun_or_service_evidence():
    settings = load_analysis_settings()
    chains = infer_behavior_chains(
        context={
            "installer_like": True,
            "is_dotnet": False,
            "is_go": False,
            "likely_packed": False,
            "has_high_runtime_noise": False,
        },
        capabilities={
            "persistence": {"matched": True, "evidence": ["CopyFileW"], "confidence": "low"},
            "service_creation": {"matched": False, "evidence": [], "confidence": "low"},
        },
        grouped_strings={
            "registry": {"matched": False, "evidence": []},
            "network": {"matched": False, "evidence": []},
            "execution": {"matched": True, "evidence": ["CreateProcessW"]},
            "filesystem": {"matched": True, "evidence": ["C:\\Temp\\setup.tmp"]},
            "installer_or_packager": {"matched": True, "evidence": ["installer"]},
            "runtime_or_language": {"matched": False, "evidence": []},
            "anti_analysis": {"matched": False, "evidence": []},
            "credentials_or_auth": {"matched": False, "evidence": []},
        },
        iocs={
            "high_confidence": _ioc_bucket(),
            "contextual": {
                **_ioc_bucket(),
                "file_paths": [
                    {
                        "value": "C:\\Temp\\setup.tmp",
                        "allowed_for_reasoning": True,
                    }
                ],
            },
        },
        analysis_settings=settings,
    )

    assert chains["persistence_chain"]["matched"] is False


def test_existing_malicious_chain_regression_stays_high_and_investigate_deeper():
    settings = load_analysis_settings()
    correlated_behaviors = correlate_behaviors(
        capabilities={
            "downloader_behavior": {"matched": True, "confidence": "high", "evidence": ["URLDownloadToFileW"]},
            "networking": {"matched": True, "confidence": "high", "evidence": ["InternetOpenUrlW"]},
            "process_execution": {"matched": True, "confidence": "medium", "evidence": ["CreateProcessW"]},
        },
        grouped_strings={
            "network": {"matched": True, "evidence": ["https://evil.example/payload"]},
            "execution": {"matched": True, "evidence": ["cmd.exe /c ping 1.1.1.1 -n 3 & del payload.exe"]},
            "filesystem": {"matched": True, "evidence": ["C:\\Temp\\payload.exe"]},
            "crypto_or_encoding": {"matched": False, "evidence": []},
        },
        iocs={
            **_ioc_views(),
            "classified": {
                **_ioc_bucket(),
                "commands": [
                    {
                        "value": "cmd.exe /c ping 1.1.1.1 -n 3 & del payload.exe",
                        "allowed_for_reasoning": True,
                    }
                ],
            },
            "high_confidence": {
                **_ioc_bucket(),
                "urls": [{"value": "https://evil.example/payload", "classification": "high_confidence"}],
                "commands": [{"value": "cmd.exe /c ping 1.1.1.1 -n 3 & del payload.exe", "classification": "high_confidence"}],
            },
            "contextual": {
                **_ioc_bucket(),
                "file_paths": [{"value": "C:\\Temp\\payload.exe", "allowed_for_reasoning": True}],
            },
        },
        behavior_chains={
            "download_write_execute_chain": {"matched": True, "evidence": ["URLDownloadToFileW", "CreateProcessW"]},
            "anti_analysis_chain": {"matched": False, "evidence": []},
            "credential_access_chain": {"matched": False, "evidence": []},
            "persistence_chain": {"matched": False, "evidence": []},
        },
        context={
            "installer_like": False,
            "likely_packed": False,
            "has_high_runtime_noise": False,
            "is_dotnet": False,
            "is_go": False,
            "evidence": {},
        },
        imports={"flat": ["URLDownloadToFileW", "InternetOpenUrlW", "CreateProcessW"]},
        analysis_settings=settings,
    )
    final_decision = build_final_decision(
        analysis_summary={
            "severity": "high",
            "recommended_next_step": "investigate_deeper",
            "reasons": ["strong downloader chain"],
            "top_findings": [],
        },
        correlated_behaviors=correlated_behaviors,
        intent_inference={"primary": "likely_downloader", "candidates": []},
        interpretation={"quick_assessment": "Correlated staging and execution evidence points to downloader or dropper behavior."},
        context={
            "installer_like": False,
            "is_dotnet": False,
            "is_go": False,
            "likely_packed": False,
            "has_high_runtime_noise": False,
        },
        iocs=_ioc_views(),
        behavior_chains={
            "download_write_execute_chain": {"matched": True},
            "credential_access_chain": {"matched": False},
            "persistence_chain": {"matched": False},
        },
        analysis_settings=settings,
    )

    assert correlated_behaviors[0]["name"] == "likely_downloader_or_dropper"
    assert final_decision["headline_behavior"] == "downloader or dropper"
    assert final_decision["normalized_severity"] == "high"
    assert final_decision["normalized_next_step"] == "investigate_deeper"


def test_injection_precedence_regression_beats_obfuscation_when_both_match():
    settings = load_analysis_settings()
    final_decision = build_final_decision(
        analysis_summary={
            "severity": "high",
            "recommended_next_step": "investigate_deeper",
            "reasons": ["multiple malicious behaviors matched"],
            "top_findings": [],
        },
        correlated_behaviors=[
            {
                "name": "likely_obfuscated_loader",
                "matched": True,
                "confidence": "high",
                "score": 12,
                "summary_label": "obfuscated loader candidate",
                "recommended_next_step": "investigate_deeper",
                "severity_hint": "medium",
                "evidence": [".text"],
                "rationale": ["packing and encoding indicators are present"],
                "analyst_next_steps": ["Recover decoded strings and configuration material"],
            },
            {
                "name": "likely_process_injection_loader",
                "matched": True,
                "confidence": "high",
                "score": 12,
                "summary_label": "process injection loader",
                "recommended_next_step": "investigate_deeper",
                "severity_hint": "high",
                "evidence": ["CreateRemoteThread"],
                "rationale": ["a canonical remote-process injection API sequence is present"],
                "analyst_next_steps": ["Inspect process injection logic"],
            },
        ],
        intent_inference={"primary": "likely_process_injection_loader", "candidates": []},
        interpretation={"quick_assessment": "A process injection loader pattern is supported by correlated static evidence."},
        context={
            "installer_like": False,
            "is_dotnet": False,
            "is_go": False,
            "likely_packed": True,
            "has_high_runtime_noise": False,
        },
        iocs=_ioc_views(),
        behavior_chains={
            "download_write_execute_chain": {"matched": False},
            "credential_access_chain": {"matched": False},
            "persistence_chain": {"matched": False},
        },
        analysis_settings=settings,
    )

    assert final_decision["selected_behavior_name"] == "likely_process_injection_loader"
    assert final_decision["headline_behavior"] == "process injection loader"


def test_cli_summary_consumes_normalized_decision_output():
    report = {
        "sample": {"name": "setup.exe"},
        "hashes": {"sha256": "a" * 64},
        "analysis_summary": {
            "severity": "high",
            "recommended_next_step": "investigate_deeper",
            "top_findings": [
                "Likely behavior: installer or packaged application",
                "installer or packager context is dominant",
            ],
        },
        "intent_inference": {"primary": "likely_downloader"},
        "interpretation": {"quick_assessment": "Installer or packaging context dominates and stronger malicious chains are absent."},
        "context": {"is_dotnet": False, "is_go": False, "likely_packed": False},
        "environment": {"degraded_mode": False},
        "iocs": _ioc_views(),
        "final_decision": {
            "headline_behavior": "installer or packaged application",
            "normalized_severity": "low",
            "normalized_next_step": "archive",
            "notable_iocs": [],
            "actionable_next_steps": ["No further analysis unless additional context exists"],
        },
        "cli_summary": {"max_top_findings": 4, "max_iocs": 3, "max_next_steps": 3},
    }

    summary = build_cli_triage_summary(report)

    assert "Severity: LOW" in summary
    assert "Likely Behavior: installer or packaged application" in summary
    assert "Recommended Next Step: archive" in summary
    assert "Notable IOCs:" not in summary
    assert "No further analysis unless additional context exists" in summary
