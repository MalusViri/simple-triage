"""Tests for correlated behavior logic and compact CLI summary output."""

from __future__ import annotations

from staticprep.analyzers.behavior_correlation import correlate_behaviors
from staticprep.analyzers.contextual_analysis import infer_intents
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


def _empty_ioc_views() -> dict[str, object]:
    return {
        "classified": _ioc_bucket(),
        "high_confidence": _ioc_bucket(),
        "contextual": _ioc_bucket(),
        "suppressed": _ioc_bucket(),
    }


def test_correlate_behaviors_matches_downloader_or_dropper_pattern():
    settings = load_analysis_settings()
    result = correlate_behaviors(
        capabilities={
            "downloader_behavior": {"matched": True, "confidence": "high", "evidence": ["URLDownloadToFileW"]},
            "networking": {"matched": True, "confidence": "high", "evidence": ["InternetOpenUrlW"]},
            "process_execution": {"matched": True, "confidence": "medium", "evidence": ["CreateProcessW"]},
        },
        grouped_strings={
            "network": {"matched": True, "evidence": ["https://evil.example/payload"]},
            "execution": {"matched": True, "evidence": ["cmd.exe /c ping 1.1.1.1 -n 3 & del payload.exe"]},
            "filesystem": {"matched": True, "evidence": ["C:\\Temp\\payload.exe"]},
        },
        iocs={
            **_empty_ioc_views(),
            "classified": {
                **_empty_ioc_views()["classified"],
                "commands": [
                    {
                        "value": "cmd.exe /c ping 1.1.1.1 -n 3 & del payload.exe",
                        "allowed_for_reasoning": True,
                    }
                ],
            },
            "high_confidence": {
                **_empty_ioc_views()["high_confidence"],
                "urls": [{"value": "https://evil.example/payload"}],
                "commands": [{"value": "cmd.exe /c ping 1.1.1.1 -n 3 & del payload.exe"}],
            },
            "contextual": {
                **_empty_ioc_views()["contextual"],
                "file_paths": [{"value": "C:\\Temp\\payload.exe"}],
            },
        },
        behavior_chains={
            "download_write_execute_chain": {"matched": True, "evidence": ["URLDownloadToFileW", "CreateProcessW"]},
            "anti_analysis_chain": {"matched": False, "evidence": []},
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

    assert result[0]["name"] == "likely_downloader_or_dropper"
    assert result[0]["matched"] is True
    assert result[0]["confidence"] == "high"
    assert any("self-delete" in item for item in result[0]["rationale"])


def test_correlate_behaviors_matches_process_injection_loader_pattern():
    settings = load_analysis_settings()
    result = correlate_behaviors(
        capabilities={
            "process_injection": {"matched": True, "confidence": "high", "evidence": ["WriteProcessMemory"]},
            "anti_analysis": {"matched": True, "confidence": "medium", "evidence": ["IsDebuggerPresent"]},
        },
        grouped_strings={
            "crypto_or_encoding": {"matched": True, "evidence": ["base64", "decrypt"]},
            "execution": {"matched": False, "evidence": []},
        },
        iocs=_empty_ioc_views(),
        behavior_chains={
            "anti_analysis_chain": {"matched": True, "evidence": ["IsDebuggerPresent"]},
            "download_write_execute_chain": {"matched": False, "evidence": []},
        },
        context={
            "installer_like": False,
            "likely_packed": True,
            "has_high_runtime_noise": False,
            "is_dotnet": False,
            "is_go": False,
            "evidence": {"high_entropy_sections": [".text"]},
        },
        imports={"flat": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]},
        analysis_settings=settings,
    )

    assert result[0]["name"] == "likely_process_injection_loader"
    assert result[0]["matched"] is True
    assert "OpenProcess" in result[0]["evidence"]


def test_runtime_context_reduces_false_positive_when_no_stronger_malicious_pattern_exists():
    settings = load_analysis_settings()
    result = correlate_behaviors(
        capabilities={},
        grouped_strings={},
        iocs=_empty_ioc_views(),
        behavior_chains={"download_write_execute_chain": {"matched": False, "evidence": []}},
        context={
            "installer_like": False,
            "likely_packed": False,
            "has_high_runtime_noise": True,
            "is_dotnet": True,
            "is_go": False,
            "evidence": {
                "dotnet_imports": ["mscoree.dll"],
                "dotnet_symbols": ["_CorExeMain"],
                "runtime_noise_strings": ["System.Runtime"],
            },
        },
        imports={"flat": ["_CorExeMain"]},
        analysis_settings=settings,
    )

    assert result[0]["name"] == "benign_or_low_signal_packaged_runtime"
    assert result[0]["matched"] is True


def test_version_like_ipv4_values_are_not_promoted_to_analyst_ready_iocs():
    settings = load_analysis_settings()
    result = classify_iocs(
        raw_iocs={"urls": [], "ips": ["3.5.0.0", "4.0.0.0", "17.0.0.0"], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
        analysis_settings=settings,
    )

    assert all(entry["classification"] == "contextual_only" for entry in result["classified"]["ips"])
    assert result["high_confidence"]["ips"] == []


def test_no_evidence_ambiguous_intent_is_not_reported_with_meaningful_confidence():
    settings = load_analysis_settings()
    intents = infer_intents(
        context={
            "installer_like": False,
            "is_dotnet": False,
            "is_go": False,
            "likely_packed": False,
            "has_sparse_imports": False,
            "has_high_runtime_noise": False,
        },
        capabilities={},
        behavior_chains={
            "download_write_execute_chain": {"matched": False, "evidence": []},
            "credential_access_chain": {"matched": False, "evidence": []},
            "persistence_chain": {"matched": False, "evidence": []},
            "installer_or_packager_chain": {"matched": False, "evidence": []},
        },
        correlated_behaviors=[],
        grouped_strings={},
        iocs={"high_confidence": {}, "classified": {}},
        analysis_summary={"top_findings": []},
        analysis_settings=settings,
    )

    assert intents["primary"] == "ambiguous_requires_manual_review"
    assert intents["candidates"][0]["confidence"] == "low"


def test_cli_triage_summary_is_compact_and_directional():
    report = {
        "sample": {"name": "RATPNG.exe"},
        "hashes": {"sha256": "a" * 64},
        "analysis_summary": {
            "severity": "high",
            "recommended_next_step": "investigate_deeper",
            "top_findings": [
                "Likely behavior: process injection loader",
                "High-confidence capabilities: process_injection",
                "Correlated execution evidence is present",
            ],
        },
        "intent_inference": {"primary": "likely_process_injection_loader"},
        "interpretation": {"quick_assessment": "A process injection loader pattern is supported by correlated static evidence."},
        "context": {"is_dotnet": True, "is_go": False, "likely_packed": True},
        "environment": {"degraded_mode": False},
        "iocs": {
            "high_confidence": {
                "urls": [{"value": "https://evil.example/payload"}],
                "domains": [],
                "commands": [{"value": "cmd.exe /c ping 1.1.1.1 -n 3 & del payload.exe"}],
                "file_paths": [],
            },
            "classified": {
                "file_paths": [
                    {
                        "value": "C:\\Temp\\payload.exe",
                        "classification": "low_confidence",
                        "allowed_for_reasoning": True,
                    }
                ]
            },
        },
        "correlated_behaviors": [
            {
                "name": "likely_process_injection_loader",
                "matched": True,
                "summary_label": "process injection loader",
                "recommended_next_step": "investigate_deeper",
                "analyst_next_steps": [
                    "Review the remote-process injection path and target selection",
                    "Inspect payload decoding, crypto, or decompression helpers",
                ],
            }
        ],
        "cli_summary": {"max_top_findings": 4, "max_iocs": 3, "max_next_steps": 3},
    }

    summary = build_cli_triage_summary(report)

    assert "Sample: RATPNG.exe" in summary
    assert "Likely Behavior: process injection loader" in summary
    assert "Recommended Next Step: investigate deeper" in summary
    assert "Notable IOCs:" in summary
    assert "Next Analysis Path:" in summary
