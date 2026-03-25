"""Focused tests for Phase 5 contextual triage behavior."""

from __future__ import annotations

from staticprep.analyzers.contextual_analysis import (
    detect_binary_context,
    group_strings_by_behavior,
    infer_behavior_chains,
    infer_intents,
)
from staticprep.analyzers.iocs import classify_iocs
from staticprep.analyzers.prioritization import build_analysis_summary
from staticprep.config import load_analysis_settings
from staticprep.exporters.markdown_exporter import build_summary_markdown


def test_dotnet_context_detection_flags_sparse_managed_profile():
    settings = load_analysis_settings()

    context = detect_binary_context(
        imports={
            "attempted": True,
            "succeeded": True,
            "dll_count": 1,
            "total_import_count": 2,
            "flat": ["_CorExeMain", "LoadLibraryA"],
            "by_dll": {"mscoree.dll": ["_CorExeMain"]},
        },
        pe_info={"is_pe": True, "sections": [{"name": ".text"}]},
        all_strings=["System.Runtime", "AssemblyVersion", "v4.0.30319"],
        packed_assessment={"likely_packed": True, "high_entropy_sections": [{"name": ".text"}]},
        analysis_settings=settings,
    )

    assert context["is_dotnet"] is True
    assert context["has_sparse_imports"] is True
    assert ".NET indicators were observed" in context["rationale"]


def test_go_context_detection_reduces_entropy_only_scoring():
    settings = load_analysis_settings()
    go_context = {
        "is_dotnet": False,
        "is_go": True,
        "likely_packed": True,
        "installer_like": False,
        "has_sparse_imports": False,
        "has_high_runtime_noise": False,
        "rationale": [],
        "evidence": {},
    }
    generic_context = {**go_context, "is_go": False}
    base_iocs = {
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
    }
    packed = {"high_entropy_sections": [{"name": ".text", "entropy": 7.9}], "likely_packed": True}

    generic = build_analysis_summary(
        capabilities={},
        iocs=base_iocs,
        yara_results={"match_count": 0, "matches": []},
        packed_assessment=packed,
        environment={"degraded_mode": False},
        analysis_settings=settings,
        context=generic_context,
        behavior_chains={},
    )
    go_result = build_analysis_summary(
        capabilities={},
        iocs=base_iocs,
        yara_results={"match_count": 0, "matches": []},
        packed_assessment=packed,
        environment={"degraded_mode": False},
        analysis_settings=settings,
        context=go_context,
        behavior_chains={},
    )

    assert go_result["score"] < generic["score"]


def test_installer_context_detection_and_scoring_penalty():
    settings = load_analysis_settings()
    context = detect_binary_context(
        imports={"attempted": False, "succeeded": False, "dll_count": 0, "total_import_count": 0, "flat": [], "by_dll": {}},
        pe_info={"is_pe": False, "sections": []},
        all_strings=["Nullsoft Installer", "app.asar", "Electron"],
        packed_assessment={"likely_packed": False, "high_entropy_sections": []},
        analysis_settings=settings,
    )

    result = build_analysis_summary(
        capabilities={},
        iocs={
            "high_confidence": {"urls": [], "ips": [], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
            "contextual": {"urls": [], "ips": [], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
        },
        yara_results={"match_count": 0, "matches": []},
        packed_assessment={"high_entropy_sections": [], "likely_packed": False},
        environment={"degraded_mode": False},
        analysis_settings=settings,
        context=context,
        behavior_chains={},
    )

    assert context["installer_like"] is True
    assert result["score"] == 0


def test_semantic_ioc_validation_downgrades_version_and_ping_context_ips():
    settings = load_analysis_settings()

    version_context = classify_iocs(
        raw_iocs={"urls": [], "ips": ["1.1.1.1"], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
        analysis_settings=settings,
        context_strings=["AssemblyVersion 1.1.1.1", "System.Runtime"],
        binary_context={"is_dotnet": True},
    )
    ping_context = classify_iocs(
        raw_iocs={"urls": [], "ips": ["1.1.1.1"], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
        analysis_settings=settings,
        context_strings=["cmd /c ping 1.1.1.1 -n 5"],
        binary_context={"is_dotnet": False},
    )
    local_context = classify_iocs(
        raw_iocs={"urls": [], "ips": ["127.0.0.1"], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
        analysis_settings=settings,
    )

    assert version_context["classified"]["ips"][0]["classification"] == "contextual_only"
    assert version_context["classified"]["ips"][0]["reasons"] == ["version_like_runtime_value"]
    assert ping_context["classified"]["ips"][0]["classification"] == "low_confidence"
    assert local_context["classified"]["ips"][0]["classification"] == "contextual_only"


def test_grouped_domains_behavior_chains_and_intent_inference():
    settings = load_analysis_settings()
    all_strings = [
        "https://download.example/payload",
        "powershell.exe -enc AAA",
        "C:\\Temp\\payload.exe",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "AssemblyVersion",
    ]
    suspicious_categories = {
        "urls": ["https://download.example/payload"],
        "ips": [],
        "domains": ["download.example"],
        "registry_paths": ["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "file_paths": ["C:\\Temp\\payload.exe"],
        "commands_or_lolbins": ["powershell.exe -enc AAA"],
        "powershell": ["powershell.exe -enc AAA"],
        "appdata_or_temp": ["C:\\Temp\\payload.exe"],
        "other": [],
    }
    grouped = group_strings_by_behavior(all_strings, suspicious_categories, settings)
    capabilities = {
        "downloader_behavior": {"matched": True, "evidence": ["downloadstring"], "confidence": "medium"},
        "networking": {"matched": True, "evidence": ["connect"], "confidence": "high"},
        "process_execution": {"matched": True, "evidence": ["CreateProcessW"], "confidence": "medium"},
        "persistence": {"matched": True, "evidence": ["Run\\"], "confidence": "medium"},
        "anti_analysis": {"matched": False, "evidence": [], "confidence": "low"},
        "credential_access_indicators": {"matched": False, "evidence": [], "confidence": "low"},
    }
    iocs = {
        "high_confidence": {
            "urls": [{"value": "https://download.example/payload"}],
            "ips": [],
            "domains": [],
            "registry_paths": [{"value": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}],
            "file_paths": [],
            "mutexes": [],
            "commands": [{"value": "powershell.exe -enc AAA"}],
        },
        "contextual": {
            "urls": [],
            "ips": [],
            "domains": [],
            "registry_paths": [],
            "file_paths": [{"value": "C:\\Temp\\payload.exe"}],
            "mutexes": [],
            "commands": [],
        },
    }
    context = {
        "is_dotnet": True,
        "is_go": False,
        "likely_packed": True,
        "installer_like": False,
        "has_sparse_imports": True,
        "has_high_runtime_noise": False,
        "rationale": [],
        "evidence": {"dotnet_imports": ["mscoree.dll"], "dotnet_symbols": ["_CorExeMain"], "high_entropy_sections": [".text"], "installer_strings": []},
    }
    chains = infer_behavior_chains(context, capabilities, grouped, iocs, settings)
    summary = build_analysis_summary(
        capabilities=capabilities,
        iocs=iocs,
        yara_results={"match_count": 0, "matches": []},
        packed_assessment={"high_entropy_sections": [{"name": ".text", "entropy": 7.8}], "likely_packed": True},
        environment={"degraded_mode": False},
        analysis_settings=settings,
        context=context,
        behavior_chains=chains,
    )
    intents = infer_intents(context, capabilities, chains, grouped, iocs, summary, settings)

    assert grouped["network"]["matched"] is True
    assert grouped["execution"]["matched"] is True
    assert grouped["filesystem"]["matched"] is True
    assert chains["download_write_execute_chain"]["matched"] is True
    assert chains["persistence_chain"]["matched"] is True
    assert intents["primary"] in {"likely_downloader", "likely_packed_loader", "likely_managed_obfuscated_payload"}
    assert any(candidate["name"] == "likely_downloader" for candidate in intents["candidates"])


def test_summary_markdown_includes_phase5_sections():
    report = {
        "sample": {"name": "sample.exe", "path": "/tmp/sample.exe", "size": 1, "type_hint": "application/octet-stream"},
        "context": {
            "is_dotnet": True,
            "is_go": False,
            "likely_packed": True,
            "installer_like": False,
            "has_sparse_imports": True,
            "has_high_runtime_noise": False,
            "evidence": {},
            "rationale": [".NET indicators were observed"],
        },
        "analysis_summary": {
            "severity": "high",
            "score": 75,
            "recommended_next_step": "investigate_deeper",
            "top_findings": ["Likely packed"],
            "reasons": [],
            "dominant_signal_classes": ["behavior_chain:download_write_execute_chain"],
            "suppressed_signal_classes": [],
            "score_breakdown": [],
        },
        "findings": {
            "executive_summary": {
                "worth_deeper_investigation": True,
                "analysis_degraded": False,
                "top_findings": ["Likely packed"],
                "dominant_signal_classes": ["behavior_chain:download_write_execute_chain"],
                "suppressed_signal_classes": [],
            },
            "analyst_ready": [],
            "contextual": [],
            "raw_references": {"artifact_files": ["report.json"]},
        },
        "interpretation": {
            "notes": [],
            "codes": [],
            "summary": [],
            "quick_assessment": "Corroborated execution-oriented behavior is present and outweighs generic context.",
            "analyst_summary": "This sample demonstrates a clear download, write, and execute chain.",
            "strongest_evidence": ["powershell.exe"],
            "suppressed_or_contextual_evidence": [],
        },
        "environment": {"pefile_available": True, "yara_available": True, "degraded_mode": False, "degraded_reasons": []},
        "behavior_chains": {
            "download_write_execute_chain": {"matched": True, "confidence": "high", "evidence": ["powershell.exe"], "evidence_sources": ["grouped_strings"]},
        },
        "intent_inference": {
            "primary": "likely_downloader",
            "secondary": [],
            "candidates": [{"name": "likely_downloader", "score": 12, "confidence": "high", "evidence": ["powershell.exe"], "rationale": ["network indicators are present"], "suppressed_by_context": []}],
        },
        "packed_assessment": {"likely_packed": True, "high_entropy_sections": [], "rationale": "", "attempted": True, "succeeded": True, "skipped": False, "error": None, "threshold_used": 7.2},
        "iocs": {
            "high_confidence": {"urls": [], "domains": [], "registry_paths": [], "commands": [], "ips": [], "file_paths": [], "mutexes": []},
            "contextual": {"urls": [], "file_paths": [], "domains": [], "registry_paths": [], "commands": [], "ips": [], "mutexes": []},
            "suppressed": {"urls": [], "file_paths": [], "domains": [], "registry_paths": [], "commands": [], "ips": [], "mutexes": []},
            "raw_summary": {"total": 0, "by_quality": {"clean": 0, "noisy": 0, "malformed": 0, "contextual_only": 0}},
        },
        "interesting_strings_preview": [],
        "hashes": {"md5": "a", "sha1": "b", "sha256": "c"},
        "strings": {
            "suspicious_count": 0,
            "reasoning": {"quality_summary": {"reasoning_eligible_count": 0, "suppressed_count": 0}},
            "grouped_domains": {"network": {"matched": True, "count": 1, "source_categories": ["urls"], "evidence": ["https://x"]}},
        },
        "yara": {"scan_status": "completed", "attempted": True, "succeeded": True, "match_count": 0, "rule_stats": {"discovered": 0, "valid": 0, "invalid": 0}, "matches": [], "warnings": [], "yara_health": "healthy"},
        "errors": [],
    }

    summary = build_summary_markdown(report)

    assert "## Binary Context" in summary
    assert "## Behavior Chains" in summary
    assert "## Likely Intent" in summary
    assert "## Grouped String Evidence" in summary
    assert "## Signal Scoring" in summary
    assert "YARA health" in summary
