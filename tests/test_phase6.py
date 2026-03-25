"""Focused tests for Phase 6 evidence hygiene and reasoning behavior."""

from __future__ import annotations

from staticprep.analyzers.contextual_analysis import (
    group_strings_by_behavior,
    infer_behavior_chains,
    infer_intents,
)
from staticprep.analyzers.evidence import assess_evidence_quality, filter_reasoning_strings
from staticprep.analyzers.interpretation import build_interpretation
from staticprep.analyzers.iocs import classify_iocs
from staticprep.analyzers.prioritization import build_analysis_summary
from staticprep.config import load_analysis_settings


def test_garbage_noisy_strings_are_excluded_from_reasoning_groups():
    settings = load_analysis_settings()
    strings = [
        "@@@@!!!!%%%%^^^^",
        "powershell.exe -enc AAA",
        "https://download.example/payload",
    ]

    reasoning_strings, metadata = filter_reasoning_strings(strings, settings)
    grouped = group_strings_by_behavior(
        all_strings=reasoning_strings,
        suspicious_categories={
            "urls": ["https://download.example/payload"],
            "ips": [],
            "domains": ["download.example"],
            "registry_paths": [],
            "file_paths": [],
            "commands_or_lolbins": ["powershell.exe -enc AAA"],
            "powershell": ["powershell.exe -enc AAA"],
            "appdata_or_temp": [],
            "other": [],
        },
        analysis_settings=settings,
    )

    assert any(entry["quality"] == "noisy" for entry in metadata)
    assert "@@@@!!!!%%%%^^^^" not in reasoning_strings
    assert grouped["network"]["matched"] is True
    assert grouped["execution"]["matched"] is True


def test_symbol_heavy_fake_paths_are_suppressed_from_reasoning():
    settings = load_analysis_settings()

    result = classify_iocs(
        raw_iocs={
            "urls": [],
            "ips": [],
            "domains": [],
            "registry_paths": [],
            "file_paths": ["Q:\\@@@\\%%%\\!!.exe"],
            "mutexes": [],
            "commands": [],
        },
        analysis_settings=settings,
    )

    assert result["classified"]["file_paths"][0]["quality"] == "malformed"
    assert result["classified"]["file_paths"][0]["allowed_for_reasoning"] is False
    assert result["suppressed"]["file_paths"][0]["value"] == "Q:\\@@@\\%%%\\!!.exe"


def test_installer_context_beats_downloader_residue_when_chains_are_weak():
    settings = load_analysis_settings()
    context = {
        "is_dotnet": False,
        "is_go": False,
        "likely_packed": True,
        "installer_like": True,
        "has_sparse_imports": False,
        "has_high_runtime_noise": True,
        "evidence": {
            "installer_strings": ["Nullsoft", "Electron", "app.asar"],
            "runtime_noise_strings": ["Electron", "app.asar"],
            "high_entropy_sections": [".text"],
        },
        "rationale": [],
    }
    grouped = {
        "network": {"matched": False, "evidence": [], "source_categories": [], "count": 0},
        "execution": {"matched": False, "evidence": [], "source_categories": [], "count": 0},
        "filesystem": {"matched": False, "evidence": [], "source_categories": [], "count": 0},
        "registry": {"matched": False, "evidence": [], "source_categories": [], "count": 0},
        "installer_or_packager": {"matched": True, "evidence": ["Nullsoft", "Electron"], "source_categories": [], "count": 2},
        "runtime_or_language": {"matched": True, "evidence": ["app.asar"], "source_categories": [], "count": 1},
        "anti_analysis": {"matched": False, "evidence": [], "source_categories": [], "count": 0},
        "credentials_or_auth": {"matched": False, "evidence": [], "source_categories": [], "count": 0},
    }
    capabilities = {
        "downloader_behavior": {"matched": True, "evidence": ["http://"], "confidence": "low"},
        "networking": {"matched": True, "evidence": ["http://"], "confidence": "low"},
        "process_execution": {"matched": False, "evidence": [], "confidence": "low"},
        "persistence": {"matched": False, "evidence": [], "confidence": "low"},
        "anti_analysis": {"matched": False, "evidence": [], "confidence": "low"},
        "credential_access_indicators": {"matched": False, "evidence": [], "confidence": "low"},
    }
    iocs = {
        "classified": {"urls": [], "commands": []},
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

    assert summary["severity"] == "low"
    assert intents["primary"] == "likely_installer_or_packaged_app"
    assert "likely_downloader" != intents["primary"]


def test_go_context_caps_entropy_only_suspicion():
    settings = load_analysis_settings()
    summary = build_analysis_summary(
        capabilities={},
        iocs={
            "classified": {},
            "high_confidence": {"urls": [], "ips": [], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
            "contextual": {"urls": [], "ips": [], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
        },
        yara_results={"match_count": 0, "matches": []},
        packed_assessment={"high_entropy_sections": [{"name": ".text", "entropy": 7.7}], "likely_packed": True},
        environment={"degraded_mode": False},
        analysis_settings=settings,
        context={
            "is_dotnet": False,
            "is_go": True,
            "likely_packed": True,
            "installer_like": False,
            "has_sparse_imports": False,
            "has_high_runtime_noise": False,
        },
        behavior_chains={},
    )

    assert summary["severity"] == "low"
    assert "packed_entropy" in summary["suppressed_signal_classes"]


def test_bare_http_is_contextual_only_for_reasoning():
    settings = load_analysis_settings()
    quality = assess_evidence_quality("http://", "suspicious_string", settings)

    assert quality["quality"] == "contextual_only"
    assert quality["allowed_for_reasoning"] is False


def test_interpretation_is_populated_for_malicious_and_packaged_cases():
    settings = load_analysis_settings()
    malicious = build_interpretation(
        all_strings=["https://download.example/payload", "powershell.exe -enc AAA"],
        iocs={
            "suppressed": {"urls": [], "ips": [], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
            "raw_summary": {"by_classification": {"trusted_pki": 0, "likely_installer_artifact": 0}},
        },
        context={"installer_like": False, "is_go": False, "is_dotnet": False},
        behavior_chains={"download_write_execute_chain": {"matched": True, "evidence": ["URLDownloadToFileW", "CreateProcessW"]}},
        intent_inference={"primary": "likely_downloader"},
        analysis_summary={"top_findings": ["Validated external network indicators were identified"], "suppressed_signal_classes": []},
        packed_assessment={"likely_packed": False, "high_entropy_sections": []},
        capabilities={"networking": {"matched": True, "confidence": "high"}},
        yara_results={"match_count": 0},
        analysis_settings=settings,
    )
    packaged = build_interpretation(
        all_strings=["Nullsoft Installer", "Electron", "app.asar", "ocsp"],
        iocs={
            "suppressed": {"urls": [], "ips": [], "domains": [], "registry_paths": [], "file_paths": [], "mutexes": [], "commands": []},
            "raw_summary": {"by_classification": {"trusted_pki": 1, "likely_installer_artifact": 2}},
        },
        context={"installer_like": True, "is_go": False, "is_dotnet": False},
        behavior_chains={"download_write_execute_chain": {"matched": False, "evidence": []}},
        intent_inference={"primary": "likely_installer_or_packaged_app"},
        analysis_summary={"top_findings": ["Likely packed based on PE section entropy"], "suppressed_signal_classes": ["weak_network_residue"]},
        packed_assessment={"likely_packed": True, "high_entropy_sections": [{"name": ".ndata"}]},
        capabilities={"networking": {"matched": False, "confidence": "low"}},
        yara_results={"match_count": 0},
        analysis_settings=settings,
    )

    assert "download" in malicious["analyst_summary"].lower()
    assert "installer" in packaged["analyst_summary"].lower()
    assert packaged["suppressed_or_contextual_evidence"]
