"""Tests for capability mapping logic."""

from __future__ import annotations

from staticprep.analyzers.capabilities import infer_capabilities
from staticprep.config import load_analysis_settings


def test_infer_capabilities_uses_weighted_configured_indicators():
    mapping = {
        "networking": {
            "api": ["connect"],
            "strings": ["http://"],
            "yara": ["networking"],
        }
    }

    result = infer_capabilities(
        capability_map=mapping,
        apis=["connect"],
        strings=["http://example.com"],
        yara_matches=[{"rule": "basic_rule", "tags": ["networking"], "meta": {}}],
        capability_settings=load_analysis_settings()["capabilities"],
    )

    assert result["networking"].matched is True
    assert result["networking"].evidence == ["connect", "http://", "networking"]
    assert result["networking"].evidence_source == ["API", "string", "YARA"]
    assert result["networking"].score == 8
    assert result["networking"].confidence == "high"


def test_infer_capabilities_reduces_confidence_for_weak_only_evidence():
    mapping = {
        "downloader_behavior": {
            "api": [],
            "strings": ["http://", "https://"],
            "yara": [],
        },
        "anti_analysis": {
            "api": ["IsDebuggerPresent"],
            "strings": ["debugger"],
            "yara": [],
        },
        "persistence": {
            "api": [],
            "strings": ["startup"],
            "yara": [],
        },
    }

    result = infer_capabilities(
        capability_map=mapping,
        apis=["IsDebuggerPresent"],
        strings=["http://example.com", "startup", "debugger"],
        yara_matches=[],
        capability_settings=load_analysis_settings()["capabilities"],
    )

    assert result["downloader_behavior"].confidence == "low"
    assert result["anti_analysis"].confidence == "low"
    assert result["persistence"].confidence == "low"
