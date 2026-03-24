"""Tests for capability mapping logic."""

from __future__ import annotations

from staticprep.analyzers.capabilities import infer_capabilities


def test_infer_capabilities_uses_configured_indicators():
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
    )

    assert result["networking"].matched is True
    assert result["networking"].evidence == ["connect", "http://", "networking"]
    assert result["networking"].evidence_source == ["API", "string", "YARA"]
