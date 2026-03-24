"""Tests for local YARA behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from staticprep.analyzers.yara_scan import run_yara_scan, yara


def test_yara_missing_directory_returns_warning(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"just bytes")

    result, errors = run_yara_scan(sample, tmp_path / "missing_rules")

    if yara is None:
        assert result["enabled"] is False
        assert errors[0]["severity"] == "warning"
    else:
        assert result["enabled"] is True
        assert errors[0]["message"].startswith("Rules directory does not exist")


@pytest.mark.skipif(yara is None, reason="yara-python is not installed")
def test_yara_rule_loading_and_match_parsing(fixture_dir):
    sample = fixture_dir / "samples" / "note.txt"
    rules_dir = fixture_dir / "rules"

    result, errors = run_yara_scan(sample, rules_dir)

    assert errors == []
    assert result["enabled"] is True
    assert result["matches"] == [
        {
            "rule": "ContainsPowerShell",
            "tags": ["process_execution"],
            "meta": {"author": "test", "description": "Matches powershell strings"},
        }
    ]
