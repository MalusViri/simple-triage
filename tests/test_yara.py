"""Tests for local YARA behavior."""

from __future__ import annotations

import pytest

from staticprep.analyzers.yara_scan import _build_yara_externals, run_yara_scan, yara


def test_yara_missing_directory_returns_warning(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"just bytes")

    result, errors = run_yara_scan(sample, tmp_path / "missing_rules")

    if yara is None:
        assert result["enabled"] is False
        assert result["skipped"] is True
        assert result["succeeded"] is False
        assert result["error"] == "yara-python is not installed"
        assert result["scan_status"] == "skipped_dependency_unavailable"
        assert result["yara_health"] == "unavailable"
        assert errors[0]["severity"] == "warning"
    else:
        assert result["enabled"] is True
        assert result["attempted"] is True
        assert result["succeeded"] is False
        assert result["scan_status"] == "failed_missing_rules_directory"
        assert result["yara_health"] == "degraded"
        assert errors[0]["message"].startswith("Rules directory does not exist")


def test_build_yara_externals(tmp_path):
    sample = tmp_path / "Example.BIN"
    sample.write_bytes(b"test")

    externals = _build_yara_externals(sample)

    assert externals == {
        "filepath": str(sample.resolve()),
        "filename": "Example.BIN",
        "extension": "bin",
    }


@pytest.mark.skipif(yara is None, reason="yara-python is not installed")
def test_yara_rule_loading_and_match_parsing(fixture_dir):
    sample = fixture_dir / "samples" / "note.txt"
    rules_dir = fixture_dir / "rules"

    result, errors = run_yara_scan(sample, rules_dir)

    assert errors == []
    assert result["enabled"] is True
    assert result["succeeded"] is True
    assert result["scan_status"] == "completed"
    assert result["yara_health"] == "healthy"
    assert result["match_count"] == 1
    assert result["matches"] == [
        {
            "rule": "ContainsPowerShell",
            "tags": ["process_execution"],
            "meta": {"author": "test", "description": "Matches powershell strings"},
        }
    ]


@pytest.mark.skipif(yara is None, reason="yara-python is not installed")
def test_yara_externals_support_filepath_filename_and_extension(tmp_path):
    sample = tmp_path / "demo.EXE"
    sample.write_bytes(b"notepad")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "externals.yar").write_text(
        """
rule MatchFilepath
{
    condition:
        filepath contains "demo.EXE"
}

rule MatchFilename
{
    condition:
        filename == "demo.EXE"
}

rule MatchExtension
{
    condition:
        extension == "exe"
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result, errors = run_yara_scan(sample, rules_dir)

    assert errors == []
    assert result["succeeded"] is True
    assert result["rule_stats"]["valid"] == 1
    assert [match["rule"] for match in result["matches"]] == [
        "MatchExtension",
        "MatchFilename",
        "MatchFilepath",
    ]


@pytest.mark.skipif(yara is None, reason="yara-python is not installed")
def test_yara_reports_partial_ruleset_issues_cleanly(tmp_path):
    sample = tmp_path / "demo.bin"
    sample.write_bytes(b"powershell demo")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yar").write_text(
        """
rule GoodRule
{
    strings:
        $a = "powershell"
    condition:
        $a
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (rules_dir / "bad.yar").write_text(
        """
rule BadRule
{
    condition:
        this is not valid yara
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result, errors = run_yara_scan(sample, rules_dir)

    assert result["succeeded"] is True
    assert result["scan_status"] == "completed_with_partial_rule_issues"
    assert result["yara_health"] == "healthy_with_minor_rule_errors"
    assert result["warning_count"] == 1
    assert result["rule_stats"] == {"discovered": 2, "valid": 1, "invalid": 1}
    assert result["matches"][0]["rule"] == "GoodRule"
    assert len(errors) == 1
