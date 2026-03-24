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
        assert errors[0]["severity"] == "warning"
    else:
        assert result["enabled"] is True
        assert result["attempted"] is True
        assert result["succeeded"] is False
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
    assert [match["rule"] for match in result["matches"]] == [
        "MatchExtension",
        "MatchFilename",
        "MatchFilepath",
    ]
