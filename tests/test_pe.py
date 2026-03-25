"""Tests for PE parsing behavior."""

from __future__ import annotations

import pytest

from staticprep.analyzers.pe import analyze_pe, pefile
from staticprep.main import analyze_sample


def test_analyze_sample_handles_non_pe_file(tmp_path, fixture_dir):
    sample = fixture_dir / "samples" / "note.txt"
    report, output_dir = analyze_sample(
        sample_path=sample,
        output_root=tmp_path,
        rules_dir=fixture_dir / "rules",
        skip_yara=True,
    )

    assert report.pe["is_pe"] is False
    if pefile is None:
        assert report.pe["attempted"] is False
        assert report.pe["skipped"] is True
        assert report.imports["attempted"] is False
        assert report.imports["skipped"] is True
    else:
        assert report.pe["attempted"] is True
        assert report.pe["succeeded"] is False
        assert report.imports["attempted"] is True
        assert report.imports["succeeded"] is False
    assert report.imports["error"] is not None
    assert any(error.stage == "pe" for error in report.errors)
    assert (output_dir / "report.json").exists()


@pytest.mark.skipif(pefile is None, reason="pefile is not installed")
def test_analyze_pe_fixture(fixture_dir):
    sample = fixture_dir / "samples" / "minimal_pe32.exe"
    pe_info, imports = analyze_pe(sample)

    assert pe_info["is_pe"] is True
    assert pe_info["attempted"] is True
    assert pe_info["succeeded"] is True
    assert pe_info["machine_type"] == "IMAGE_FILE_MACHINE_I386"
    assert pe_info["number_of_sections"] == 1
    assert isinstance(imports["by_dll"], dict)
    assert imports["total_import_count"] >= 0
    assert imports["dll_count"] >= 0
