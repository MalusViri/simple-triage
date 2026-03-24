"""End-to-end artifact generation tests."""

from __future__ import annotations

import json

from staticprep.analyzers import pe as pe_analyzer
from staticprep.analyzers import yara_scan
from staticprep.main import analyze_sample


def test_end_to_end_artifact_generation(tmp_path, fixture_dir):
    sample = fixture_dir / "samples" / "note.txt"
    rules_dir = fixture_dir / "rules"

    report, output_dir = analyze_sample(
        sample_path=sample,
        output_root=tmp_path / "output",
        rules_dir=rules_dir,
    )

    expected_artifacts = {
        "report.json",
        "summary.md",
        "strings_ascii.txt",
        "strings_utf16.txt",
        "suspicious_strings.txt",
        "imports.json",
        "yara_matches.json",
    }
    assert expected_artifacts.issubset({path.name for path in output_dir.iterdir()})

    report_json = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    summary = (output_dir / "summary.md").read_text(encoding="utf-8")

    assert report_json["sample"]["name"] == "note.txt"
    assert output_dir.name.startswith("note_")
    assert sorted(report_json.keys()) == [
        "analysis_summary",
        "capabilities",
        "environment",
        "errors",
        "generated_at",
        "hashes",
        "interesting_strings_preview",
        "imports",
        "iocs",
        "packed_assessment",
        "pe",
        "sample",
        "strings",
        "yara",
    ]
    assert sorted(report_json["environment"].keys()) == [
        "degraded_mode",
        "degraded_reasons",
        "pefile_available",
        "python_version",
        "yara_available",
    ]
    assert sorted(report_json["strings"]["suspicious"]["categorized"].keys()) == [
        "appdata_or_temp",
        "commands_or_lolbins",
        "domains",
        "file_paths",
        "ips",
        "other",
        "powershell",
        "registry_paths",
        "urls",
    ]
    assert sorted(report_json["iocs"].keys()) == [
        "commands",
        "domains",
        "file_paths",
        "ips",
        "mutexes",
        "registry_paths",
        "urls",
    ]
    assert sorted(report_json["analysis_summary"].keys()) == [
        "recommended_next_step",
        "reasons",
        "score",
        "severity",
        "top_findings",
    ]
    assert "## Quick Assessment" in summary
    assert "## Top Findings" in summary
    assert "## Environment and Degraded Mode" in summary
    assert "## Likely Packed Assessment" in summary
    assert "## Suspicious Strings Highlights" in summary
    assert "## Capability Highlights" in summary
    assert "## IOC Highlights" in summary
    assert report.sample["name"] == "note.txt"
    assert isinstance(report_json["interesting_strings_preview"], list)


def test_degraded_mode_reporting_when_dependencies_missing(tmp_path, fixture_dir, monkeypatch):
    sample = fixture_dir / "samples" / "note.txt"
    monkeypatch.setattr(pe_analyzer, "pefile", None)
    monkeypatch.setattr("staticprep.main.yara_module", None)
    monkeypatch.setattr(yara_scan, "yara", None)

    report, _ = analyze_sample(
        sample_path=sample,
        output_root=tmp_path / "output",
        rules_dir=fixture_dir / "rules",
    )

    assert report.environment["degraded_mode"] is True
    assert report.environment["pefile_available"] is False
    assert report.environment["yara_available"] is False
    assert any(error.stage == "environment" for error in report.errors)


def test_skipped_analysis_steps_report_explicit_status(tmp_path, fixture_dir):
    sample = fixture_dir / "samples" / "note.txt"
    report, _ = analyze_sample(
        sample_path=sample,
        output_root=tmp_path / "output",
        rules_dir=fixture_dir / "rules",
        skip_pe=True,
        skip_yara=True,
    )

    assert report.pe["skipped"] is True
    assert report.pe["attempted"] is False
    assert report.pe["error"] == "PE parsing skipped by flag."
    assert report.imports["skipped"] is True
    assert report.imports["attempted"] is False
    assert report.yara["skipped"] is True
    assert report.yara["attempted"] is False
    assert report.yara["error"] == "YARA scanning skipped by flag."
