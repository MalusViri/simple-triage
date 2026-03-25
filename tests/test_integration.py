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
        "behavior_chains",
        "capabilities",
        "context",
        "environment",
        "errors",
        "findings",
        "generated_at",
        "hashes",
        "imports",
        "intent_inference",
        "interesting_strings_preview",
        "interpretation",
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
    assert "grouped_domains" in report_json["strings"]
    assert sorted(report_json["iocs"].keys()) == [
        "classified",
        "commands",
        "contextual",
        "domains",
        "file_paths",
        "high_confidence",
        "ips",
        "mutexes",
        "raw_summary",
        "registry_paths",
        "urls",
    ]
    assert sorted(report_json["context"].keys()) == [
        "evidence",
        "has_high_runtime_noise",
        "has_sparse_imports",
        "installer_like",
        "is_dotnet",
        "is_go",
        "likely_packed",
        "rationale",
    ]
    assert sorted(report_json["analysis_summary"].keys()) == [
        "reasons",
        "recommended_next_step",
        "score",
        "severity",
        "top_findings",
    ]
    assert sorted(report_json["findings"].keys()) == [
        "analyst_ready",
        "contextual",
        "executive_summary",
        "raw_references",
    ]
    assert sorted(report_json["interpretation"].keys()) == ["codes", "notes", "summary"]
    assert "## Quick Assessment" in summary
    assert "## Binary Context" in summary
    assert "## Top Findings" in summary
    assert "## Behavior Chains" in summary
    assert "## Likely Intent" in summary
    assert "## Analyst-Ready Findings" in summary
    assert "## Contextual / Low-Confidence Findings" in summary
    assert "## Interpretation Notes" in summary
    assert "## Grouped String Evidence" in summary
    assert "## Raw Findings References" in summary
    assert "## Environment and Degraded Mode" in summary
    assert "## IOC Highlights" in summary
    assert "## YARA Status" in summary
    assert report.sample["name"] == "note.txt"
    assert isinstance(report_json["interesting_strings_preview"], list)
    assert "raw_summary" in report_json["iocs"]
    assert "warning_count" in report_json["yara"]


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
