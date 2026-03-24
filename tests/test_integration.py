"""End-to-end artifact generation tests."""

from __future__ import annotations

import json

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
    assert report_json["sample"]["name"] == "note.txt"
    assert sorted(report_json.keys()) == [
        "capabilities",
        "errors",
        "generated_at",
        "hashes",
        "imports",
        "pe",
        "sample",
        "strings",
        "yara",
    ]
    assert report.sample["name"] == "note.txt"
