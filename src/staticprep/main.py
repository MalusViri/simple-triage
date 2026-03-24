"""Main analysis pipeline."""

from __future__ import annotations

import mimetypes
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from staticprep.analyzers.capabilities import infer_capabilities
from staticprep.analyzers.hashes import compute_hashes
from staticprep.analyzers import pe as pe_analyzer
from staticprep.analyzers.strings import extract_strings_from_file, filter_suspicious_strings
from staticprep.analyzers.yara_scan import run_yara_scan
from staticprep.config import (
    DEFAULT_RULES_DIR,
    load_capability_map,
    load_suspicious_patterns,
)
from staticprep.exporters.json_exporter import export_json
from staticprep.exporters.markdown_exporter import export_markdown
from staticprep.exporters.text_exporter import export_plaintext_list
from staticprep.models import AnalysisError, AnalysisReport
from staticprep.utils.files import ensure_directory, sanitize_sample_name
from staticprep.utils.validators import validate_input_file


def collect_file_metadata(path: Path) -> dict[str, Any]:
    """Collect deterministic file metadata."""
    stat = path.stat()
    type_hint, _ = mimetypes.guess_type(path.name)
    return {
        "name": path.name,
        "path": str(path),
        "size": stat.st_size,
        "type_hint": type_hint or "application/octet-stream",
    }


def analyze_sample(
    sample_path: Path,
    output_root: Path,
    rules_dir: Path | None = None,
    min_string_length: int = 4,
    skip_yara: bool = False,
    skip_pe: bool = False,
    skip_strings: bool = False,
) -> tuple[AnalysisReport, Path]:
    """Run the full analysis pipeline for a single sample."""
    sample_path = validate_input_file(sample_path)
    sample_output_dir = ensure_directory(output_root / sanitize_sample_name(sample_path))

    errors: list[AnalysisError] = []
    metadata = collect_file_metadata(sample_path)
    hashes = compute_hashes(sample_path)

    capability_map = load_capability_map()
    suspicious_patterns = load_suspicious_patterns()

    ascii_strings: list[str] = []
    utf16_strings: list[str] = []
    suspicious_strings: list[dict[str, str]] = []
    if not skip_strings:
        ascii_strings, utf16_strings = extract_strings_from_file(sample_path, min_string_length)
        suspicious_strings = filter_suspicious_strings(
            ascii_strings + utf16_strings,
            suspicious_patterns,
        )

    pe_info: dict[str, Any] = {"is_pe": False}
    imports: dict[str, Any] = {"by_dll": {}, "flat": []}
    if not skip_pe:
        try:
            pe_info, imports = pe_analyzer.analyze_pe(sample_path)
        except Exception as exc:
            pefile_module = getattr(pe_analyzer, "pefile", None)
            pe_format_error = getattr(pefile_module, "PEFormatError", None)
            if pe_format_error is not None and isinstance(exc, pe_format_error):
                errors.append(
                    AnalysisError(
                        stage="pe",
                        message=f"File is not a valid PE: {exc}",
                        severity="warning",
                    )
                )
            elif "pefile is not installed" in str(exc):
                errors.append(
                    AnalysisError(
                        stage="pe",
                        message="pefile is not installed; skipping PE parsing.",
                        severity="warning",
                    )
                )
            else:
                errors.append(
                    AnalysisError(stage="pe", message=f"PE parsing failed: {exc}", severity="error")
                )

    yara_results: dict[str, Any] = {"enabled": not skip_yara, "matches": []}
    if not skip_yara:
        raw_yara, yara_errors = run_yara_scan(sample_path, rules_dir or DEFAULT_RULES_DIR)
        yara_results = raw_yara
        errors.extend(AnalysisError(**error) for error in yara_errors)

    capabilities = infer_capabilities(
        capability_map=capability_map,
        apis=imports["flat"],
        strings=[match["value"] for match in suspicious_strings] + ascii_strings + utf16_strings,
        yara_matches=yara_results["matches"],
    )

    report = AnalysisReport(
        sample=metadata,
        hashes=hashes,
        strings={
            "ascii_count": len(ascii_strings),
            "utf16_count": len(utf16_strings),
            "suspicious_count": len(suspicious_strings),
        },
        pe=pe_info,
        imports=imports,
        capabilities=capabilities,
        yara=yara_results,
        errors=errors,
        generated_at=datetime.now(tz=UTC).isoformat(),
    )
    export_artifacts(report, sample_output_dir, ascii_strings, utf16_strings, suspicious_strings)
    return report, sample_output_dir


def export_artifacts(
    report: AnalysisReport,
    output_dir: Path,
    ascii_strings: list[str],
    utf16_strings: list[str],
    suspicious_strings: list[dict[str, str]],
) -> None:
    """Export report artifacts for a sample."""
    report_dict = report.to_dict()
    export_json(output_dir / "report.json", report_dict)
    export_markdown(output_dir / "summary.md", report_dict)
    export_plaintext_list(output_dir / "strings_ascii.txt", ascii_strings)
    export_plaintext_list(output_dir / "strings_utf16.txt", utf16_strings)
    export_plaintext_list(
        output_dir / "suspicious_strings.txt",
        [f"{item['pattern']}: {item['value']}" for item in suspicious_strings],
    )
    export_json(output_dir / "imports.json", report_dict["imports"])
    export_json(output_dir / "yara_matches.json", report_dict["yara"])


def analyze_batch(
    input_dir: Path,
    output_root: Path,
    rules_dir: Path | None = None,
    recursive: bool = False,
    min_string_length: int = 4,
    skip_yara: bool = False,
    skip_pe: bool = False,
    skip_strings: bool = False,
) -> list[tuple[AnalysisReport, Path]]:
    """Analyze all files in a directory."""
    iterator = input_dir.rglob("*") if recursive else input_dir.glob("*")
    results = []
    for path in sorted(candidate for candidate in iterator if candidate.is_file()):
        results.append(
            analyze_sample(
                sample_path=path,
                output_root=output_root,
                rules_dir=rules_dir,
                min_string_length=min_string_length,
                skip_yara=skip_yara,
                skip_pe=skip_pe,
                skip_strings=skip_strings,
            )
        )
    return results
