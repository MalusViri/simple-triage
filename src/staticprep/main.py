"""Main analysis pipeline."""

from __future__ import annotations

import mimetypes
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from staticprep.analyzers.capabilities import infer_capabilities
from staticprep.analyzers.hashes import compute_hashes
from staticprep.analyzers.iocs import build_interesting_strings_preview, extract_iocs
from staticprep.analyzers import pe as pe_analyzer
from staticprep.analyzers.prioritization import assess_packed_status, build_analysis_summary
from staticprep.analyzers.strings import extract_strings_from_file, filter_suspicious_strings
from staticprep.analyzers.yara_scan import run_yara_scan, yara as yara_module
from staticprep.config import (
    load_analysis_settings,
    DEFAULT_RULES_DIR,
    load_capability_map,
    load_suspicious_patterns,
)
from staticprep.exporters.json_exporter import export_json
from staticprep.exporters.markdown_exporter import export_markdown
from staticprep.exporters.text_exporter import export_plaintext_list
from staticprep.models import AnalysisError, AnalysisReport
from staticprep.utils.files import build_output_directory_name, ensure_directory
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


def build_environment_report(skip_pe: bool, skip_yara: bool) -> dict[str, Any]:
    """Return environment and dependency status for the current runtime."""
    pefile_available = getattr(pe_analyzer, "pefile", None) is not None
    yara_available = yara_module is not None
    degraded_reasons = []
    if not pefile_available and not skip_pe:
        degraded_reasons.append("pefile unavailable")
    if not yara_available and not skip_yara:
        degraded_reasons.append("yara-python unavailable")
    return {
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "pefile_available": pefile_available,
        "yara_available": yara_available,
        "degraded_mode": bool(degraded_reasons),
        "degraded_reasons": degraded_reasons,
    }


def _default_pe_status(skipped: bool = False, error: str | None = None) -> dict[str, Any]:
    """Return a consistent PE status object."""
    return {
        "attempted": not skipped,
        "succeeded": False,
        "skipped": skipped,
        "error": error,
        "is_pe": False,
        "machine_type": None,
        "compile_timestamp": None,
        "subsystem": None,
        "entry_point": None,
        "image_base": None,
        "number_of_sections": 0,
        "sections": [],
        "section_entropy": {
            "attempted": not skipped,
            "succeeded": False,
            "skipped": skipped,
            "error": error,
        },
    }


def _default_imports_status(skipped: bool = False, error: str | None = None) -> dict[str, Any]:
    """Return a consistent imports status object."""
    return {
        "attempted": not skipped,
        "succeeded": False,
        "skipped": skipped,
        "error": error,
        "by_dll": {},
        "flat": [],
        "total_import_count": 0,
        "dll_count": 0,
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

    errors: list[AnalysisError] = []
    metadata = collect_file_metadata(sample_path)
    hashes = compute_hashes(sample_path)
    sample_output_dir = ensure_directory(
        output_root / build_output_directory_name(sample_path, hashes["sha256"][:8])
    )

    capability_map = load_capability_map()
    suspicious_patterns = load_suspicious_patterns()
    analysis_settings = load_analysis_settings()
    environment = build_environment_report(skip_pe=skip_pe, skip_yara=skip_yara)
    if environment["degraded_mode"]:
        for reason in environment["degraded_reasons"]:
            errors.append(
                AnalysisError(
                    stage="environment",
                    message=f"Runtime degraded mode enabled: {reason}.",
                    severity="warning",
                )
            )

    ascii_strings: list[str] = []
    utf16_strings: list[str] = []
    suspicious_strings: list[dict[str, str]] = []
    suspicious_categories = {
        "urls": [],
        "ips": [],
        "domains": [],
        "registry_paths": [],
        "file_paths": [],
        "commands_or_lolbins": [],
        "powershell": [],
        "appdata_or_temp": [],
        "other": [],
    }
    if not skip_strings:
        ascii_strings, utf16_strings = extract_strings_from_file(sample_path, min_string_length)
        suspicious_strings, suspicious_categories = filter_suspicious_strings(
            ascii_strings + utf16_strings,
            suspicious_patterns,
        )

    pe_info: dict[str, Any] = _default_pe_status(skipped=skip_pe, error="PE parsing skipped by flag." if skip_pe else None)
    imports: dict[str, Any] = _default_imports_status(skipped=skip_pe, error="Import extraction skipped by flag." if skip_pe else None)
    if not skip_pe:
        try:
            pe_info, imports = pe_analyzer.analyze_pe(sample_path)
            imports.update(
                {
                    "attempted": True,
                    "succeeded": True,
                    "skipped": False,
                    "error": None,
                }
            )
        except Exception as exc:
            pefile_module = getattr(pe_analyzer, "pefile", None)
            pe_format_error = getattr(pefile_module, "PEFormatError", None)
            if pe_format_error is not None and isinstance(exc, pe_format_error):
                message = f"File is not a valid PE: {exc}"
                pe_info = _default_pe_status(skipped=False, error=message)
                imports = _default_imports_status(skipped=False, error=message)
                errors.append(
                    AnalysisError(
                        stage="pe",
                        message=message,
                        severity="warning",
                    )
                )
            elif "pefile is not installed" in str(exc):
                message = "pefile is not installed; skipping PE parsing."
                pe_info = _default_pe_status(skipped=True, error=message)
                imports = _default_imports_status(skipped=True, error=message)
                errors.append(
                    AnalysisError(
                        stage="pe",
                        message=message,
                        severity="warning",
                    )
                )
            else:
                message = f"PE parsing failed: {exc}"
                pe_info = _default_pe_status(skipped=False, error=message)
                imports = _default_imports_status(skipped=False, error=message)
                errors.append(
                    AnalysisError(stage="pe", message=message, severity="error")
                )

    yara_results: dict[str, Any] = {
        "attempted": not skip_yara,
        "succeeded": False,
        "skipped": skip_yara,
        "error": "YARA scanning skipped by flag." if skip_yara else None,
        "enabled": not skip_yara,
        "rules_dir": str(rules_dir or DEFAULT_RULES_DIR),
        "match_count": 0,
        "matches": [],
    }
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
    capabilities_dict = {
        name: {
            "matched": result.matched,
            "evidence": result.evidence,
            "evidence_source": result.evidence_source,
            "evidence_sources": result.evidence_sources,
            "confidence": result.confidence,
        }
        for name, result in capabilities.items()
    }

    packed_assessment = assess_packed_status(pe_info, analysis_settings)
    iocs = extract_iocs(suspicious_strings, suspicious_categories)
    interesting_strings_preview = build_interesting_strings_preview(
        suspicious_categories,
        iocs,
        limit=analysis_settings["interesting_strings_preview_limit"],
    )
    analysis_summary = build_analysis_summary(
        capabilities=capabilities_dict,
        suspicious_categories=suspicious_categories,
        yara_results=yara_results,
        packed_assessment=packed_assessment,
        environment=environment,
        analysis_settings=analysis_settings,
    )

    report = AnalysisReport(
        sample=metadata,
        environment=environment,
        analysis_summary=analysis_summary,
        packed_assessment=packed_assessment,
        iocs=iocs,
        interesting_strings_preview=interesting_strings_preview,
        hashes=hashes,
        strings={
            "ascii_count": len(ascii_strings),
            "utf16_count": len(utf16_strings),
            "suspicious_count": len(suspicious_strings),
            "suspicious": {
                "matches": suspicious_strings,
                "categorized": suspicious_categories,
            },
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
