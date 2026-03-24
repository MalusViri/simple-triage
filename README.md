# staticprep

`staticprep` is an offline-first malware static analysis preparation tool for isolated reverse engineering labs. It performs deterministic, local-only triage of Windows PE samples and exports structured artifacts for analyst review and downstream local workflows.

The project is intentionally limited to static analysis preparation. It does not perform dynamic execution, sandboxing, network enrichment, telemetry, or cloud lookups.

## Design Constraints

- Offline only
- No outbound network calls
- No telemetry, analytics, or update checks
- No runtime enrichment from external services
- Local config-driven capability mapping and suspicious string detection
- Graceful handling for malformed files, non-PE files, and missing optional rule sets
- Explicit degraded-mode reporting when optional local dependencies are unavailable

## Features

- Input path validation
- Per-sample output directory creation
- File metadata collection
- MD5, SHA1, and SHA256 hashing
- ASCII and UTF-16LE string extraction
- Suspicious string filtering from local regex config
- PE parsing with `pefile`
- Section entropy calculation
- Import extraction by DLL and flattened API list
- Rule-based capability inference from local JSON config
- Local recursive YARA scanning with `yara-python`
- Structured export artifacts for review and automation
- Explicit per-step status reporting for PE, imports, section entropy, and YARA
- Categorized suspicious string highlights for analyst review
- Deterministic triage scoring and quick assessment summary
- Packed/high-entropy assessment for PE sections
- IOC-ready extraction and curated interesting-string preview

## Repository Layout

```text
config/
  capability_map.json
  suspicious_patterns.json
rules/
  yara/
src/staticprep/
tests/
```

## Setup

Use Python 3.12 or newer.

### Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### Offline Dependency Installation

For isolated environments, pre-stage wheels on a connected system, transfer them into the lab, and install from the local wheel directory only.

Connected staging system:

```bash
mkdir -p wheelhouse
python -m pip download -r requirements.txt -d wheelhouse
```

Isolated lab system:

```bash
python -m pip install --no-index --find-links ./wheelhouse -r requirements.txt
python -m pip install --no-index --find-links ./wheelhouse -e .
```

If `pefile` or `yara-python` are not installed, `staticprep` still runs in degraded mode. The report includes:

- `environment.pefile_available`
- `environment.yara_available`
- `environment.degraded_mode`
- `environment.degraded_reasons`

Structured warnings are also recorded in `errors`, and the affected analysis sections include explicit `attempted`, `succeeded`, `skipped`, and `error` fields instead of relying on ambiguous empty data.

## Usage

Single sample:

```bash
staticprep analyze ./samples/example.exe
staticprep analyze ./samples/example.exe --output ./output
staticprep analyze ./samples/example.exe --rules ./rules/yara
```

Batch mode:

```bash
staticprep batch ./samples --output ./output --recursive
```

Useful flags:

- `--output`
- `--rules`
- `--min-string-length`
- `--recursive`
- `--skip-yara`
- `--skip-pe`
- `--skip-strings`
- `--verbose`

## Output Structure

Each sample produces a self-contained output directory. To reduce collisions across similarly named samples, the directory naming convention is:

```text
output/<sample_stem>_<short_sha256>/
```

Example:

```text
output/invoice_8f3a0d12/
```

Artifacts:

```text
output/<sample_stem>_<short_sha256>/
├─ report.json
├─ summary.md
├─ strings_ascii.txt
├─ strings_utf16.txt
├─ suspicious_strings.txt
├─ imports.json
└─ yara_matches.json
```

`report.json` is the canonical machine-readable artifact. Its stable top-level keys are:

- `sample`
- `environment`
- `analysis_summary`
- `packed_assessment`
- `iocs`
- `interesting_strings_preview`
- `hashes`
- `strings`
- `pe`
- `imports`
- `capabilities`
- `yara`
- `errors`
- `generated_at`

Additive Phase 2 fields include:

- `environment`
  - `python_version`
  - `pefile_available`
  - `yara_available`
  - `degraded_mode`
  - `degraded_reasons`
- `pe`
  - `attempted`
  - `succeeded`
  - `skipped`
  - `error`
  - `section_entropy`
- `imports`
  - `attempted`
  - `succeeded`
  - `skipped`
  - `error`
  - `by_dll`
  - `flat`
  - `total_import_count`
  - `dll_count`
- `strings.suspicious`
  - `matches`
  - `categorized`
- `yara`
  - `attempted`
  - `succeeded`
  - `skipped`
  - `error`
  - `rules_dir`
  - `match_count`

Additive Phase 3 fields include:

- `analysis_summary`
  - `severity`
  - `score`
  - `top_findings`
  - `reasons`
  - `recommended_next_step`
- `packed_assessment`
  - `attempted`
  - `succeeded`
  - `skipped`
  - `error`
  - `high_entropy_sections`
  - `likely_packed`
  - `rationale`
  - `threshold_used`
- `iocs`
  - `urls`
  - `ips`
  - `domains`
  - `registry_paths`
  - `file_paths`
  - `mutexes`
  - `commands`
- `interesting_strings_preview`

## Capability Inference

Capability inference is data-driven from `config/capability_map.json`. API names, string indicators, and YARA tags or rule names map to capability categories such as persistence, networking, process execution, and process injection.

Each capability result includes:

- `matched`
- `evidence`
- `evidence_source`
- `evidence_sources`
- `confidence`

`confidence` is deterministic and intentionally simple:

- `high`: at least two evidence sources and at least three total evidence hits
- `medium`: at least two total evidence hits
- `low`: one or zero evidence hits

## Analysis Summary and Severity

`analysis_summary` is a deterministic rule-based prioritization layer intended for fast triage. It uses local evidence already gathered during static analysis, including:

- matched capabilities and their confidence
- YARA matches
- suspicious string categories
- high-entropy sections
- likely-packed assessment
- degraded-mode awareness

Severity is currently derived from a bounded score:

- `high`: score greater than or equal to the configured high threshold
- `medium`: score greater than or equal to the configured medium threshold
- `low`: below the medium threshold

Recommended next steps are intentionally simple:

- `archive`
- `review_manually`
- `investigate_deeper`

Scoring weights and thresholds are stored locally in `config/analysis_settings.json`.

## Packed and High-Entropy Assessment

`packed_assessment` is an additive top-level section that summarizes whether PE section entropy suggests packing or obfuscation. The logic is threshold-based and deterministic.

It includes:

- `high_entropy_sections`
- `likely_packed`
- `rationale`
- `threshold_used`

If PE parsing is unavailable, skipped, or unsuccessful, the section still appears with explicit state and error metadata.

## IOC Extraction

`iocs` provides a normalized offline-only extraction view intended for downstream analyst workflows and local automation.

Current IOC fields:

- `urls`
- `ips`
- `domains`
- `registry_paths`
- `file_paths`
- `mutexes`
- `commands`

These values are deduplicated and normalized where practical. No internet validation or enrichment is performed.

## YARA Externals

`staticprep` provides a small standard set of YARA external variables for every local scan. These are passed through the yara-python compile and match paths so rules that reference them compile and run without extra user configuration.

Supported externals:

- `filepath`: full resolved sample path as a string
- `filename`: sample basename
- `extension`: lowercase file extension without the leading dot

Example use in a local rule:

```yara
rule MatchExeByExternal
{
    condition:
        extension == "exe" and filename contains "sample"
}
```

## Interesting Strings Preview

`interesting_strings_preview` is a short curated list of higher-value strings for quick review. It prefers categories such as:

- URLs
- PowerShell
- suspicious commands and LOLBins
- registry paths
- appdata/temp paths
- file paths

## Suspicious String Categories

Categorized suspicious string results are exported in `report.json` under `strings.suspicious.categorized`.

Current categories:

- `urls`
- `ips`
- `domains`
- `registry_paths`
- `file_paths`
- `commands_or_lolbins`
- `powershell`
- `appdata_or_temp`
- `other`

Pattern matching remains local and config-driven through `config/suspicious_patterns.json`.

## Assumptions and Limitations

- Degraded mode depends only on local runtime availability of `pefile` and `yara-python`; no attempt is made to fetch missing dependencies.
- Capability confidence is heuristic and intended only as a quick triage aid, not a probabilistic score.
- Analysis severity is heuristic and intended for triage prioritization, not malware verdicting.
- Packed assessment is entropy-based and may flag compressed or otherwise unusual but benign binaries.
- Suspicious string categorization is regex-based and may produce overlaps or benign hits; analysts should treat it as prioritization support.
- Non-PE files and malformed PEs are handled explicitly, but they will still produce empty import data because no import table could be parsed.

## Development

Run tests with:

```bash
pytest
```

The test suite uses only safe local fixtures. PE and YARA-specific tests skip automatically when their optional dependencies are not installed in the current environment.
