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

If `pefile` or `yara-python` are not installed, `staticprep` still runs, but PE parsing or YARA scanning are skipped with structured warnings in `report.json`.

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

Each sample produces a self-contained output directory:

```text
output/<sample_name>/
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
- `hashes`
- `strings`
- `pe`
- `imports`
- `capabilities`
- `yara`
- `errors`
- `generated_at`

## Capability Inference

Capability inference is data-driven from `config/capability_map.json`. API names, string indicators, and YARA tags or rule names map to capability categories such as persistence, networking, process execution, and process injection.

Each capability result includes:

- `matched`
- `evidence`
- `evidence_source`

## Development

Run tests with:

```bash
pytest
```

The test suite uses only safe local fixtures. PE and YARA-specific tests skip automatically when their optional dependencies are not installed in the current environment.
