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
- Evidence-hygiene gating before strings, paths, commands, and mutex-like artifacts can influence higher-level reasoning
- Context-aware scoring that lets runtime/language and installer context suppress weak suspicious residue
- Packed/high-entropy assessment for PE sections
- IOC-ready extraction and curated interesting-string preview
- Artifact classification and IOC confidence filtering for analyst-facing highlights
- Semantic IOC validation for version-like, local-only, and command-context artifacts
- Path sanity checks and malformed-artifact suppression for analyst highlights
- Separation between analyst-ready findings, contextual findings, and raw exports
- Competitive primary-intent selection with optional secondary intents
- Concise analyst-facing interpretation prose with strongest and suppressed evidence
- Binary context detection for .NET, Go, sparse imports, installer-like packaging, and runtime noise
- Grouped string evidence domains for behavior-oriented review
- Deterministic behavior chaining and cautious intent inference
- Cleaner YARA warning hygiene with explicit YARA health states

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
- `context`
- `findings`
- `interpretation`
- `packed_assessment`
- `iocs`
- `behavior_chains`
- `intent_inference`
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

Additive Phase 4 fields include:

- `findings`
  - `executive_summary`
  - `analyst_ready`
  - `contextual`
  - `raw_references`
- `interpretation`
  - `notes`
  - `codes`
  - `summary`
- `iocs`
  - `classified`
  - `high_confidence`
  - `contextual`
  - `raw_summary`
- `yara`
  - `warning_count`
  - `warnings`
  - `rule_stats`
  - `scan_status`

Additive Phase 5 fields include:

- `context`
  - `is_dotnet`
  - `is_go`
  - `likely_packed`
  - `installer_like`
  - `has_sparse_imports`
  - `has_high_runtime_noise`
  - `evidence`
  - `rationale`
- `strings`
  - `grouped_domains`
- `behavior_chains`
  - `download_write_execute_chain`
  - `persistence_chain`
  - `anti_analysis_chain`
  - `credential_access_chain`
  - `installer_or_packager_chain`
- `intent_inference`
  - `primary`
  - `candidates`

Additive Phase 6 fields include:

- `strings.suspicious.matches[*]`
  - `quality`
  - `allowed_for_reasoning`
  - `quality_reasons`
- `strings.reasoning`
  - `quality_summary`
  - `categorized`
  - `string_quality`
- `iocs`
  - `suppressed`
  - `reasoning_categories`
- `iocs.classified[*]`
  - `quality`
  - `allowed_for_reasoning`
  - `quality_reasons`
- `analysis_summary`
  - `score_breakdown`
  - `dominant_signal_classes`
  - `suppressed_signal_classes`
- `intent_inference`
  - `secondary`
  - `candidates[*].score`
  - `candidates[*].suppressed_by_context`
- `interpretation`
  - `quick_assessment`
  - `analyst_summary`
  - `strongest_evidence`
  - `suppressed_or_contextual_evidence`
- `yara`
  - `yara_health`

## Capability Inference

Capability inference is data-driven from `config/capability_map.json`. API names, string indicators, and YARA tags or rule names map to capability categories such as persistence, networking, process execution, and process injection.

Each capability result includes:

- `matched`
- `evidence`
- `evidence_source`
- `evidence_sources`
- `confidence`
- `score`
- `notes`

`confidence` remains deterministic, but it is now weighted and stricter:

- API, string, and YARA evidence each have local weights in `config/analysis_settings.json`
- weak generic indicators such as bare `http://`, bare `https://`, `startup`, or isolated `debugger` references are down-weighted
- per-capability thresholds can require stronger corroboration before a result becomes `medium` or `high`

This reduces overstatement for capabilities that are supported only by weak generic strings.

## Analysis Summary and Severity

`analysis_summary` is a deterministic rule-based prioritization layer intended for fast triage. Phase 6 rebalances it into strong, medium, and weak signal tiers so corroborated evidence dominates generic residue. It uses local evidence already gathered during static analysis, including:

- matched capabilities and their confidence
- YARA matches
- suspicious string categories
- grouped string behavior domains
- composed behavior chains
- binary runtime/language context
- high-entropy sections
- likely-packed assessment
- degraded-mode awareness

Severity is currently derived from a bounded score, then optionally capped by stronger contextual explanations:

- `high`: score greater than or equal to the configured high threshold
- `medium`: score greater than or equal to the configured medium threshold
- `low`: below the medium threshold

Recommended next steps are intentionally simple:

- `archive`
- `review_manually`
- `investigate_deeper`

Phase 6 context enforcement remains rule-based:

- Go binaries with runtime-heavy strings and high entropy no longer let entropy alone dominate severity
- sparse imports in managed `.NET` samples are treated as meaningful context instead of generic suspicion by default
- installer-like context can suppress malicious intent promotion and cap severity when stronger malicious chains are absent
- weak URL or command residue contributes very little unless corroborated by stronger chain, API, or multi-source evidence
- `analysis_summary.score_breakdown`, `dominant_signal_classes`, and `suppressed_signal_classes` explain exactly what drove or reduced the final score

Scoring weights, thresholds, and context adjustments are stored locally in `config/analysis_settings.json`.

## Binary Context Detection

`context` is a new top-level report section that summarizes cautious runtime and packaging characteristics before prioritization and intent inference.

Current deterministic heuristics include:

- `.NET` indicators from `mscoree.dll`, `_CorExeMain`, `_CorDllMain`, and managed-runtime strings
- `Go` indicators from Go build/runtime strings and Go-specific sections where present
- installer-like context from NSIS, Nullsoft, Electron, Tauri, Squirrel, MSI, and related artifacts
- sparse import detection for PE samples with unusually small import tables
- high runtime-noise detection from framework or packager-heavy string evidence

This section is contextual only. It does not produce malware or benign verdicts.

## Packed and High-Entropy Assessment

`packed_assessment` is an additive top-level section that summarizes whether PE section entropy suggests packing or obfuscation. The logic is threshold-based and deterministic.

It includes:

- `high_entropy_sections`
- `likely_packed`
- `rationale`
- `threshold_used`

If PE parsing is unavailable, skipped, or unsuccessful, the section still appears with explicit state and error metadata.

## IOC Extraction and Artifact Classification

`iocs` provides a normalized offline-only extraction view intended for downstream analyst workflows and local automation.

Current IOC fields:

- `urls`
- `ips`
- `domains`
- `registry_paths`
- `file_paths`
- `mutexes`
- `commands`

These raw values remain deduplicated and normalized where practical. No internet validation or enrichment is performed.

Phase 4 adds deterministic artifact classification so analyst-facing highlights can be more selective without deleting raw data. Supported classes include:

- `high_confidence`
- `low_confidence`
- `malformed`
- `trusted_pki`
- `likely_build_artifact`
- `likely_installer_artifact`
- `contextual_only`

Examples of current filtering behavior:

- CRL, OCSP, and signer infrastructure URLs are downgraded into `trusted_pki`
- malformed domains or malformed Windows paths are labeled instead of highlighted
- manifest-like version values such as `1.0.0.0` are treated as contextual IP noise
- build and installer artifacts are separated from stronger analyst highlights

Phase 5 extends semantic validation for IP artifacts:

- version-like values such as `1.1.1.1` are downgraded when they appear in .NET assembly or runtime-version context
- `1.1.1.1` and similar values are downgraded when they appear in ping, sleep, timeout, or command-testing context
- loopback and other local-only values such as `127.0.0.1` are retained but treated as contextual rather than promoted network IOCs

Phase 6 adds evidence-quality gating on top of classification:

- symbol-heavy or binary-noise-like strings are marked `noisy`
- malformed or implausible Windows paths are marked `malformed`
- bare schemes such as `http://` and weak command-like fragments can be marked `contextual_only`
- `allowed_for_reasoning=false` prevents those artifacts from feeding behavior chains, capability confidence, score, and primary intent
- raw values remain exported, and `iocs.suppressed` provides a direct view of artifacts intentionally excluded from higher-level reasoning

`iocs.high_confidence` and `iocs.contextual` remain curated subsets. `iocs.classified`, `iocs.suppressed`, and the original raw IOC lists remain available for transparency.

## Grouped String Domains

Phase 5 adds `strings.grouped_domains`, a deterministic grouped view of extracted string evidence. Phase 6 ensures the grouped view is built from reasoning-eligible evidence only, while raw strings and suspicious-string matches remain preserved.

Current grouped domains include:

- `network`
- `execution`
- `filesystem`
- `registry`
- `anti_analysis`
- `credentials_or_auth`
- `crypto_or_encoding`
- `installer_or_packager`
- `runtime_or_language`

These domains are driven by local categories and pattern lists in `config/analysis_settings.json`. They support later scoring, chaining, and intent inference while keeping the underlying evidence transparent.

## Behavior Chains and Intent Inference

Phase 5 adds composed behavior inference from multiple evidence families instead of relying only on isolated flags.

Current behavior chains include:

- `download_write_execute_chain`
- `persistence_chain`
- `anti_analysis_chain`
- `credential_access_chain`
- `installer_or_packager_chain`

Each chain exports:

- `matched`
- `confidence`
- `evidence`
- `evidence_sources`

Phase 5 also adds `intent_inference`, which provides cautious analyst hypotheses such as:

- `likely_downloader`
- `likely_packed_loader`
- `likely_credential_aware_tooling`
- `likely_installer_or_packaged_app`
- `likely_managed_obfuscated_payload`
- `ambiguous_requires_manual_review`

Phase 6 makes intent selection competitive instead of purely additive:

- candidates receive weighted scores from chains, validated IOCs, capabilities, and binary context
- installer or packager context can beat weak downloader residue
- the report now records one `primary` intent plus optional `secondary` intents when candidates remain close
- candidate-level `suppressed_by_context` notes explain when context explicitly weakened a competing hypothesis

These are not verdicts; they are explainable hypotheses derived from context, grouped strings, behavior chains, capabilities, and bounded triage scoring.

## Analyst-Ready vs Raw Findings

`summary.md` now separates:

- quick assessment
- interpretation
- binary context
- analyst-ready findings
- behavior chains
- likely intent
- signal scoring
- contextual / low-confidence findings
- interpretation notes
- grouped string evidence
- IOC highlights
- raw findings references

`report.json` mirrors this with the additive `findings` section:

- `findings.executive_summary` for first-screen triage
- `findings.analyst_ready` for stronger findings
- `findings.contextual` for weaker or benign-context findings
- `findings.raw_references` for counts and raw artifact references

Raw exports such as `strings_ascii.txt`, `strings_utf16.txt`, `suspicious_strings.txt`, `imports.json`, and `yara_matches.json` are unchanged and remain available.

## Interpretation Guardrails

`interpretation` adds cautious false-positive guardrails and short analyst-ready prose. It does not assign malware or benign verdicts.

Current note families include:

- `likely_installer_or_packaged_app`
- `possible_electron_nsis_tauri_characteristics`
- `suspiciousness_may_reflect_compression_or_installer_behavior`
- `certificate_or_signing_infrastructure_present`

Phase 6 extends this section with:

- `quick_assessment` for first-screen triage wording
- `analyst_summary` that explains what evidence is strongest
- `strongest_evidence` and `suppressed_or_contextual_evidence` so the reader can see both what drove the interpretation and what was intentionally downgraded

These notes and summaries are derived only from local deterministic heuristics such as installer strings, PKI-related artifacts, high-entropy sections, behavior chains, intent inference, and curated score output.

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

`yara.yara_health` provides a cleaner analyst-facing top-level summary:

- `healthy`
- `healthy_with_minor_rule_errors`
- `degraded`
- `unavailable`

Raw warnings, invalid-rule counts, and `scan_status` are still preserved for transparency.

## Interesting Strings Preview

`interesting_strings_preview` is a short curated list of higher-value strings for quick review. Phase 6 restricts it to reasoning-eligible categories so malformed paths and noisy fragments do not become first-screen highlights. It prefers categories such as:

- high-confidence URLs
- high-confidence commands
- PowerShell
- high-confidence registry paths
- high-confidence domains
- contextual command strings when stronger highlights are absent

## Tuning

Most filtering, hygiene, and weighting behavior is configured locally in `config/analysis_settings.json`.

Key sections:

- `analyst_highlight_limits`
- `artifact_filters.trusted_pki_domains_or_patterns`
- `artifact_filters.build_artifact_patterns`
- `artifact_filters.installer_artifact_patterns`
- `artifact_filters.contextual_ip_values`
- `artifact_filters.semantic_ip_rules`
- `artifact_filters.command_high_confidence_terms`
- `evidence_hygiene`
- `context_detection`
- `behavior_domains`
- `behavior_chains`
- `capabilities.source_weights`
- `capabilities.weak_indicators`
- `capabilities.per_capability_overrides`
- `interpretation.installer_or_packager_patterns`
- `intent_inference`
- `intent_inference.candidate_weights`
- `intent_inference.context_suppression`
- `scoring.tier_weights`
- `scoring.class_multipliers`
- `scoring.context_adjustments`
- `scoring.severity_caps`
- `yara_reporting`

These settings are intended to be tuned against a broader local sample set without introducing network access or nondeterministic behavior.

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
- Context detection, behavior chains, and intent inference are heuristic and intended for analyst prioritization, not verdicting.
- Packed assessment is entropy-based and may flag compressed or otherwise unusual but benign binaries.
- Go binaries and managed runtimes can still produce edge cases that require local tuning against broader sample sets.
- evidence-hygiene thresholds such as symbol-ratio and path-segment sanity rules will need tuning against a broader local sample set
- signal-tier weights and intent competition thresholds are intentionally conservative and may need local adjustment for different software ecosystems
- Suspicious string categorization is regex-based and may produce overlaps or benign hits; analysts should treat it as prioritization support.
- Non-PE files and malformed PEs are handled explicitly, but they will still produce empty import data because no import table could be parsed.

## Development

Run tests with:

```bash
pytest
```

The test suite uses only safe local fixtures. PE and YARA-specific tests skip automatically when their optional dependencies are not installed in the current environment.
