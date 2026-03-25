"""Context, grouped string, behavior-chain, and intent helpers."""

from __future__ import annotations

from typing import Any


def _contains_any(values: list[str], patterns: list[str]) -> list[str]:
    """Return sorted patterns observed in the provided values."""
    lowered_values = [value.lower() for value in values]
    matches = {
        pattern
        for pattern in patterns
        if any(pattern.lower() in value for value in lowered_values)
    }
    return sorted(matches)


def _append_unique(bucket: list[str], seen: set[str], value: str) -> None:
    """Append a string once while preserving insertion order."""
    if value not in seen:
        bucket.append(value)
        seen.add(value)


def detect_binary_context(
    imports: dict[str, Any],
    pe_info: dict[str, Any],
    all_strings: list[str],
    packed_assessment: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build a cautious context profile from deterministic local evidence."""
    settings = analysis_settings["context_detection"]
    flat_imports = [value.lower() for value in imports.get("flat", [])]
    dlls = [value.lower() for value in imports.get("by_dll", {})]
    lowered_strings = [value.lower() for value in all_strings]
    section_names = [section.get("name", "").lower() for section in pe_info.get("sections", [])]

    dotnet_import_matches = sorted(
        {value for value in settings["dotnet_import_indicators"] if value.lower() in dlls}
    )
    dotnet_symbol_matches = sorted(
        {value for value in settings["dotnet_symbol_indicators"] if value.lower() in flat_imports}
    )
    dotnet_string_matches = _contains_any(lowered_strings, settings["dotnet_string_patterns"])

    go_string_matches = _contains_any(lowered_strings, settings["go_string_patterns"])
    go_section_matches = sorted(
        {
            value
            for value in settings["go_section_patterns"]
            if any(value.lower() in section for section in section_names)
        }
    )

    installer_matches = _contains_any(lowered_strings, settings["installer_patterns"])
    runtime_noise_matches = _contains_any(lowered_strings, settings["runtime_noise_patterns"])

    sparse_thresholds = settings["sparse_import_thresholds"]
    dll_count = imports.get("dll_count", 0)
    flat_count = imports.get("total_import_count", 0)
    has_sparse_imports = bool(
        pe_info.get("is_pe")
        and imports.get("attempted")
        and imports.get("succeeded")
        and dll_count <= sparse_thresholds["max_dll_count"]
        and flat_count <= sparse_thresholds["max_api_count"]
    )

    is_dotnet = bool(dotnet_import_matches or dotnet_symbol_matches or dotnet_string_matches)
    is_go = bool(go_string_matches or go_section_matches)
    installer_like = len(installer_matches) >= settings["minimum_installer_signals"]
    has_high_runtime_noise = len(runtime_noise_matches) >= settings["minimum_runtime_noise_signals"]
    likely_packed = bool(packed_assessment.get("likely_packed"))

    rationale: list[str] = []
    if is_dotnet:
        rationale.append(".NET indicators were observed")
    if is_go:
        rationale.append("Go runtime indicators were observed")
    if installer_like:
        rationale.append("Installer or packager artifacts were observed")
    if has_sparse_imports:
        rationale.append("Import table is sparse for a PE sample")
    if has_high_runtime_noise:
        rationale.append("Runtime or framework noise dominated string evidence")
    if likely_packed:
        rationale.append("Entropy profile suggests packing or compression")

    return {
        "is_dotnet": is_dotnet,
        "is_go": is_go,
        "likely_packed": likely_packed,
        "installer_like": installer_like,
        "has_sparse_imports": has_sparse_imports,
        "has_high_runtime_noise": has_high_runtime_noise,
        "evidence": {
            "dotnet_imports": dotnet_import_matches,
            "dotnet_symbols": dotnet_symbol_matches,
            "dotnet_strings": dotnet_string_matches[:6],
            "go_strings": go_string_matches[:6],
            "go_sections": go_section_matches,
            "installer_strings": installer_matches[:6],
            "runtime_noise_strings": runtime_noise_matches[:6],
            "import_profile": [
                f"dll_count={dll_count}",
                f"api_count={flat_count}",
            ],
            "high_entropy_sections": [
                section["name"] for section in packed_assessment.get("high_entropy_sections", [])[:4]
            ],
        },
        "rationale": rationale,
    }


def group_strings_by_behavior(
    all_strings: list[str],
    suspicious_categories: dict[str, list[str]],
    analysis_settings: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Group raw strings into deterministic behavior domains."""
    domain_patterns = analysis_settings["behavior_domains"]
    lowered_strings = [value.lower() for value in all_strings]
    category_values = {
        name: [value.lower() for value in values] for name, values in suspicious_categories.items()
    }

    grouped: dict[str, dict[str, Any]] = {}
    for domain, config in sorted(domain_patterns.items()):
        evidence: list[str] = []
        seen: set[str] = set()

        for category_name in config.get("categories", []):
            for value in suspicious_categories.get(category_name, [])[:10]:
                _append_unique(evidence, seen, value)

        for pattern in config.get("terms", []):
            lowered_pattern = pattern.lower()
            for original, lowered in zip(all_strings, lowered_strings, strict=False):
                if lowered_pattern in lowered:
                    _append_unique(evidence, seen, original)
                    if len(evidence) >= 10:
                        break
            if len(evidence) >= 10:
                break

        observed_categories = sorted(
            category_name
            for category_name in config.get("categories", [])
            if category_values.get(category_name)
        )
        grouped[domain] = {
            "matched": bool(evidence),
            "count": len(evidence),
            "evidence": evidence,
            "source_categories": observed_categories,
        }

    return grouped


def infer_behavior_chains(
    context: dict[str, Any],
    capabilities: dict[str, dict[str, Any]],
    grouped_strings: dict[str, dict[str, Any]],
    iocs: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Infer composed behavior chains from multiple evidence families."""
    settings = analysis_settings["behavior_chains"]
    high_iocs = iocs.get("high_confidence", {})
    contextual_iocs = iocs.get("contextual", {})

    def capability_matched(name: str) -> bool:
        return bool(capabilities.get(name, {}).get("matched"))

    def group_matched(name: str) -> bool:
        return bool(grouped_strings.get(name, {}).get("matched"))

    chains: dict[str, dict[str, Any]] = {}

    download_signal_count = sum(
        [
            capability_matched("downloader_behavior"),
            capability_matched("networking"),
            bool(high_iocs.get("urls")),
            group_matched("network"),
        ]
    )
    execution_signal_count = sum(
        [
            capability_matched("process_execution"),
            group_matched("execution"),
            bool(high_iocs.get("commands")),
        ]
    )
    filesystem_signal_count = sum(
        [
            group_matched("filesystem"),
            bool(high_iocs.get("file_paths") or contextual_iocs.get("file_paths")),
        ]
    )
    download_write_execute = (
        download_signal_count >= settings["download_write_execute_chain"]["minimum_download_signals"]
        and execution_signal_count >= settings["download_write_execute_chain"]["minimum_execution_signals"]
        and filesystem_signal_count >= settings["download_write_execute_chain"]["minimum_filesystem_signals"]
    )
    chains["download_write_execute_chain"] = {
        "matched": download_write_execute,
        "confidence": "high" if download_write_execute and download_signal_count >= 3 else "medium" if download_write_execute else "low",
        "evidence": sorted(
            set(
                capabilities.get("downloader_behavior", {}).get("evidence", [])[:2]
                + capabilities.get("networking", {}).get("evidence", [])[:2]
                + grouped_strings.get("network", {}).get("evidence", [])[:2]
                + grouped_strings.get("execution", {}).get("evidence", [])[:2]
                + grouped_strings.get("filesystem", {}).get("evidence", [])[:2]
            )
        )[:6],
        "evidence_sources": sorted(
            source
            for source, matched in {
                "capabilities": capability_matched("downloader_behavior") or capability_matched("networking") or capability_matched("process_execution"),
                "grouped_strings": group_matched("network") or group_matched("execution") or group_matched("filesystem"),
                "iocs": bool(high_iocs.get("urls") or high_iocs.get("commands") or contextual_iocs.get("file_paths")),
            }.items()
            if matched
        ),
    }

    persistence_chain = (
        capability_matched("persistence")
        and (group_matched("registry") or bool(high_iocs.get("registry_paths")))
    )
    chains["persistence_chain"] = {
        "matched": persistence_chain,
        "confidence": "high" if persistence_chain and bool(high_iocs.get("registry_paths")) else "medium" if persistence_chain else "low",
        "evidence": sorted(
            set(
                capabilities.get("persistence", {}).get("evidence", [])[:3]
                + grouped_strings.get("registry", {}).get("evidence", [])[:3]
            )
        )[:6],
        "evidence_sources": sorted(
            source
            for source, matched in {
                "capabilities": capability_matched("persistence"),
                "grouped_strings": group_matched("registry"),
                "iocs": bool(high_iocs.get("registry_paths")),
            }.items()
            if matched
        ),
    }

    anti_analysis_chain = capability_matched("anti_analysis") and group_matched("anti_analysis")
    chains["anti_analysis_chain"] = {
        "matched": anti_analysis_chain,
        "confidence": "high" if anti_analysis_chain and context.get("likely_packed") else "medium" if anti_analysis_chain else "low",
        "evidence": sorted(
            set(
                capabilities.get("anti_analysis", {}).get("evidence", [])[:3]
                + grouped_strings.get("anti_analysis", {}).get("evidence", [])[:3]
            )
        )[:6],
        "evidence_sources": sorted(
            source
            for source, matched in {
                "capabilities": capability_matched("anti_analysis"),
                "grouped_strings": group_matched("anti_analysis"),
                "context": bool(context.get("likely_packed")),
            }.items()
            if matched
        ),
    }

    credential_chain = capability_matched("credential_access_indicators") and (
        group_matched("credentials_or_auth") or bool(high_iocs.get("commands"))
    )
    chains["credential_access_chain"] = {
        "matched": credential_chain,
        "confidence": "high" if credential_chain and group_matched("credentials_or_auth") else "medium" if credential_chain else "low",
        "evidence": sorted(
            set(
                capabilities.get("credential_access_indicators", {}).get("evidence", [])[:3]
                + grouped_strings.get("credentials_or_auth", {}).get("evidence", [])[:3]
            )
        )[:6],
        "evidence_sources": sorted(
            source
            for source, matched in {
                "capabilities": capability_matched("credential_access_indicators"),
                "grouped_strings": group_matched("credentials_or_auth"),
                "iocs": bool(high_iocs.get("commands")),
            }.items()
            if matched
        ),
    }

    installer_chain = context.get("installer_like") and (
        group_matched("installer_or_packager") or group_matched("runtime_or_language")
    )
    chains["installer_or_packager_chain"] = {
        "matched": installer_chain,
        "confidence": "high" if installer_chain and context.get("has_high_runtime_noise") else "medium" if installer_chain else "low",
        "evidence": sorted(
            set(
                context.get("evidence", {}).get("installer_strings", [])[:3]
                + grouped_strings.get("installer_or_packager", {}).get("evidence", [])[:3]
                + grouped_strings.get("runtime_or_language", {}).get("evidence", [])[:3]
            )
        )[:6],
        "evidence_sources": sorted(
            source
            for source, matched in {
                "context": bool(context.get("installer_like")),
                "grouped_strings": group_matched("installer_or_packager") or group_matched("runtime_or_language"),
            }.items()
            if matched
        ),
    }

    return chains


def infer_intents(
    context: dict[str, Any],
    capabilities: dict[str, dict[str, Any]],
    behavior_chains: dict[str, dict[str, Any]],
    grouped_strings: dict[str, dict[str, Any]],
    analysis_summary: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build explainable analyst hypotheses from context and composed behaviors."""
    settings = analysis_settings["intent_inference"]
    candidates: list[dict[str, Any]] = []

    def add_candidate(name: str, matched: bool, rationale: list[str], evidence: list[str]) -> None:
        if not matched:
            return
        candidates.append(
            {
                "name": name,
                "matched": True,
                "confidence": "high" if len(rationale) >= settings["high_confidence_min_rationale_count"] else "medium",
                "rationale": rationale[:5],
                "evidence": sorted(set(evidence))[:6],
            }
        )

    add_candidate(
        "likely_downloader",
        behavior_chains["download_write_execute_chain"]["matched"]
        or (
            capabilities.get("downloader_behavior", {}).get("matched")
            and grouped_strings.get("network", {}).get("matched")
        ),
        [
            reason
            for reason in [
                "network indicators are present" if grouped_strings.get("network", {}).get("matched") else "",
                "download-related capability matched" if capabilities.get("downloader_behavior", {}).get("matched") else "",
                "execution behavior was also observed" if behavior_chains["download_write_execute_chain"]["matched"] else "",
            ]
            if reason
        ],
        behavior_chains["download_write_execute_chain"]["evidence"]
        + capabilities.get("downloader_behavior", {}).get("evidence", []),
    )
    add_candidate(
        "likely_packed_loader",
        context.get("likely_packed")
        and behavior_chains["download_write_execute_chain"]["matched"],
        [
            "high-entropy sections were observed",
            "download or execution signals were chained together",
        ],
        context.get("evidence", {}).get("high_entropy_sections", [])
        + behavior_chains["download_write_execute_chain"]["evidence"],
    )
    add_candidate(
        "likely_credential_aware_tooling",
        behavior_chains["credential_access_chain"]["matched"],
        [
            "credential or auth-related strings were observed",
            "credential access capability indicators matched",
        ],
        behavior_chains["credential_access_chain"]["evidence"]
        + capabilities.get("credential_access_indicators", {}).get("evidence", []),
    )
    add_candidate(
        "likely_installer_or_packaged_app",
        behavior_chains["installer_or_packager_chain"]["matched"],
        [
            "installer or packager strings were observed",
            "runtime or packaged-application noise was observed"
            if context.get("has_high_runtime_noise")
            else "",
        ],
        behavior_chains["installer_or_packager_chain"]["evidence"],
    )
    add_candidate(
        "likely_managed_obfuscated_payload",
        context.get("is_dotnet")
        and context.get("has_sparse_imports")
        and (context.get("likely_packed") or capabilities.get("anti_analysis", {}).get("matched")),
        [
            ".NET indicators were observed",
            "the import table is sparse",
            "packing or anti-analysis indicators were observed",
        ],
        context.get("evidence", {}).get("dotnet_imports", [])
        + context.get("evidence", {}).get("dotnet_symbols", [])
        + capabilities.get("anti_analysis", {}).get("evidence", []),
    )
    add_candidate(
        "likely_benign_packaged_utility",
        context.get("installer_like")
        and not behavior_chains["download_write_execute_chain"]["matched"]
        and analysis_summary.get("severity") == "low",
        [
            "installer-like context was observed",
            "stronger chained behavior was not observed",
            "overall severity remained low",
        ],
        context.get("evidence", {}).get("installer_strings", [])
        + grouped_strings.get("runtime_or_language", {}).get("evidence", []),
    )

    ambiguous = not candidates or all(
        candidate["confidence"] == "medium" for candidate in candidates
    )
    if ambiguous:
        candidates.append(
            {
                "name": "ambiguous_requires_manual_review",
                "matched": True,
                "confidence": "medium",
                "rationale": [
                    "evidence did not support a single strong hypothesis"
                ],
                "evidence": analysis_summary.get("top_findings", [])[:4],
            }
        )

    return {
        "candidates": sorted(candidates, key=lambda item: (item["name"] != "ambiguous_requires_manual_review", item["name"])),
        "primary": next(
            (
                candidate["name"]
                for candidate in candidates
                if candidate["name"] != "ambiguous_requires_manual_review"
            ),
            "ambiguous_requires_manual_review",
        ),
    }
