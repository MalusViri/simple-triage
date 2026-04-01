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


def _allowed_entries(entries: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Return entries that are eligible for higher-level reasoning."""
    return [entry for entry in (entries or []) if entry.get("allowed_for_reasoning", True)]


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
    allowed_contextual_paths = _allowed_entries(contextual_iocs.get("file_paths"))
    allowed_commands = _allowed_entries(high_iocs.get("commands"))
    allowed_urls = _allowed_entries(high_iocs.get("urls"))

    def capability_matched(name: str) -> bool:
        return bool(capabilities.get(name, {}).get("matched"))

    def group_matched(name: str) -> bool:
        return bool(grouped_strings.get(name, {}).get("matched"))

    chains: dict[str, dict[str, Any]] = {}

    download_signal_count = sum(
        [
            capability_matched("downloader_behavior"),
            capability_matched("networking"),
            bool(allowed_urls),
            group_matched("network"),
        ]
    )
    execution_signal_count = sum(
        [
            capability_matched("process_execution"),
            group_matched("execution"),
            bool(allowed_commands),
        ]
    )
    filesystem_signal_count = sum(
        [
            group_matched("filesystem"),
            bool(_allowed_entries(high_iocs.get("file_paths")) or allowed_contextual_paths),
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
                "iocs": bool(allowed_urls or allowed_commands or allowed_contextual_paths),
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
    correlated_behaviors: list[dict[str, Any]],
    grouped_strings: dict[str, dict[str, Any]],
    iocs: dict[str, Any],
    analysis_summary: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build explainable analyst hypotheses from context and composed behaviors."""
    settings = analysis_settings["intent_inference"]
    candidates: list[dict[str, Any]] = []
    candidate_weights = settings["candidate_weights"]
    correlated_intent_weights = settings["behavior_correlation_candidate_weights"]
    suppressions = settings["context_suppression"]
    high_iocs = iocs.get("high_confidence", {})
    classified = iocs.get("classified", {})

    def high_conf_count(name: str) -> int:
        return len(_allowed_entries(high_iocs.get(name)))

    def weak_count(name: str) -> int:
        return len(
            [
                entry
                for entry in classified.get(name, [])
                if entry.get("classification") == "low_confidence"
                and entry.get("allowed_for_reasoning", False)
            ]
        )

    strong_malicious_chain_present = any(
        behavior_chains.get(name, {}).get("matched")
        for name in (
            "download_write_execute_chain",
            "credential_access_chain",
            "persistence_chain",
        )
    )

    def add_candidate(
        name: str,
        score: int,
        rationale: list[str],
        evidence: list[str],
        suppressed_reasons: list[str] | None = None,
    ) -> None:
        if score <= 0:
            return
        confidence = "high" if score >= settings["minimum_primary_score"] + 4 else "medium"
        unique_rationale = [item for item in rationale if item]
        unique_evidence = sorted(set(item for item in evidence if item))[:6]
        candidates.append(
            {
                "name": name,
                "matched": True,
                "score": score,
                "confidence": confidence if len(unique_rationale) >= settings["high_confidence_min_rationale_count"] else "medium",
                "rationale": unique_rationale[:5],
                "evidence": unique_evidence,
                "suppressed_by_context": suppressed_reasons or [],
            }
        )

    for behavior in correlated_behaviors:
        if not behavior.get("matched"):
            continue
        add_candidate(
            behavior["name"],
            correlated_intent_weights.get(behavior["confidence"], 0),
            behavior.get("rationale", []),
            behavior.get("evidence", []),
        )

    downloader_score = 0
    downloader_rationale: list[str] = []
    downloader_evidence: list[str] = []
    downloader_suppressed: list[str] = []
    if behavior_chains["download_write_execute_chain"]["matched"]:
        downloader_score += candidate_weights["download_chain"]
        downloader_rationale.append("download, write, and execute evidence forms a composed chain")
        downloader_evidence.extend(behavior_chains["download_write_execute_chain"]["evidence"])
    if capabilities.get("downloader_behavior", {}).get("matched"):
        downloader_score += candidate_weights["downloader_capability"]
        downloader_rationale.append("downloader capability indicators matched")
        downloader_evidence.extend(capabilities.get("downloader_behavior", {}).get("evidence", []))
    if capabilities.get("networking", {}).get("matched"):
        downloader_score += candidate_weights["networking_capability"]
        downloader_rationale.append("networking capability indicators matched")
        downloader_evidence.extend(capabilities.get("networking", {}).get("evidence", []))
    if high_conf_count("urls") or high_conf_count("domains"):
        downloader_score += (high_conf_count("urls") + high_conf_count("domains")) * candidate_weights["external_network_ioc"]
        downloader_rationale.append("validated external network indicators were observed")
        downloader_evidence.extend(
            [entry["value"] for entry in _allowed_entries(high_iocs.get("urls"))[:2]]
            + [entry["value"] for entry in _allowed_entries(high_iocs.get("domains"))[:2]]
        )
    if high_conf_count("commands"):
        downloader_score += high_conf_count("commands") * candidate_weights["execution_ioc"]
        downloader_rationale.append("meaningful execution-oriented commands were observed")
        downloader_evidence.extend([entry["value"] for entry in _allowed_entries(high_iocs.get("commands"))[:2]])
    if context.get("installer_like") and not strong_malicious_chain_present:
        downloader_score -= suppressions["installer_without_malicious_chain"]
        downloader_suppressed.append("installer-like context outweighed weak downloader residue")
    if weak_count("urls") or weak_count("commands"):
        downloader_score -= suppressions["weak_network_residue"]
        downloader_suppressed.append("generic URL or command residue was treated as weak without corroboration")

    add_candidate(
        "likely_downloader",
        downloader_score,
        downloader_rationale,
        downloader_evidence,
        downloader_suppressed,
    )

    packed_loader_score = 0
    packed_loader_rationale: list[str] = []
    packed_loader_evidence: list[str] = []
    packed_loader_suppressed: list[str] = []
    if context.get("likely_packed"):
        packed_loader_score += candidate_weights["packed_context"]
        packed_loader_rationale.append("entropy profile suggests compression or packing")
        packed_loader_evidence.extend(context.get("evidence", {}).get("high_entropy_sections", []))
    if behavior_chains["download_write_execute_chain"]["matched"]:
        packed_loader_score += candidate_weights["download_chain"]
        packed_loader_rationale.append("packed context is paired with a download and execution chain")
        packed_loader_evidence.extend(behavior_chains["download_write_execute_chain"]["evidence"])
    if context.get("is_go") and not strong_malicious_chain_present:
        packed_loader_score -= suppressions["go_entropy_only"]
        packed_loader_suppressed.append("Go runtime context reduced confidence in entropy-only packing suspicion")

    add_candidate(
        "likely_packed_loader",
        packed_loader_score,
        packed_loader_rationale,
        packed_loader_evidence,
        packed_loader_suppressed,
    )

    add_candidate(
        "likely_credential_aware_tooling",
        candidate_weights["credential_chain"] if behavior_chains["credential_access_chain"]["matched"] else 0,
        [
            "credential or auth-related strings were observed",
            "credential access capability indicators matched",
        ],
        behavior_chains["credential_access_chain"]["evidence"]
        + capabilities.get("credential_access_indicators", {}).get("evidence", []),
    )

    installer_score = 0
    installer_rationale: list[str] = []
    installer_evidence: list[str] = []
    if context.get("installer_like"):
        installer_score += candidate_weights["installer_context"]
        installer_rationale.append("installer or packager context is strong")
        installer_evidence.extend(context.get("evidence", {}).get("installer_strings", []))
    if behavior_chains["installer_or_packager_chain"]["matched"]:
        installer_score += candidate_weights["installer_chain"]
        installer_rationale.append("installer or packaged-application artifacts form a coherent chain")
        installer_evidence.extend(behavior_chains["installer_or_packager_chain"]["evidence"])
    if context.get("has_high_runtime_noise"):
        installer_score += candidate_weights["runtime_noise"]
        installer_rationale.append("runtime strings are dominated by framework or packaging residue")
        installer_evidence.extend(context.get("evidence", {}).get("runtime_noise_strings", []))
    if installer_score > 0 and not strong_malicious_chain_present:
        installer_score += 2
        installer_rationale.append("stronger malicious chains are absent")

    add_candidate(
        "likely_installer_or_packaged_app",
        installer_score,
        installer_rationale,
        installer_evidence,
    )

    managed_score = 0
    managed_rationale: list[str] = []
    managed_evidence: list[str] = []
    if context.get("is_dotnet") and context.get("has_sparse_imports"):
        managed_score += candidate_weights["dotnet_managed_context"]
        managed_rationale.extend(
            [
                ".NET indicators were observed",
                "the sparse import table is consistent with managed code",
            ]
        )
        managed_evidence.extend(
            context.get("evidence", {}).get("dotnet_imports", [])
            + context.get("evidence", {}).get("dotnet_symbols", [])
        )
    if capabilities.get("anti_analysis", {}).get("matched"):
        managed_score += candidate_weights["anti_analysis_capability"]
        managed_rationale.append("anti-analysis indicators were also observed")
        managed_evidence.extend(capabilities.get("anti_analysis", {}).get("evidence", []))

    add_candidate(
        "likely_managed_obfuscated_payload",
        managed_score,
        managed_rationale,
        managed_evidence,
    )

    ranked_candidates = sorted(
        candidates,
        key=lambda item: (-item["score"], item["name"]),
    )
    if not ranked_candidates or ranked_candidates[0]["score"] < settings["minimum_primary_score"]:
        candidates.append(
            {
                "name": "ambiguous_requires_manual_review",
                "matched": True,
                "confidence": "low",
                "score": 0,
                "rationale": [
                    "evidence did not support a single strong hypothesis"
                ],
                "evidence": analysis_summary.get("top_findings", [])[:4],
                "suppressed_by_context": [],
            }
        )
        ranked_candidates = sorted(
            candidates,
            key=lambda item: (-item["score"], item["name"]),
        )

    primary = ranked_candidates[0]["name"]
    secondary = [
        candidate["name"]
        for candidate in ranked_candidates[1:]
        if ranked_candidates[0]["score"] - candidate["score"] < settings["minimum_primary_margin"]
    ]

    return {
        "candidates": ranked_candidates,
        "primary": primary,
        "secondary": secondary,
    }
