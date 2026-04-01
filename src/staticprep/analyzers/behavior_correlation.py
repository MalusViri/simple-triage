"""Correlate higher-value analyst behavior patterns from existing static evidence."""

from __future__ import annotations

from typing import Any


def _append_unique(bucket: list[str], seen: set[str], value: str) -> None:
    """Append a value once while preserving insertion order."""
    if value and value not in seen:
        bucket.append(value)
        seen.add(value)


def _take_values(entries: list[dict[str, Any]] | None, limit: int = 3) -> list[str]:
    """Return entry values from IOC views."""
    return [entry["value"] for entry in (entries or [])[:limit]]


def _has_any_import(flat_imports: set[str], names: list[str]) -> bool:
    """Return whether any import name is present."""
    lowered_names = {name.lower() for name in names}
    return bool(flat_imports.intersection(lowered_names))


def _canonical_injection_chain_present(flat_imports: set[str], settings: dict[str, Any]) -> bool:
    """Return whether a canonical injection sequence is statically visible."""
    return all(
        _has_any_import(flat_imports, names)
        for names in settings["api_groups"].values()
    )


def _entries_with_terms(entries: list[dict[str, Any]] | None, terms: list[str]) -> list[str]:
    """Return IOC values that contain any supplied term."""
    lowered_terms = [term.lower() for term in terms]
    matched: list[str] = []
    for entry in entries or []:
        value = str(entry.get("value", ""))
        lowered_value = value.lower()
        if any(term in lowered_value for term in lowered_terms):
            matched.append(value)
    return matched


def correlate_behaviors(
    capabilities: dict[str, dict[str, Any]],
    grouped_strings: dict[str, dict[str, Any]],
    iocs: dict[str, Any],
    behavior_chains: dict[str, dict[str, Any]],
    context: dict[str, Any],
    imports: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build deterministic correlated behavior patterns for triage guidance."""
    settings = analysis_settings["behavior_correlation"]
    downloader_requirements = settings.get("downloader_requirements", {})
    limits = settings["limits"]
    high_iocs = iocs.get("high_confidence", {})
    contextual_iocs = iocs.get("contextual", {})
    flat_imports = {value.lower() for value in imports.get("flat", [])}
    matched_malicious_behaviors: set[str] = set()

    def capability_confidence(name: str) -> str:
        return capabilities.get(name, {}).get("confidence", "low")

    def capability_matched(name: str) -> bool:
        return bool(capabilities.get(name, {}).get("matched"))

    def group_matched(name: str) -> bool:
        return bool(grouped_strings.get(name, {}).get("matched"))

    def add_behavior(
        name: str,
        matched: bool,
        score: int,
        rationale: list[str],
        evidence: list[str],
        analyst_next_steps: list[str],
        recommended_next_step: str,
        severity_hint: str,
        summary_label: str,
    ) -> dict[str, Any]:
        confidence = "low"
        if matched:
            confidence = (
                "high"
                if score >= settings["confidence_thresholds"]["high"]
                else "medium"
            )
        return {
            "name": name,
            "matched": matched,
            "confidence": confidence,
            "score": score if matched else 0,
            "summary_label": summary_label,
            "recommended_next_step": recommended_next_step if matched else "review_manually",
            "severity_hint": severity_hint if matched else "low",
            "evidence": list(dict.fromkeys(item for item in evidence if item))[: limits["evidence"]],
            "rationale": list(dict.fromkeys(item for item in rationale if item))[: limits["rationale"]],
            "analyst_next_steps": analyst_next_steps[: limits["next_steps"]] if matched else [],
        }

    download_evidence: list[str] = []
    download_rationale: list[str] = []
    download_score = 0
    retrieval_api_hits = sorted(
        {
            api_name
            for api_name in downloader_requirements.get("retrieval_api_terms", [])
            if api_name.lower() in flat_imports
        }
    )
    payload_path_hits = _entries_with_terms(
        high_iocs.get("file_paths", []) + contextual_iocs.get("file_paths", []),
        list(downloader_requirements.get("staging_path_terms", [])),
    )
    execution_present = capability_matched("process_execution") or group_matched("execution") or bool(high_iocs.get("commands"))
    nontrusted_external_ioc = bool(high_iocs.get("urls") or high_iocs.get("domains"))
    if behavior_chains.get("download_write_execute_chain", {}).get("matched"):
        download_score += settings["weights"]["behavior_chain"]
        download_rationale.append("download, write, and execute evidence forms a corroborated chain")
        download_evidence.extend(behavior_chains["download_write_execute_chain"].get("evidence", []))
    if capability_matched("downloader_behavior"):
        download_score += settings["weights"]["capability_high"] if capability_confidence("downloader_behavior") == "high" else settings["weights"]["capability_medium"]
        download_rationale.append("downloader-related APIs or strings were observed")
        download_evidence.extend(capabilities["downloader_behavior"].get("evidence", []))
    if capability_matched("networking"):
        download_score += settings["weights"]["networking_capability"]
        download_rationale.append("networking evidence supports external retrieval behavior")
        download_evidence.extend(capabilities["networking"].get("evidence", []))
    if capability_matched("process_execution"):
        download_score += settings["weights"]["execution_capability"]
        download_rationale.append("execution APIs support staged payload launch")
        download_evidence.extend(capabilities["process_execution"].get("evidence", []))
    if high_iocs.get("urls") or high_iocs.get("domains"):
        download_score += settings["weights"]["external_ioc"]
        download_rationale.append("validated external network indicators were retained for reasoning")
        download_evidence.extend(_take_values(high_iocs.get("urls")))
        download_evidence.extend(_take_values(high_iocs.get("domains")))
    self_delete_commands = [
        entry["value"]
        for entry in iocs.get("classified", {}).get("commands", [])
        if entry.get("allowed_for_reasoning", False)
        and any(term in entry["value"].lower() for term in settings["command_patterns"]["self_delete"])
    ]
    if self_delete_commands:
        download_score += settings["weights"]["self_delete_command"]
        download_rationale.append("command-based self-delete or delayed cleanup behavior was observed")
        download_evidence.extend(self_delete_commands)
    if high_iocs.get("commands"):
        download_score += settings["weights"]["command_ioc"]
        download_rationale.append("command execution evidence was retained for reasoning")
        download_evidence.extend(_take_values(high_iocs.get("commands")))
    if high_iocs.get("file_paths") or contextual_iocs.get("file_paths"):
        download_score += settings["weights"]["filesystem_ioc"]
        download_rationale.append("filesystem paths suggest payload staging or output locations")
        download_evidence.extend(_take_values(high_iocs.get("file_paths")))
        download_evidence.extend(_take_values(contextual_iocs.get("file_paths")))

    strong_downloader_corroboration = (
        behavior_chains.get("download_write_execute_chain", {}).get("matched")
        or (
            bool(retrieval_api_hits)
            and execution_present
            and (
                bool(payload_path_hits)
                or bool(self_delete_commands)
                or nontrusted_external_ioc
            )
        )
    )
    if retrieval_api_hits:
        download_rationale.append("retrieval-oriented networking APIs were observed")
        download_evidence.extend(retrieval_api_hits[:3])

    if context.get("installer_like") and not any(
        behavior_chains.get(name, {}).get("matched")
        for name in ("download_write_execute_chain", "credential_access_chain", "persistence_chain")
    ):
        download_score -= settings["weights"]["installer_suppression"]
        download_rationale.append("installer-like context weakened downloader residue without a stronger malicious chain")

    downloader_behavior = add_behavior(
        name="likely_downloader_or_dropper",
        matched=(
            download_score >= settings["match_thresholds"]["likely_downloader_or_dropper"]
            and strong_downloader_corroboration
            and not (context.get("installer_like") and not behavior_chains.get("download_write_execute_chain", {}).get("matched") and not self_delete_commands and not payload_path_hits)
        ),
        score=download_score,
        rationale=download_rationale,
        evidence=download_evidence,
        analyst_next_steps=settings["next_steps"]["likely_downloader_or_dropper"],
        recommended_next_step="investigate_deeper",
        severity_hint="high",
        summary_label="downloader or dropper",
    )
    if downloader_behavior["matched"]:
        matched_malicious_behaviors.add(downloader_behavior["name"])

    injection_evidence: list[str] = []
    injection_rationale: list[str] = []
    injection_score = 0
    canonical_injection = _canonical_injection_chain_present(
        flat_imports,
        settings["process_injection_loader"],
    )
    if canonical_injection:
        injection_score += settings["weights"]["canonical_injection_chain"]
        injection_rationale.append("a canonical remote-process injection API sequence is present")
        seen_injection_evidence: set[str] = set()
        for names in settings["process_injection_loader"]["api_groups"].values():
            for name in names:
                if name.lower() in flat_imports:
                    _append_unique(injection_evidence, seen_injection_evidence, name)
                    break
    if capability_matched("process_injection"):
        injection_score += settings["weights"]["process_injection_capability"]
        injection_rationale.append("process injection capability indicators matched")
        injection_evidence.extend(capabilities["process_injection"].get("evidence", []))
    if group_matched("crypto_or_encoding"):
        injection_score += settings["weights"]["crypto_or_encoding"]
        injection_rationale.append("crypto or encoding support may hide or transform injected payload content")
        injection_evidence.extend(grouped_strings["crypto_or_encoding"].get("evidence", []))
    if capability_matched("anti_analysis") or behavior_chains.get("anti_analysis_chain", {}).get("matched"):
        injection_score += settings["weights"]["anti_analysis_boost"]
        injection_rationale.append("anti-analysis evidence boosts confidence in the loader hypothesis")
        injection_evidence.extend(capabilities.get("anti_analysis", {}).get("evidence", []))
    if context.get("likely_packed"):
        injection_score += settings["weights"]["packed_context"]
        injection_rationale.append("packed or compressed context may support staged loader behavior")
        injection_evidence.extend(context.get("evidence", {}).get("high_entropy_sections", []))

    injection_behavior = add_behavior(
        name="likely_process_injection_loader",
        matched=injection_score >= settings["match_thresholds"]["likely_process_injection_loader"],
        score=injection_score,
        rationale=injection_rationale,
        evidence=injection_evidence,
        analyst_next_steps=settings["next_steps"]["likely_process_injection_loader"],
        recommended_next_step="investigate_deeper",
        severity_hint="high",
        summary_label="process injection loader",
    )
    if injection_behavior["matched"]:
        matched_malicious_behaviors.add(injection_behavior["name"])

    obfuscated_evidence: list[str] = []
    obfuscated_rationale: list[str] = []
    obfuscated_score = 0
    if context.get("likely_packed"):
        obfuscated_score += settings["weights"]["packed_context"]
        obfuscated_rationale.append("entropy profile suggests compression, packing, or obfuscation")
        obfuscated_evidence.extend(context.get("evidence", {}).get("high_entropy_sections", []))
    if group_matched("crypto_or_encoding"):
        obfuscated_score += settings["weights"]["crypto_or_encoding"]
        obfuscated_rationale.append("crypto or encoding strings suggest hidden or transformed content")
        obfuscated_evidence.extend(grouped_strings["crypto_or_encoding"].get("evidence", []))
    if capability_matched("anti_analysis") or behavior_chains.get("anti_analysis_chain", {}).get("matched"):
        obfuscated_score += settings["weights"]["anti_analysis_boost"]
        obfuscated_rationale.append("anti-analysis indicators are present")
        obfuscated_evidence.extend(capabilities.get("anti_analysis", {}).get("evidence", []))
    if capability_matched("process_execution") or group_matched("execution"):
        obfuscated_score += settings["weights"]["execution_capability"]
        obfuscated_rationale.append("execution-oriented evidence is present alongside obfuscation context")
        obfuscated_evidence.extend(capabilities.get("process_execution", {}).get("evidence", []))
        obfuscated_evidence.extend(grouped_strings.get("execution", {}).get("evidence", []))

    obfuscated_behavior = add_behavior(
        name="likely_obfuscated_loader",
        matched=(
            obfuscated_score >= settings["match_thresholds"]["likely_obfuscated_loader"]
            and not downloader_behavior["matched"]
            and not injection_behavior["matched"]
        ),
        score=obfuscated_score,
        rationale=obfuscated_rationale,
        evidence=obfuscated_evidence,
        analyst_next_steps=settings["next_steps"]["likely_obfuscated_loader"],
        recommended_next_step="investigate_deeper",
        severity_hint="medium",
        summary_label="obfuscated loader",
    )
    if obfuscated_behavior["matched"]:
        matched_malicious_behaviors.add(obfuscated_behavior["name"])

    installer_score = 0
    installer_rationale: list[str] = []
    installer_evidence: list[str] = []
    if context.get("installer_like"):
        installer_score += settings["weights"]["installer_context"]
        installer_rationale.append("installer or packager context is dominant")
        installer_evidence.extend(context.get("evidence", {}).get("installer_strings", []))
    if behavior_chains.get("installer_or_packager_chain", {}).get("matched"):
        installer_score += settings["weights"]["installer_chain"]
        installer_rationale.append("packager-related strings form a coherent contextual chain")
        installer_evidence.extend(behavior_chains["installer_or_packager_chain"].get("evidence", []))
    if context.get("has_high_runtime_noise"):
        installer_score += settings["weights"]["runtime_noise"]
        installer_rationale.append("runtime or framework noise dominates string evidence")
        installer_evidence.extend(context.get("evidence", {}).get("runtime_noise_strings", []))

    installer_behavior = add_behavior(
        name="likely_installer_or_packaged_app",
        matched=(
            installer_score >= settings["match_thresholds"]["likely_installer_or_packaged_app"]
            and not matched_malicious_behaviors
        ),
        score=installer_score,
        rationale=installer_rationale,
        evidence=installer_evidence,
        analyst_next_steps=settings["next_steps"]["likely_installer_or_packaged_app"],
        recommended_next_step="archive",
        severity_hint="low",
        summary_label="installer or packaged application",
    )

    runtime_score = 0
    runtime_rationale: list[str] = []
    runtime_evidence: list[str] = []
    if context.get("is_dotnet"):
        runtime_score += settings["weights"]["runtime_context"]
        runtime_rationale.append(".NET runtime context is present")
        runtime_evidence.extend(context.get("evidence", {}).get("dotnet_imports", []))
        runtime_evidence.extend(context.get("evidence", {}).get("dotnet_symbols", []))
    if context.get("is_go"):
        runtime_score += settings["weights"]["runtime_context"]
        runtime_rationale.append("Go runtime context is present")
        runtime_evidence.extend(context.get("evidence", {}).get("go_sections", []))
        runtime_evidence.extend(context.get("evidence", {}).get("go_strings", []))
    if context.get("has_high_runtime_noise"):
        runtime_score += settings["weights"]["runtime_noise"]
        runtime_rationale.append("runtime or framework noise dominates reasoning-eligible strings")
        runtime_evidence.extend(context.get("evidence", {}).get("runtime_noise_strings", []))

    runtime_behavior = add_behavior(
        name="benign_or_low_signal_packaged_runtime",
        matched=(
            runtime_score >= settings["match_thresholds"]["benign_or_low_signal_packaged_runtime"]
            and not matched_malicious_behaviors
            and not installer_behavior["matched"]
        ),
        score=runtime_score,
        rationale=runtime_rationale,
        evidence=runtime_evidence,
        analyst_next_steps=settings["next_steps"]["benign_or_low_signal_packaged_runtime"],
        recommended_next_step="archive",
        severity_hint="low",
        summary_label="low-signal packaged runtime",
    )

    behaviors = [
        downloader_behavior,
        injection_behavior,
        obfuscated_behavior,
        installer_behavior,
        runtime_behavior,
    ]
    return sorted(
        behaviors,
        key=lambda item: (
            not item["matched"],
            -item["score"],
            item["name"],
        ),
    )
