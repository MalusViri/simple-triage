"""Analysis summary and analyst-facing finding helpers."""

from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def assess_packed_status(
    pe_info: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Assess whether a PE appears packed based on high-entropy sections."""
    threshold = analysis_settings["entropy"]["high_entropy_threshold"]
    min_sections = analysis_settings["entropy"]["min_high_entropy_sections_for_likely_packed"]

    if not pe_info.get("attempted", False):
        return {
            "attempted": False,
            "succeeded": False,
            "skipped": True,
            "error": pe_info.get("error") or "Entropy assessment skipped.",
            "high_entropy_sections": [],
            "likely_packed": False,
            "rationale": "PE analysis was skipped, so entropy-based packing assessment was not performed.",
            "threshold_used": threshold,
        }

    if not pe_info.get("succeeded", False) or not pe_info.get("is_pe", False):
        return {
            "attempted": True,
            "succeeded": False,
            "skipped": False,
            "error": pe_info.get("error") or "PE metadata unavailable.",
            "high_entropy_sections": [],
            "likely_packed": False,
            "rationale": "Entropy-based packing assessment requires successful PE parsing.",
            "threshold_used": threshold,
        }

    high_entropy_sections = sorted(
        [
            {"name": section["name"], "entropy": section["entropy"]}
            for section in pe_info.get("sections", [])
            if section.get("entropy", 0.0) >= threshold
        ],
        key=lambda item: (-item["entropy"], item["name"]),
    )
    likely_packed = len(high_entropy_sections) >= min_sections
    rationale = (
        f"{len(high_entropy_sections)} section(s) met or exceeded entropy threshold {threshold}."
        if high_entropy_sections
        else f"No sections met entropy threshold {threshold}."
    )
    if likely_packed:
        rationale = (
            f"Likely packed because {len(high_entropy_sections)} section(s) met or exceeded "
            f"entropy threshold {threshold}."
        )

    return {
        "attempted": True,
        "succeeded": True,
        "skipped": False,
        "error": None,
        "high_entropy_sections": high_entropy_sections,
        "likely_packed": likely_packed,
        "rationale": rationale,
        "threshold_used": threshold,
    }


def build_analysis_summary(
    capabilities: dict[str, dict[str, Any]],
    iocs: dict[str, Any],
    yara_results: dict[str, Any],
    packed_assessment: dict[str, Any],
    environment: dict[str, Any],
    analysis_settings: dict[str, Any],
    context: dict[str, Any] | None = None,
    behavior_chains: dict[str, Any] | None = None,
    correlated_behaviors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a deterministic top-level triage summary."""
    tier_weights = analysis_settings["scoring"]["tier_weights"]
    multipliers = analysis_settings["scoring"]["class_multipliers"]
    thresholds = analysis_settings["scoring"]["severity_thresholds"]
    adjustments = analysis_settings["scoring"].get("context_adjustments", {})
    severity_caps = analysis_settings["scoring"].get("severity_caps", {})
    context = context or {}
    behavior_chains = behavior_chains or {}
    correlated_behaviors = correlated_behaviors or []
    classified_iocs = iocs.get("classified", {})

    score = 0
    reasons: list[str] = []
    top_findings: list[str] = []
    breakdown: list[dict[str, Any]] = []
    suppressed_signal_classes: list[str] = []

    def add_signal(
        signal_class: str,
        tier: str,
        count: int,
        reason: str,
        top_finding: str | None = None,
        multiplier_key: str | None = None,
        suppressed: bool = False,
    ) -> None:
        nonlocal score
        if count <= 0:
            return
        multiplier = multipliers.get(multiplier_key or signal_class, 1.0)
        delta = int(round(tier_weights[tier] * count * multiplier))
        if suppressed:
            suppressed_signal_classes.append(signal_class)
            breakdown.append(
                {
                    "signal_class": signal_class,
                    "tier": tier,
                    "count": count,
                    "delta": 0,
                    "suppressed": True,
                    "reason": reason,
                }
            )
            return
        score += delta
        reasons.append(reason)
        breakdown.append(
            {
                "signal_class": signal_class,
                "tier": tier,
                "count": count,
                "delta": delta,
                "suppressed": False,
                "reason": reason,
            }
        )
        if top_finding:
            top_findings.append(top_finding)

    def low_conf_count(artifact_type: str) -> int:
        return len(
            [
                entry
                for entry in classified_iocs.get(artifact_type, [])
                if entry.get("classification") == "low_confidence"
                and entry.get("allowed_for_reasoning", False)
            ]
        )

    high_caps = sorted(
        [name for name, data in capabilities.items() if data["matched"] and data["confidence"] == "high"]
    )
    medium_caps = sorted(
        [name for name, data in capabilities.items() if data["matched"] and data["confidence"] == "medium"]
    )
    low_caps = sorted(
        [name for name, data in capabilities.items() if data["matched"] and data["confidence"] == "low"]
    )

    if high_caps:
        add_signal(
            "high_confidence_capability",
            "strong",
            len(high_caps),
            f"{len(high_caps)} high-confidence capability match(es)",
            f"High-confidence capabilities: {', '.join(high_caps[:3])}",
        )
    if medium_caps:
        add_signal(
            "medium_confidence_capability",
            "medium",
            len(medium_caps),
            f"{len(medium_caps)} medium-confidence capability match(es)",
        )
    if low_caps:
        add_signal(
            "low_confidence_capability",
            "weak",
            len(low_caps),
            f"{len(low_caps)} low-confidence capability match(es)",
        )

    if yara_results.get("match_count", 0):
        add_signal(
            "yara_match",
            "strong",
            yara_results["match_count"],
            f"{yara_results['match_count']} YARA match(es)",
            f"YARA hits: {', '.join(match['rule'] for match in yara_results['matches'][:3])}",
        )

    high_entropy_sections = packed_assessment.get("high_entropy_sections", [])
    high_iocs = iocs.get("high_confidence", {})
    contextual_iocs = iocs.get("contextual", {})

    validated_urls = len(high_iocs.get("urls", []))
    validated_domains = len(high_iocs.get("domains", []))
    registry_count = len(high_iocs.get("registry_paths", []))
    command_count = len(high_iocs.get("commands", []))
    file_path_count = len(high_iocs.get("file_paths", []))
    low_conf_url_count = low_conf_count("urls")
    low_conf_command_count = low_conf_count("commands")

    strong_malicious_chain_present = any(
        behavior_chains.get(name, {}).get("matched")
        for name in (
            "download_write_execute_chain",
            "persistence_chain",
            "credential_access_chain",
        )
    )

    if validated_urls or validated_domains:
        add_signal(
            "external_url_or_domain",
            "strong",
            validated_urls + validated_domains,
            f"{validated_urls + validated_domains} validated external URL/domain indicator(s)",
            "Validated external network indicators were identified",
        )
    if registry_count:
        add_signal(
            "registry_path",
            "medium",
            registry_count,
            f"{registry_count} validated registry path indicator(s)",
            "Persistence-relevant registry paths were identified",
        )
    if command_count:
        add_signal(
            "command",
            "medium",
            command_count,
            f"{command_count} meaningful command indicator(s)",
            "Meaningful suspicious command strings were identified",
        )
    if file_path_count:
        add_signal(
            "file_path",
            "medium",
            file_path_count,
            f"{file_path_count} validated Windows file path indicator(s)",
        )
    if low_conf_url_count:
        add_signal(
            "weak_network_residue",
            "weak",
            low_conf_url_count,
            f"{low_conf_url_count} weak URL indicator(s) were retained as low-confidence residue",
        )
    if low_conf_command_count:
        add_signal(
            "weak_command_residue",
            "weak",
            low_conf_command_count,
            f"{low_conf_command_count} weak command indicator(s) were retained as low-confidence residue",
        )

    for chain_name, chain in sorted(behavior_chains.items()):
        if chain.get("matched"):
            add_signal(
                f"behavior_chain:{chain_name}",
                "strong" if chain.get("confidence") == "high" else "medium",
                1,
                f"Behavior chain matched: {chain_name}",
                chain_name.replace("_", " "),
                multiplier_key=f"behavior_chain_{chain.get('confidence', 'medium')}",
            )

    matched_correlated_behaviors = [
        behavior for behavior in correlated_behaviors if behavior.get("matched")
    ]
    for behavior in matched_correlated_behaviors:
        behavior_name = behavior["name"]
        add_signal(
            f"correlated_behavior:{behavior_name}",
            "strong" if behavior.get("confidence") == "high" else "medium",
            1,
            f"Correlated behavior matched: {behavior_name}",
            f"Likely behavior: {behavior.get('summary_label', behavior_name.replace('_', ' '))}",
        )

    entropy_only_suppressed = False
    if high_entropy_sections:
        suppressed = context.get("is_go") and not strong_malicious_chain_present
        entropy_only_suppressed = suppressed
        add_signal(
            "packed_entropy",
            "medium",
            len(high_entropy_sections),
            f"{len(high_entropy_sections)} high-entropy PE section(s)",
            "High-entropy sections were identified",
            suppressed=suppressed,
        )
    if packed_assessment.get("likely_packed"):
        suppressed = (
            (context.get("is_go") and not strong_malicious_chain_present)
            or (context.get("installer_like") and not strong_malicious_chain_present)
        )
        add_signal(
            "likely_packed",
            "medium",
            1,
            "Entropy profile suggests the sample may be packed or compressed",
            "Likely packed based on PE section entropy",
            suppressed=suppressed,
        )

    if context.get("is_go") and packed_assessment.get("likely_packed") and not strong_malicious_chain_present:
        score += adjustments["go_entropy_only_penalty"]
        reasons.append("Go runtime context reduced confidence in entropy-only packing suspicion")
        suppressed_signal_classes.append("go_entropy_only")

    if context.get("is_dotnet") and context.get("has_sparse_imports") and not strong_malicious_chain_present:
        score += adjustments["dotnet_sparse_imports_penalty"]
        reasons.append(".NET sparse imports were treated as managed-runtime context rather than generic suspicion")
        suppressed_signal_classes.append("dotnet_sparse_imports")

    if context.get("installer_like"):
        score += adjustments["installer_like_penalty"]
        reasons.append("Installer-like context reduced severity absent stronger corroboration")
        if not strong_malicious_chain_present and (low_conf_url_count or low_conf_command_count):
            score += adjustments["installer_weak_signal_suppression"]
            reasons.append("Installer context suppressed weak downloader or network residue")
            suppressed_signal_classes.extend(["weak_network_residue", "weak_command_residue"])

    if context.get("has_high_runtime_noise"):
        score += adjustments["runtime_noise_penalty"]
        reasons.append("High runtime-noise context reduced confidence in generic string hits")

    if environment.get("degraded_mode"):
        score += int(round(tier_weights["medium"] * multipliers["degraded_mode_penalty"]))
        reasons.append("Runtime degraded mode reduced available evidence")
        top_findings.append("Analysis ran in degraded mode")

    score = max(0, min(score, 100))
    if score >= thresholds["high"]:
        severity = "high"
        recommended_next_step = "investigate_deeper"
    elif score >= thresholds["medium"]:
        severity = "medium"
        recommended_next_step = "review_manually"
    else:
        severity = "low"
        recommended_next_step = "archive"

    if context.get("installer_like") and not strong_malicious_chain_present:
        capped = severity_caps.get("installer_without_malicious_chain")
        if capped and SEVERITY_ORDER[severity] > SEVERITY_ORDER[capped]:
            severity = capped
            recommended_next_step = "archive" if capped == "low" else "review_manually"
    if context.get("is_go") and entropy_only_suppressed and not strong_malicious_chain_present:
        capped = severity_caps.get("go_entropy_only")
        if capped and SEVERITY_ORDER[severity] > SEVERITY_ORDER[capped]:
            severity = capped
            recommended_next_step = "archive" if capped == "low" else "review_manually"

    primary_behavior = matched_correlated_behaviors[0] if matched_correlated_behaviors else None
    if primary_behavior:
        desired_severity = primary_behavior.get("severity_hint")
        if desired_severity and SEVERITY_ORDER[severity] < SEVERITY_ORDER[desired_severity]:
            severity = desired_severity
        if primary_behavior.get("recommended_next_step") == "investigate_deeper":
            recommended_next_step = "investigate_deeper"
        elif primary_behavior.get("recommended_next_step") == "archive" and severity == "low":
            recommended_next_step = "archive"

    if not top_findings:
        if environment.get("degraded_mode"):
            top_findings.append("Analysis ran in degraded mode")
        else:
            top_findings.append("No strong static indicators were identified")

    dominant_signal_classes = [
        item["signal_class"]
        for item in sorted(
            [entry for entry in breakdown if not entry["suppressed"] and entry["delta"] > 0],
            key=lambda entry: (-entry["delta"], entry["signal_class"]),
        )[:4]
    ]

    return {
        "severity": severity,
        "score": score,
        "top_findings": list(dict.fromkeys(top_findings))[:5],
        "reasons": reasons[:10],
        "recommended_next_step": recommended_next_step,
        "score_breakdown": breakdown,
        "dominant_signal_classes": dominant_signal_classes,
        "suppressed_signal_classes": sorted(set(suppressed_signal_classes)),
    }


def build_findings(
    analysis_summary: dict[str, Any],
    capabilities: dict[str, dict[str, Any]],
    iocs: dict[str, Any],
    interpretation: dict[str, Any],
    yara_results: dict[str, Any],
    packed_assessment: dict[str, Any],
    errors: list[dict[str, Any]],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Build curated analyst-ready and contextual finding groups."""
    limit = analysis_settings["analyst_highlight_limits"]["top_findings"]
    contextual_limit = analysis_settings["analyst_highlight_limits"]["contextual_findings"]

    analyst_ready: list[dict[str, Any]] = []
    contextual: list[dict[str, Any]] = []

    for capability, data in sorted(capabilities.items()):
        if not data["matched"]:
            continue
        finding = {
            "type": "capability",
            "name": capability,
            "confidence": data["confidence"],
            "evidence": data["evidence"][:3],
            "score": data.get("score", 0),
            "notes": data.get("notes", []),
        }
        if data["confidence"] in {"high", "medium"}:
            analyst_ready.append(finding)
        else:
            contextual.append(finding)

    for artifact_type, entries in sorted(iocs.get("high_confidence", {}).items()):
        for entry in entries:
            analyst_ready.append(
                {
                    "type": "ioc",
                    "name": artifact_type,
                    "confidence": "high",
                    "evidence": [entry["value"]],
                    "classification": entry["classification"],
                    "notes": entry["reasons"],
                }
            )

    for artifact_type, entries in sorted(iocs.get("contextual", {}).items()):
        for entry in entries:
            contextual.append(
                {
                    "type": "ioc",
                    "name": artifact_type,
                    "confidence": "contextual",
                    "evidence": [entry["value"]],
                    "classification": entry["classification"],
                    "notes": entry["reasons"],
                    "quality": entry.get("quality"),
                    "allowed_for_reasoning": entry.get("allowed_for_reasoning"),
                }
            )

    for artifact_type, entries in sorted(iocs.get("suppressed", {}).items()):
        for entry in entries:
            contextual.append(
                {
                    "type": "suppressed_ioc",
                    "name": artifact_type,
                    "confidence": "suppressed",
                    "evidence": [entry["value"]],
                    "classification": entry["classification"],
                    "notes": entry["quality_reasons"] + entry["reasons"],
                    "quality": entry.get("quality"),
                    "allowed_for_reasoning": entry.get("allowed_for_reasoning"),
                }
            )

    for note in interpretation.get("notes", []):
        contextual.append(
            {
                "type": "interpretation",
                "name": note["code"],
                "confidence": "contextual",
                "evidence": note.get("evidence", [])[:3],
                "notes": [note["summary"]],
            }
        )

    if yara_results.get("match_count", 0):
        analyst_ready.append(
            {
                "type": "yara",
                "name": "yara_matches",
                "confidence": "high",
                "evidence": [match["rule"] for match in yara_results["matches"][:3]],
                "notes": ["Local YARA rules matched the sample"],
            }
        )

    if packed_assessment.get("likely_packed"):
        contextual.append(
            {
                "type": "packing",
                "name": "likely_packed",
                "confidence": "contextual",
                "evidence": [
                    section["name"] for section in packed_assessment.get("high_entropy_sections", [])[:3]
                ],
                "notes": [packed_assessment["rationale"]],
            }
        )

    executive_summary = {
        "worth_deeper_investigation": analysis_summary["recommended_next_step"] != "archive",
        "recommended_next_step": analysis_summary["recommended_next_step"],
        "severity": analysis_summary["severity"],
        "score": analysis_summary["score"],
        "analysis_degraded": any(error["stage"] == "environment" for error in errors),
        "top_findings": analysis_summary["top_findings"],
        "dominant_signal_classes": analysis_summary.get("dominant_signal_classes", []),
        "suppressed_signal_classes": analysis_summary.get("suppressed_signal_classes", []),
    }

    raw_references = {
        "suspicious_string_count": iocs["raw_summary"]["total"],
        "ioc_raw_summary": iocs["raw_summary"],
        "artifact_files": [
            "report.json",
            "strings_ascii.txt",
            "strings_utf16.txt",
            "suspicious_strings.txt",
            "imports.json",
            "yara_matches.json",
        ],
    }

    return {
        "executive_summary": executive_summary,
        "analyst_ready": analyst_ready[:limit],
        "contextual": contextual[:contextual_limit],
        "raw_references": raw_references,
    }
