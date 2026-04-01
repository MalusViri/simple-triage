"""Final analyst-facing decision normalization and false-positive suppression."""

from __future__ import annotations

from typing import Any


_DEFAULT_LABELS = {
    "likely_process_injection_loader": "process injection loader",
    "likely_downloader_or_dropper": "downloader or dropper",
    "likely_obfuscated_loader": "obfuscated loader candidate",
    "likely_installer_or_packaged_app": "installer or packaged application",
    "benign_or_low_signal_packaged_runtime": "low-signal packaged runtime",
    "likely_managed_obfuscated_payload": "managed obfuscated payload candidate",
    "likely_downloader": "downloader candidate",
    "likely_packed_loader": "packed loader candidate",
    "ambiguous_requires_manual_review": "mixed static signals",
}

_ACTION_VERBS = (
    "review",
    "inspect",
    "recover",
    "trace",
    "check",
    "confirm",
    "preserve",
    "archive",
    "analyze",
    "extract",
    "decode",
)


def _behavior_label(name: str, summary_label: str | None = None) -> str:
    """Return a readable analyst-facing label."""
    if summary_label:
        return summary_label
    return _DEFAULT_LABELS.get(name, name.replace("_", " "))


def _contains_term(value: str, terms: list[str]) -> bool:
    lowered = value.lower()
    return any(term.lower() in lowered for term in terms)


def _is_actionable(step: str) -> bool:
    """Return whether next-step text is phrased as an analyst action."""
    lowered = step.strip().lower()
    return bool(lowered) and any(lowered.startswith(verb) for verb in _ACTION_VERBS)


def _dedupe(values: list[str]) -> list[str]:
    """Return a deterministic de-duplicated list."""
    return list(dict.fromkeys(value for value in values if value))


def _build_notable_iocs(iocs: dict[str, Any], settings: dict[str, Any], limit: int = 3) -> list[str]:
    """Return compact non-trusted IOC values for analyst-facing summaries."""
    filtered: list[str] = []
    suppressed_classes = set(settings.get("trusted_ioc_types_for_cli", []))
    groups = [
        iocs.get("high_confidence", {}).get("urls", []),
        iocs.get("high_confidence", {}).get("domains", []),
        iocs.get("high_confidence", {}).get("commands", []),
        iocs.get("high_confidence", {}).get("file_paths", []),
    ]
    for group in groups:
        for entry in group:
            if entry.get("classification") in suppressed_classes:
                continue
            value = str(entry.get("value", "")).strip()
            if value and value not in filtered:
                filtered.append(value)
            if len(filtered) >= limit:
                return filtered
    return filtered


def _normalize_headline(label: str, context: dict[str, Any]) -> str:
    """Remove contradictory analyst wording from the selected headline."""
    normalized = label
    if "managed" in normalized.lower() and not context.get("is_dotnet"):
        normalized = normalized.replace("managed ", "").replace(" managed", "").strip()
    if "packed" in normalized.lower() and not context.get("likely_packed"):
        normalized = normalized.replace("packed ", "").replace(" packed", "").strip()
    return " ".join(normalized.split()) or "mixed static signals"


def _candidate_from_behavior(
    behavior: dict[str, Any],
    priority_order: dict[str, int],
    confidence_weights: dict[str, int],
) -> dict[str, Any]:
    """Convert a correlated behavior into a comparable decision candidate."""
    name = behavior["name"]
    confidence = str(behavior.get("confidence", "low"))
    priority_bonus = max(0, len(priority_order) - priority_order.get(name, len(priority_order)))
    return {
        "name": name,
        "summary_label": _behavior_label(name, behavior.get("summary_label")),
        "score": int(behavior.get("score", 0)),
        "confidence": confidence,
        "recommended_next_step": behavior.get("recommended_next_step", "review_manually"),
        "severity_hint": behavior.get("severity_hint", "low"),
        "evidence": behavior.get("evidence", []),
        "rationale": behavior.get("rationale", []),
        "analyst_next_steps": behavior.get("analyst_next_steps", []),
        "effective_rank": int(behavior.get("score", 0)) * 10 + confidence_weights.get(confidence, 0) + priority_bonus,
        "source": "correlated_behavior",
    }


def _candidate_from_intent(intent_inference: dict[str, Any]) -> dict[str, Any] | None:
    """Build a fallback candidate from the primary intent when needed."""
    primary_name = intent_inference.get("primary")
    if not primary_name or primary_name == "ambiguous_requires_manual_review":
        return None
    for candidate in intent_inference.get("candidates", []):
        if candidate.get("name") == primary_name:
            return {
                "name": primary_name,
                "summary_label": _behavior_label(primary_name),
                "score": int(candidate.get("score", 0)),
                "confidence": candidate.get("confidence", "low"),
                "recommended_next_step": "review_manually",
                "severity_hint": "medium",
                "evidence": candidate.get("evidence", []),
                "rationale": candidate.get("rationale", []),
                "analyst_next_steps": [],
                "effective_rank": int(candidate.get("score", 0)) * 10,
                "source": "intent_inference",
            }
    return None


def _suppression_reasons(
    candidate: dict[str, Any],
    context: dict[str, Any],
    behavior_chains: dict[str, Any],
    settings: dict[str, Any],
) -> list[str]:
    """Return candidate suppression reasons driven by contradiction and context guardrails."""
    reasons: list[str] = []
    guards = settings.get("contradiction_guards", {})
    strong_malicious_chain_present = any(
        behavior_chains.get(name, {}).get("matched")
        for name in (
            "download_write_execute_chain",
            "credential_access_chain",
            "persistence_chain",
        )
    )
    name = str(candidate["name"])
    label = str(candidate.get("summary_label", ""))
    if guards.get("managed_requires_dotnet") and (
        "managed" in name.lower() or "managed" in label.lower()
    ) and not context.get("is_dotnet"):
        reasons.append("managed_wording_without_dotnet_context")
    if guards.get("packed_wording_requires_packed_context") and (
        "packed" in name.lower() or "packed" in label.lower()
    ) and not context.get("likely_packed"):
        reasons.append("packed_wording_without_packed_context")
    if (
        context.get("installer_like")
        and not strong_malicious_chain_present
        and name in settings.get("installer_suppressed_behaviors", [])
    ):
        reasons.append("installer_context_without_strong_malicious_chain")
    return reasons


def _default_steps(next_step: str, settings: dict[str, Any]) -> list[str]:
    """Return fallback actionable steps for a normalized next-step bucket."""
    defaults = settings.get("default_actionable_next_steps", {})
    return list(defaults.get(next_step, ["Review the structured artifacts."]))


def build_final_decision(
    *,
    analysis_summary: dict[str, Any],
    correlated_behaviors: list[dict[str, Any]],
    intent_inference: dict[str, Any],
    interpretation: dict[str, Any],
    context: dict[str, Any],
    iocs: dict[str, Any],
    behavior_chains: dict[str, Any],
    analysis_settings: dict[str, Any],
) -> dict[str, Any]:
    """Normalize final analyst-facing decision output after earlier stages complete."""
    settings = analysis_settings["decision_control"]
    priority_order = {
        name: index for index, name in enumerate(settings.get("behavior_priority", []))
    }
    confidence_weights = {
        name: int(value) for name, value in settings.get("confidence_weights", {}).items()
    }
    severity_rank = {
        name: int(value) for name, value in settings.get("severity_rank", {}).items()
    }
    strong_malicious_chain_present = any(
        behavior_chains.get(name, {}).get("matched")
        for name in (
            "download_write_execute_chain",
            "credential_access_chain",
            "persistence_chain",
        )
    )

    candidates = [
        _candidate_from_behavior(behavior, priority_order, confidence_weights)
        for behavior in correlated_behaviors
        if behavior.get("matched")
    ]
    fallback_intent = _candidate_from_intent(intent_inference)
    if fallback_intent:
        candidates.append(fallback_intent)

    suppressed_candidates: list[str] = []
    suppression_reasons: list[str] = []
    viable_candidates: list[dict[str, Any]] = []
    for candidate in candidates:
        reasons = _suppression_reasons(candidate, context, behavior_chains, settings)
        if reasons:
            suppressed_candidates.append(candidate["name"])
            suppression_reasons.extend(reasons)
            continue
        viable_candidates.append(candidate)

    viable_candidates.sort(
        key=lambda item: (-item["effective_rank"], item["name"]),
    )
    winner = viable_candidates[0] if viable_candidates else None

    normalized_severity = analysis_summary["severity"]
    normalized_next_step = analysis_summary["recommended_next_step"]
    if winner:
        hinted = winner.get("severity_hint", normalized_severity)
        if severity_rank.get(hinted, -1) > severity_rank.get(normalized_severity, -1):
            normalized_severity = hinted
        if winner.get("recommended_next_step") == "investigate_deeper":
            normalized_next_step = "investigate_deeper"
        elif winner.get("recommended_next_step") == "archive" and normalized_severity == "low":
            normalized_next_step = "archive"

    if context.get("installer_like") and not strong_malicious_chain_present:
        normalized_severity = "low"
        normalized_next_step = "archive"
    elif context.get("has_high_runtime_noise") and not strong_malicious_chain_present and normalized_severity == "high":
        normalized_severity = "medium"
        normalized_next_step = "review_manually"

    if winner:
        headline_behavior = _normalize_headline(winner["summary_label"], context)
        headline_confidence = winner["confidence"]
        rationale = _dedupe(winner.get("rationale", []) + analysis_summary.get("reasons", [])[:2])[:6]
        actionable_next_steps = [
            step for step in winner.get("analyst_next_steps", []) if _is_actionable(step)
        ]
    else:
        headline_behavior = settings.get("fallback_headlines", {}).get(
            normalized_next_step,
            _behavior_label(intent_inference.get("primary", "ambiguous_requires_manual_review")),
        )
        headline_behavior = _normalize_headline(headline_behavior, context)
        headline_confidence = "low"
        rationale = analysis_summary.get("reasons", [])[:4]
        actionable_next_steps = []

    if context.get("installer_like") and not strong_malicious_chain_present:
        headline_behavior = "installer or packaged application"
    elif context.get("has_high_runtime_noise") and not strong_malicious_chain_present and not context.get("installer_like"):
        if headline_behavior in {"obfuscated loader candidate", "suspicious behavior candidate"}:
            headline_behavior = "low-signal packaged runtime"

    if not actionable_next_steps:
        actionable_next_steps = _default_steps(normalized_next_step, settings)

    actionable_next_steps = _dedupe(actionable_next_steps)
    if not all(_is_actionable(step) for step in actionable_next_steps):
        actionable_next_steps = _default_steps(normalized_next_step, settings)

    quick_assessment = interpretation.get("quick_assessment", "")
    if headline_behavior == "installer or packaged application":
        quick_assessment = (
            "Installer or packaging context dominates and stronger malicious chains are absent."
        )
    elif headline_behavior == "process injection loader":
        quick_assessment = (
            "A process-injection-style loader remains the strongest correlated behavior."
        )
    elif headline_behavior == "downloader or dropper":
        quick_assessment = (
            "Retrieval, staging, and execution evidence remains strong enough for downloader-style triage."
        )

    return {
        "selected_behavior_name": winner["name"] if winner else None,
        "headline_behavior": headline_behavior,
        "headline_confidence": headline_confidence,
        "normalized_severity": normalized_severity,
        "normalized_next_step": normalized_next_step,
        "actionable_next_steps": actionable_next_steps,
        "quick_assessment": quick_assessment,
        "notable_iocs": _build_notable_iocs(iocs, settings),
        "suppressed_candidates": sorted(set(suppressed_candidates)),
        "suppression_reasons": sorted(set(suppression_reasons)),
        "decision_rationale": rationale,
    }
