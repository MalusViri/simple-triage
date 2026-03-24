"""Data models for staticprep analysis results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class AnalysisError:
    """Structured error or warning information captured during analysis."""

    stage: str
    message: str
    severity: str = "error"


@dataclass(slots=True)
class CapabilityEvidence:
    """Evidence supporting a capability match."""

    value: str
    evidence_source: str


@dataclass(slots=True)
class CapabilityResult:
    """Capability result for a single capability name."""

    matched: bool
    evidence: list[str] = field(default_factory=list)
    evidence_source: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    confidence: str = "low"


@dataclass(slots=True)
class AnalysisReport:
    """Canonical report structure exported as JSON."""

    sample: dict[str, Any]
    environment: dict[str, Any]
    analysis_summary: dict[str, Any]
    packed_assessment: dict[str, Any]
    iocs: dict[str, Any]
    interesting_strings_preview: list[str]
    hashes: dict[str, str]
    strings: dict[str, Any]
    pe: dict[str, Any]
    imports: dict[str, Any]
    capabilities: dict[str, CapabilityResult]
    yara: dict[str, Any]
    errors: list[AnalysisError]
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation with stable structure."""
        payload = asdict(self)
        payload["capabilities"] = {
            name: asdict(result) for name, result in self.capabilities.items()
        }
        payload["errors"] = [asdict(error) for error in self.errors]
        return payload
