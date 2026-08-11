"""Core domain models shared across the whole Defender platform.

These are the *nouns* every layer speaks: findings, severities, dimensions,
and the final compliance verdict. Keeping them in one small module means the
engine, agents, reports, CLI, and web app never disagree about vocabulary.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    """Ordered severity levels. Order matters for gate comparisons."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

# How many points a single finding of each severity subtracts from the
# per-dimension score. Critical findings are meant to sting.
SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 8.0,
    Severity.HIGH: 20.0,
    Severity.CRITICAL: 40.0,
}


class Dimension(str, enum.Enum):
    """The validation layers a diff is checked against — the 'quality layers'."""

    SECURITY = "security"
    COMPLIANCE = "compliance"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    ARCHITECTURE = "architecture"
    VULNERABILITY = "vulnerability"


class Verdict(str, enum.Enum):
    """The gate decision for a change set."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class Finding(BaseModel):
    """A single issue discovered by an analyzer agent."""

    id: str = Field(..., description="Stable rule identifier, e.g. SEC-HARDCODED-SECRET")
    dimension: Dimension
    severity: Severity
    title: str
    message: str = Field(..., description="Human-readable explanation of the issue.")
    file: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None
    remediation: Optional[str] = Field(
        None, description="Concrete guidance on how to fix it."
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks this maps to, e.g. ['PCI-DSS 6.5.3'].",
    )
    source: str = Field(
        "static", description="'static' (deterministic rule) or 'agent' (LLM-derived)."
    )
    confidence: float = Field(1.0, ge=0.0, le=1.0)

    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        return "<change set>"


class DimensionReport(BaseModel):
    """Aggregated result for a single validation dimension."""

    dimension: Dimension
    score: float = Field(100.0, ge=0.0, le=100.0)
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""
    agent_narrative: str = Field(
        "", description="Free-form LLM narrative from the analyzer agent."
    )

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out


class ComplianceReport(BaseModel):
    """The final, top-level artifact Defender produces for a change set."""

    change_id: str
    title: str = "Defender Compliance Report"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_score: float = 100.0
    verdict: Verdict = Verdict.PASS
    gate_reason: str = ""
    model_provider: str = "mock"
    model_name: str = ""
    dimensions: list[DimensionReport] = Field(default_factory=list)
    executive_summary: str = ""
    files_analyzed: list[str] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for d in self.dimensions:
            out.extend(d.findings)
        return out

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.all_findings():
            out[f.severity.value] += 1
        return out

    def highest_severity(self) -> Optional[Severity]:
        findings = self.all_findings()
        if not findings:
            return None
        return max(f.severity for f in findings)
