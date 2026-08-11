"""Scoring & gate policy.

Turns findings into a 0-100 score per dimension, an overall weighted score, and
a final PASS/WARN/FAIL verdict against the configured gate policy. This is the
governance brain: it decides whether a change is allowed toward production.
"""

from __future__ import annotations

from defender.core.config import Settings, get_settings
from defender.core.models import (
    ComplianceReport,
    Dimension,
    Finding,
    Severity,
    SEVERITY_PENALTY,
    Verdict,
)

# Security & compliance carry more weight for banking gate decisions.
DIMENSION_WEIGHTS: dict[Dimension, float] = {
    Dimension.SECURITY: 1.5,
    Dimension.COMPLIANCE: 1.5,
    Dimension.VULNERABILITY: 1.2,
    Dimension.ARCHITECTURE: 1.0,
    Dimension.PERFORMANCE: 0.8,
    Dimension.QUALITY: 0.7,
}


def score_dimension(findings: list[Finding]) -> float:
    """Start at 100 and subtract severity penalties; floor at 0."""
    penalty = sum(SEVERITY_PENALTY[f.severity] for f in findings)
    return round(max(0.0, 100.0 - penalty), 1)


def overall_score(report: ComplianceReport) -> float:
    if not report.dimensions:
        return 100.0
    total_w = 0.0
    acc = 0.0
    for d in report.dimensions:
        w = DIMENSION_WEIGHTS.get(d.dimension, 1.0)
        acc += d.score * w
        total_w += w
    return round(acc / total_w, 1) if total_w else 100.0


def decide_verdict(
    report: ComplianceReport, settings: Settings | None = None
) -> tuple[Verdict, str]:
    """Apply gate policy: block on severity threshold OR low overall score."""
    settings = settings or get_settings()
    highest = report.highest_severity()
    block_at = settings.block_severity

    if highest is not None and highest >= block_at:
        n = sum(1 for f in report.all_findings() if f.severity >= block_at)
        return (
            Verdict.FAIL,
            f"Blocked: {n} finding(s) at/above '{block_at.value}' severity "
            f"(policy blocks >= {block_at.value}).",
        )

    if report.overall_score < settings.defender_gate_min_score:
        return (
            Verdict.FAIL,
            f"Blocked: overall score {report.overall_score} is below the required "
            f"minimum of {settings.defender_gate_min_score}.",
        )

    # Warn if there are any medium+ findings but nothing blocking.
    if any(f.severity >= Severity.MEDIUM for f in report.all_findings()):
        return (
            Verdict.WARN,
            "Passed with warnings: medium-severity findings present. Review advised.",
        )

    return Verdict.PASS, "All quality layers passed the configured gate policy."
