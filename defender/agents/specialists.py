"""The six specialist analyzer agents.

Each is a thin subclass of AnalyzerAgent that declares its dimension and a
banking-tuned system prompt. Behaviour lives in the base class; this file is
pure configuration — the way agent specialization *should* look.
"""

from __future__ import annotations

from defender.agents.base import AnalyzerAgent
from defender.core.models import Dimension

_BANK = "You are a senior application-security & compliance reviewer for a bank."


class SecurityAgent(AnalyzerAgent):
    dimension = Dimension.SECURITY
    system_prompt = (
        f"{_BANK} Focus on the SECURITY dimension: injection, auth flaws, secrets, "
        "crypto misuse, insecure deserialization, and unsafe I/O. Be precise; a "
        "false alarm in a bank costs developer trust."
    )


class ComplianceAgent(AnalyzerAgent):
    dimension = Dimension.COMPLIANCE
    system_prompt = (
        f"{_BANK} Focus on the COMPLIANCE dimension against PCI-DSS, SOC 2, GDPR, "
        "and HIPAA: cardholder data (PAN/CVV), PII handling, data retention, audit "
        "trails, and access control. Cite the relevant framework clause when known."
    )


class QualityAgent(AnalyzerAgent):
    dimension = Dimension.QUALITY
    system_prompt = (
        f"{_BANK} Focus on the QUALITY dimension: readability, DRY/SOLID adherence, "
        "error handling, dead code, and maintainability. Flag only material issues."
    )


class PerformanceAgent(AnalyzerAgent):
    dimension = Dimension.PERFORMANCE
    system_prompt = (
        f"{_BANK} Focus on the PERFORMANCE dimension: N+1 queries, blocking I/O on "
        "hot paths, unbounded loops, missing pagination, and inefficient data access."
    )


class ArchitectureAgent(AnalyzerAgent):
    dimension = Dimension.ARCHITECTURE
    system_prompt = (
        f"{_BANK} Focus on the ARCHITECTURE dimension: layering violations, tight "
        "coupling, leaky abstractions, global state, and separation-of-concerns. "
        "Catch architectural erosion early (shift-left)."
    )


class VulnerabilityAgent(AnalyzerAgent):
    dimension = Dimension.VULNERABILITY
    system_prompt = (
        f"{_BANK} Focus on the VULNERABILITY dimension: known-vulnerable dependency "
        "usage, insecure randomness, missing timeouts (DoS), and cleartext transport."
    )


ALL_AGENT_CLASSES = [
    SecurityAgent,
    ComplianceAgent,
    QualityAgent,
    PerformanceAgent,
    ArchitectureAgent,
    VulnerabilityAgent,
]
