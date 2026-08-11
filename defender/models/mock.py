"""Deterministic, offline mock provider.

This is what lets Defender run on a laptop with ZERO API keys and still produce
a believable, *reproducible* agentic narrative. It does light keyword heuristics
so demos surface a couple of LLM-flavored findings on obviously-bad code, but it
never calls the network. Perfect for CI smoke tests and air-gapped evals.
"""

from __future__ import annotations

import hashlib
import json

from defender.models.base import ModelProvider

# Keyword -> (dimension, severity, title) heuristics the mock "reasons" about.
_HEURISTICS = [
    ("eval(", "security", "high", "Dynamic code execution via eval()"),
    ("pickle.load", "security", "high", "Insecure deserialization with pickle"),
    ("verify=false", "security", "high", "TLS verification disabled"),
    ("todo", "quality", "low", "Unresolved TODO left in change set"),
    ("except:", "quality", "medium", "Bare except swallows errors"),
    ("select *", "performance", "medium", "SELECT * pulls unneeded columns"),
    ("time.sleep", "performance", "low", "Blocking sleep in request path"),
    ("card_number", "compliance", "high", "Possible PAN handling — PCI-DSS scope"),
    ("global ", "architecture", "medium", "Global mutable state hurts testability"),
]


class MockProvider(ModelProvider):
    provider_name = "mock"

    async def complete(self, system: str, user: str) -> str:
        low = user.lower()
        dimension = _dimension_from_system(system)
        findings = []
        for needle, dim, sev, title in _HEURISTICS:
            if dim == dimension and needle in low:
                findings.append(
                    {
                        "id": f"AI-{dim.upper()}-{_stable_suffix(needle)}",
                        "dimension": dim,
                        "severity": sev,
                        "title": title,
                        "message": (
                            f"The {dimension} analyzer (offline mock) flagged a "
                            f"pattern resembling '{needle.strip()}'. Review whether "
                            "this is appropriate for a regulated banking workload."
                        ),
                        "remediation": "Refactor to the secure/compliant equivalent.",
                        "source": "agent",
                        "confidence": 0.6,
                    }
                )
        narrative = (
            f"[offline mock · {dimension}] Reviewed the change set heuristically. "
            + (
                f"Surfaced {len(findings)} contextual concern(s) worth a human look."
                if findings
                else "No additional contextual concerns beyond static analysis."
            )
        )
        return json.dumps({"narrative": narrative, "findings": findings})


def _dimension_from_system(system: str) -> str:
    # Prefer the explicit tag the analyzer agents inject.
    marker = "[defender_dimension="
    s = system.lower()
    idx = s.find(marker)
    if idx != -1:
        return s[idx + len(marker):].split("]", 1)[0].strip()
    for dim in (
        "security",
        "compliance",
        "quality",
        "performance",
        "architecture",
        "vulnerability",
    ):
        if dim in s:
            return dim
    return "quality"


def _stable_suffix(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:6].upper()
