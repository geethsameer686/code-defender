"""Rule catalog aggregation + package exports."""

from __future__ import annotations

from defender.rules.base import RuleEngine, StaticRule
from defender.rules.compliance import COMPLIANCE_RULES
from defender.rules.engineering import ENGINEERING_RULES
from defender.rules.security import SECURITY_RULES

ALL_RULES: list[StaticRule] = [
    *SECURITY_RULES,
    *COMPLIANCE_RULES,
    *ENGINEERING_RULES,
]


def default_engine() -> RuleEngine:
    return RuleEngine(ALL_RULES)


__all__ = ["ALL_RULES", "RuleEngine", "StaticRule", "default_engine"]
