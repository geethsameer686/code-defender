"""Static rule engine — the deterministic backbone of Defender.

LLM agents add contextual judgement, but regulated banks need *reproducible*,
explainable checks that fire the same way every time. These regex-based rules
run on the added lines of a change set and are cheap, fast, and auditable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from defender.core.diff import DiffFile
from defender.core.models import Dimension, Finding, Severity


@dataclass
class StaticRule:
    id: str
    dimension: Dimension
    severity: Severity
    title: str
    message: str
    pattern: str
    remediation: str = ""
    frameworks: list[str] = field(default_factory=list)
    file_suffixes: tuple[str, ...] = ()  # empty => all files
    flags: int = re.IGNORECASE

    def compiled(self) -> re.Pattern:
        return re.compile(self.pattern, self.flags)

    def applies_to(self, path: str) -> bool:
        if not self.file_suffixes:
            return True
        return any(path.endswith(sfx) for sfx in self.file_suffixes)


class RuleEngine:
    """Runs a set of StaticRules against parsed diff files."""

    def __init__(self, rules: list[StaticRule]):
        self.rules = rules
        self._compiled = [(r, r.compiled()) for r in rules]

    def scan(self, files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for df in files:
            if df.is_deleted:
                continue
            for line in df.added_lines:
                text = line.content
                for rule, pattern in self._compiled:
                    if not rule.applies_to(df.path):
                        continue
                    if pattern.search(text):
                        findings.append(
                            Finding(
                                id=rule.id,
                                dimension=rule.dimension,
                                severity=rule.severity,
                                title=rule.title,
                                message=rule.message,
                                file=df.path,
                                line=line.new_lineno,
                                snippet=text.strip()[:240],
                                remediation=rule.remediation,
                                frameworks=list(rule.frameworks),
                                source="static",
                                confidence=1.0,
                            )
                        )
        return findings

    def for_dimension(self, dimension: Dimension) -> "RuleEngine":
        return RuleEngine([r for r in self.rules if r.dimension == dimension])
