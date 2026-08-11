"""Base analyzer agent — the unit of shift-left agentic evaluation.

Each agent owns exactly one validation dimension and fuses two signals:
  1. Deterministic static rules (fast, reproducible, audit-defensible).
  2. LLM contextual reasoning via the BYOM provider (catches logic/architecture
     issues regex can't).

This mirrors an ADK `LlmAgent` with attached tools: the static rule engine is
effectively the agent's tool, and the model supplies judgement on top.
"""

from __future__ import annotations

from defender.core.diff import DiffFile
from defender.core.models import Dimension, DimensionReport, Finding, Severity
from defender.models.base import ModelProvider
from defender.rules import default_engine
from defender.scoring import score_dimension

_MAX_CODE_CHARS = 6000  # keep prompts bounded / cost-aware


class AnalyzerAgent:
    """Analyzes a change set for one dimension."""

    dimension: Dimension = Dimension.QUALITY
    system_prompt: str = "You are a code analyzer."

    def __init__(
        self,
        provider: ModelProvider,
        use_llm: bool = True,
        llm_max_files: int = 40,
        llm_max_batches: int = 8,
    ):
        self.provider = provider
        self.use_llm = use_llm
        self.llm_max_files = llm_max_files
        self.llm_max_batches = llm_max_batches
        self._rule_engine = default_engine().for_dimension(self.dimension)

    async def analyze(self, files: list[DiffFile]) -> DimensionReport:
        static_findings = self._rule_engine.scan(files)

        narrative = ""
        agent_findings: list[Finding] = []
        if self.use_llm:
            narrative, agent_findings = await self._run_llm(files)

        findings = static_findings + agent_findings
        score = score_dimension(findings)
        return DimensionReport(
            dimension=self.dimension,
            score=score,
            findings=findings,
            summary=self._summarize(findings),
            agent_narrative=narrative,
        )

    async def _run_llm(self, files: list[DiffFile]) -> tuple[str, list[Finding]]:
        batches = self._collect_batches(files)
        if not batches:
            return "", []
        # Prefix a machine-readable tag so deterministic providers (mock) know
        # the dimension without sniffing prose. Real LLMs simply ignore it.
        system = f"[DEFENDER_DIMENSION={self.dimension.value}]\n{self.system_prompt}"
        narratives: list[str] = []
        findings: list[Finding] = []
        for code in batches:
            user_prompt = self._build_prompt(code)
            try:
                raw = await self.provider.complete(system, user_prompt)
            except Exception as exc:  # provider hiccup -> degrade gracefully
                narratives.append(f"[llm unavailable: {type(exc).__name__}]")
                continue
            data = ModelProvider.extract_json(raw)
            n = str(data.get("narrative", "")).strip()
            if n:
                narratives.append(n)
            findings.extend(self._parse_findings(data.get("findings", [])))
        return " ".join(narratives), findings

    def _collect_batches(self, files: list[DiffFile]) -> list[str]:
        """Group files into char-bounded batches for multiple LLM calls.

        Static analysis already covers *every* file; the LLM covers up to
        ``llm_max_files`` across up to ``llm_max_batches`` calls so large repos
        degrade predictably instead of silently truncating to the first ~6KB.
        """
        from defender.agents.batching import collect_batches

        return collect_batches(
            files,
            max_files=self.llm_max_files,
            max_batches=self.llm_max_batches,
            max_chars=_MAX_CODE_CHARS,
        )

    def _build_prompt(self, code: str) -> str:
        return (
            f"Review the following added code for {self.dimension.value} issues in a "
            "regulated banking context. Respond ONLY with a JSON object of the form "
            '{"narrative": "<2-3 sentence assessment>", "findings": [{"id": "AI-'
            f'{self.dimension.value.upper()}-<slug>", "severity": '
            '"low|medium|high|critical", "title": "...", "message": "...", '
            '"remediation": "...", "file": "<path>", "line": <int or null>}]}. '
            "Only report genuine issues; return an empty findings list if clean.\n\n"
            f"CODE:\n{code}"
        )

    def _parse_findings(self, raw_findings: object) -> list[Finding]:
        return parse_agent_findings(self.dimension, raw_findings)

    def _summarize(self, findings: list[Finding]) -> str:
        if not findings:
            return f"No {self.dimension.value} issues detected."
        crit = sum(1 for f in findings if f.severity >= Severity.HIGH)
        return (
            f"{len(findings)} {self.dimension.value} finding(s), "
            f"{crit} high/critical."
        )


def parse_agent_findings(dimension: Dimension, raw_findings: object) -> list[Finding]:
    """Turn an LLM's raw findings list into typed Finding objects.

    Shared by the native per-agent path and the genuine ADK pipeline so both
    interpret model output identically. Defensive: bad shapes are skipped.
    """
    out: list[Finding] = []
    if not isinstance(raw_findings, list):
        return out
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        try:
            sev = Severity(str(item.get("severity", "low")).lower())
        except ValueError:
            sev = Severity.LOW
        out.append(
            Finding(
                id=str(item.get("id") or f"AI-{dimension.value.upper()}"),
                dimension=dimension,
                severity=sev,
                title=str(item.get("title", "Agent-identified issue")),
                message=str(item.get("message", "")),
                file=item.get("file"),
                line=item.get("line") if isinstance(item.get("line"), int) else None,
                remediation=item.get("remediation"),
                source="agent",
                confidence=float(item.get("confidence", 0.7) or 0.7),
            )
        )
    return out
