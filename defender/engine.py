"""Defender orchestrator — the multi-agent conductor.

Runs every specialist analyzer concurrently (ADK ParallelAgent semantics),
fuses their per-dimension reports into a single ComplianceReport, computes the
weighted overall score, and applies the governance gate. This is the top-level
API the CLI, web app, and webhook receiver all call.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Callable, Optional

from defender.agents.specialists import ALL_AGENT_CLASSES
from defender.core.config import Settings, get_settings
from defender.core.diff import DiffFile, file_to_difffile, parse_diff
from defender.core.models import (
    ComplianceReport,
    Dimension,
    DimensionReport,
    Severity,
)
from defender.models import get_provider
from defender.scoring import decide_verdict, overall_score, score_dimension

ProgressFn = Optional[Callable[[str], None]]


class Defender:
    """Orchestrates the full validation pipeline for a change set."""

    def __init__(
        self,
        settings: Settings | None = None,
        use_llm: bool = True,
        llm_max_files: int = 40,
        on_progress: ProgressFn = None,
    ):
        self.settings = settings or get_settings()
        self.use_llm = use_llm
        self.llm_max_files = llm_max_files
        self.on_progress = on_progress
        self.provider_name = self.settings.effective_model_provider

        # Genuine Google ADK path: agents run under an ADK ParallelAgent/Runner.
        self.use_adk = False
        if self.provider_name == "adk" and use_llm:
            from defender.adk import adk_available

            self.use_adk = adk_available()

        if self.use_adk:
            self.provider = None
            self.model_name = self.settings.defender_model_name
            self.agents = []  # static rules handled directly in ADK mode
        else:
            self.provider = get_provider(self.settings)
            self.model_name = self.provider.model
            self.agents = [
                cls(self.provider, use_llm=use_llm, llm_max_files=llm_max_files)
                for cls in ALL_AGENT_CLASSES
            ]

    def _progress(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(message)

    async def analyze(
        self, files: list[DiffFile], change_id: str = "", title: str = ""
    ) -> ComplianceReport:
        """Run every analyzer in parallel and assemble the verdict."""
        change_id = change_id or _fingerprint(files)
        names = [f.path for f in files if not f.is_deleted]
        self._progress(
            f"Running static rule engine across {len(names)} file(s)..."
        )

        if self.use_adk:
            dims = ", ".join(d.value for d in Dimension)
            self._progress(
                f"Dispatching to 6 Google ADK agents ({dims}) via "
                f"'{self.model_name}'..."
            )
            dimension_reports = await self._analyze_adk(files)
            provider_label, model_label = "adk", self.model_name
        else:
            self._progress(
                f"Running {len(self.agents)} specialist agents via "
                f"'{self.provider.name}' backend..."
            )
            dimension_reports = await asyncio.gather(
                *(agent.analyze(files) for agent in self.agents)
            )
            provider_label, model_label = self.provider.name, self.provider.model

        self._progress("Scoring dimensions and computing the compliance verdict...")
        report = ComplianceReport(
            change_id=change_id,
            title=title or "Defender Compliance Report",
            model_provider=provider_label,
            model_name=model_label,
            dimensions=list(dimension_reports),
            files_analyzed=names,
        )
        report.overall_score = overall_score(report)
        report.verdict, report.gate_reason = decide_verdict(report, self.settings)
        report.stats = _build_stats(report)
        report.executive_summary = _executive_summary(report)
        self._progress("Done.")
        return report

    async def _analyze_adk(self, files: list[DiffFile]) -> list[DimensionReport]:
        """LLM analysis via the genuine ADK ParallelAgent; static rules alongside."""
        from defender.adk import run_adk_analysis
        from defender.agents.base import parse_agent_findings
        from defender.agents.batching import collect_batches
        from defender.models.base import ModelProvider
        from defender.rules import default_engine

        engine = default_engine()
        # Static findings per dimension (deterministic, covers every file).
        static: dict[Dimension, list] = {d: [] for d in Dimension}
        for f in engine.scan(files):
            static[f.dimension].append(f)

        # ADK LLM findings per dimension, across batches.
        agent_findings: dict[Dimension, list] = {d: [] for d in Dimension}
        narratives: dict[Dimension, list[str]] = {d: [] for d in Dimension}
        batches = collect_batches(files, max_files=self.llm_max_files)
        for i, code in enumerate(batches, start=1):
            batch_files = re.findall(r"### FILE: (.+)", code)
            preview = ", ".join(batch_files[:3])
            if len(batch_files) > 3:
                preview += f" (+{len(batch_files) - 3} more)"
            self._progress(
                f"ADK batch {i}/{len(batches)}: analyzing {preview or 'code'}..."
            )
            outputs = await run_adk_analysis(
                code, self.model_name, self.settings.llm_gateway_user_name
            )
            for dim, raw in outputs.items():
                data = ModelProvider.extract_json(raw)
                if data.get("narrative"):
                    narratives[dim].append(str(data["narrative"]).strip())
                agent_findings[dim].extend(
                    parse_agent_findings(dim, data.get("findings", []))
                )

        reports: list[DimensionReport] = []
        for dim in Dimension:
            findings = static[dim] + agent_findings[dim]
            crit = sum(1 for f in findings if f.severity >= Severity.HIGH)
            summary = (
                f"No {dim.value} issues detected."
                if not findings
                else f"{len(findings)} {dim.value} finding(s), {crit} high/critical."
            )
            reports.append(
                DimensionReport(
                    dimension=dim,
                    score=score_dimension(findings),
                    findings=findings,
                    summary=summary,
                    agent_narrative=" ".join(narratives[dim]),
                )
            )
        return reports

    async def analyze_diff(
        self, diff_text: str, change_id: str = "", title: str = ""
    ) -> ComplianceReport:
        return await self.analyze(parse_diff(diff_text), change_id, title)

    async def analyze_paths(
        self, paths: list[str], title: str = "", use_gitignore: bool = True
    ) -> ComplianceReport:
        """Analyze a mix of files and directories (directories are expanded)."""
        from defender.core.repo import expand_paths

        self._progress("Scanning repository tree (respecting .gitignore)...")
        scan = expand_paths(paths, use_gitignore=use_gitignore)
        self._progress(f"Found {len(scan.files)} analyzable source file(s).")
        files = [file_to_difffile(p, _read(p)) for p in scan.files]
        report = await self.analyze(files, title=title or "Defender scan")
        report.stats["skipped_large"] = scan.skipped_large
        report.stats["skipped_binary"] = scan.skipped_binary
        if scan.truncated_at_max:
            report.executive_summary = (
                "[NOTE] File-count cap reached; some files were not scanned. "
                + report.executive_summary
            )
        if not scan.files:
            # A 0-file scan with a PASS verdict is a silent false-green — the
            # single most dangerous failure mode for a compliance gate. Make
            # it loud in every output format, not just something a human
            # notices in a CLI table.
            report.executive_summary = (
                "[WARNING] No files were analyzed. This usually means the path "
                "does not exist, is empty, or every file was filtered out "
                "(binary/oversized/excluded). A PASS here does NOT mean the "
                "target is compliant — it means nothing was checked. "
                + report.executive_summary
            )
        return report

    async def analyze_git_url(
        self,
        url: str,
        clone_timeout: int = 45,
        branch: str | None = None,
        auth_token: str | None = None,
    ) -> ComplianceReport:
        """Shallow-clone a remote repo, audit it, and always clean up the checkout."""
        import os

        from defender.core.clone import cloned_repo

        self._progress(f"Connecting to {url}...")
        with cloned_repo(
            url, timeout=clone_timeout, branch=branch, auth_token=auth_token
        ) as tmpdir:
            self._progress("Repository cloned. Walking the tree...")
            # Strip the ugly absolute temp-checkout prefix from any progress
            # messages emitted while we're inside the clone (e.g. "analyzing
            # <tmpdir>/src/foo.py" -> "analyzing src/foo.py"), mirroring the
            # same relativization already applied to findings/files below.
            original_progress = self.on_progress
            if original_progress:
                prefix = tmpdir + os.sep
                self.on_progress = lambda msg: original_progress(
                    msg.replace(prefix, "")
                )
            try:
                report = await self.analyze_paths(
                    [tmpdir], title=f"Defender audit: {url}"
                )
            finally:
                self.on_progress = original_progress
            # Report paths relative to the repo root, not the temp checkout
            # (which is deleted the moment this context manager exits).
            report.files_analyzed = [
                os.path.relpath(p, tmpdir) for p in report.files_analyzed
            ]
            for f in report.all_findings():
                if f.file and f.file.startswith(tmpdir):
                    f.file = os.path.relpath(f.file, tmpdir)
        report.title = f"Defender audit: {url}"
        return report


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _fingerprint(files: list[DiffFile]) -> str:
    h = hashlib.sha256()
    for f in files:
        h.update(f.path.encode())
        h.update(f.added_text().encode())
    return h.hexdigest()[:12]


def _build_stats(report: ComplianceReport) -> dict[str, int]:
    counts = report.counts_by_severity()
    counts["total"] = sum(counts[s.value] for s in Severity)
    counts["files"] = len(report.files_analyzed)
    return counts


def _executive_summary(report: ComplianceReport) -> str:
    counts = report.counts_by_severity()
    worst = report.highest_severity()
    worst_txt = worst.value if worst else "none"
    lines = [
        f"Defender validated {len(report.files_analyzed)} file(s) across "
        f"{len(report.dimensions)} quality layers using the "
        f"'{report.model_provider}' model backend.",
        f"Overall compliance score: {report.overall_score}/100 — "
        f"verdict: {report.verdict.value.upper()}.",
        f"Findings — critical: {counts['critical']}, high: {counts['high']}, "
        f"medium: {counts['medium']}, low: {counts['low']}. "
        f"Highest severity: {worst_txt}.",
        report.gate_reason,
    ]
    return " ".join(lines)
