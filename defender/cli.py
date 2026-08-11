"""Defender command-line interface.

The CLI is a first-class integration surface: run it in any CI/CD pipeline, any
git hook, or locally. Exit code is non-zero when the gate FAILs, so it drops
straight into a pipeline `&&` chain or a required status check.

Examples:
    defender scan app/*.py
    git diff origin/main | defender review --stdin
    defender review --git origin/main --format sarif -o defender.sarif
    defender serve
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from defender.core.models import ComplianceReport, Verdict
from defender.engine import Defender
from defender.reporting import to_html, to_json, to_markdown, to_sarif

app = typer.Typer(
    add_completion=False,
    help="Defender — AI Code Compliance Defender for regulated banking systems.",
)
console = Console()

_FORMATTERS = {
    "json": to_json,
    "md": to_markdown,
    "markdown": to_markdown,
    "sarif": to_sarif,
    "html": to_html,
}


def _run(report_coro) -> ComplianceReport:
    # Provider backends (e.g. the Walmart gateway via gemini_llm.py) print
    # diagnostic [INFO] lines to stdout. Suppress stdout for the duration of
    # the analysis so the CLI emits only the report. Errors still surface via
    # stderr. Done in the main thread only: worker threads share sys.stdout,
    # so a per-call redirect there would corrupt restoration.
    with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
        return asyncio.run(report_coro)


def _emit(report: ComplianceReport, fmt: str, output: str | None) -> None:
    if fmt == "table":
        _render_table(report)
    else:
        formatter = _FORMATTERS.get(fmt)
        if formatter is None:
            console.print(f"[red]Unknown format '{fmt}'.[/red]")
            raise typer.Exit(2)
        rendered = formatter(report)
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
            console.print(f"[green]Report written to {output}[/green]")
        else:
            # Write raw to stdout. NEVER use rich here: it word-wraps to the
            # terminal width and corrupts JSON/SARIF when piped in CI.
            sys.stdout.write(rendered + "\n")


def _exit_for(report: ComplianceReport, strict: bool) -> None:
    if report.verdict == Verdict.FAIL:
        raise typer.Exit(1)
    if report.verdict == Verdict.WARN and strict:
        raise typer.Exit(1)
    raise typer.Exit(0)


def _require_paths_exist(paths: list[str]) -> None:
    """Fail fast (exit 2) instead of silently 'scanning' zero files.

    A missing path producing a 0-file PASS is the worst kind of bug for a
    compliance gate: it looks green while checking nothing.
    """
    import os

    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        console.print(f"[red]Path(s) not found:[/red] {', '.join(missing)}")
        raise typer.Exit(2)


@app.command()
def scan(
    paths: list[str] = typer.Argument(..., help="Files or directories to scan."),
    format: str = typer.Option("table", "--format", "-f", help="table|json|md|sarif|html"),
    output: str = typer.Option(None, "--output", "-o", help="Write report to file."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Static rules only."),
    llm_max_files: int = typer.Option(
        40, "--llm-max-files", help="Max files sent to the LLM (static covers all)."
    ),
    no_gitignore: bool = typer.Option(
        False, "--no-gitignore", help="Do not respect .gitignore when walking dirs."
    ),
    strict: bool = typer.Option(False, "--strict", help="Non-zero exit on WARN too."),
) -> None:
    """Scan files or directories (directories are expanded, .gitignore respected)."""
    _require_paths_exist(paths)
    defender = Defender(use_llm=not no_llm, llm_max_files=llm_max_files)
    report = _run(
        defender.analyze_paths(
            paths, title="Defender scan", use_gitignore=not no_gitignore
        )
    )
    _emit(report, format, output)
    _exit_for(report, strict)


@app.command()
def audit(
    path: str = typer.Argument(".", help="Repo root, or a git URL to clone-and-scan."),
    format: str = typer.Option("table", "--format", "-f"),
    output: str = typer.Option(None, "--output", "-o"),
    no_llm: bool = typer.Option(False, "--no-llm"),
    llm_max_files: int = typer.Option(40, "--llm-max-files"),
    clone_timeout: int = typer.Option(45, "--clone-timeout", help="Seconds allowed for the git clone."),
    strict: bool = typer.Option(False, "--strict"),
) -> None:
    """Full-repository compliance audit. Accepts a local path OR a git URL
    (shallow-clones to a temp dir, scans, and always cleans up)."""
    from defender.core.clone import CloneError, looks_like_git_url

    defender = Defender(use_llm=not no_llm, llm_max_files=llm_max_files)
    if looks_like_git_url(path):
        try:
            report = _run(defender.analyze_git_url(path, clone_timeout=clone_timeout))
        except CloneError as exc:
            console.print(f"[red]Clone failed:[/red] {exc}")
            raise typer.Exit(2)
    else:
        _require_paths_exist([path])
        report = _run(defender.analyze_paths([path], title=f"Defender repo audit: {path}"))
    _emit(report, format, output)
    _exit_for(report, strict)


@app.command()
def review(
    diff_file: str = typer.Option(None, "--diff", help="Path to a unified diff file."),
    stdin: bool = typer.Option(False, "--stdin", help="Read diff from stdin."),
    git: str = typer.Option(None, "--git", help="git diff against this ref/range."),
    format: str = typer.Option("table", "--format", "-f"),
    output: str = typer.Option(None, "--output", "-o"),
    no_llm: bool = typer.Option(False, "--no-llm"),
    strict: bool = typer.Option(False, "--strict"),
) -> None:
    """Review a pull-request-style unified diff."""
    diff_text = _resolve_diff(diff_file, stdin, git)
    if not diff_text.strip():
        console.print("[yellow]Empty diff — nothing to review.[/yellow]")
        raise typer.Exit(0)
    defender = Defender(use_llm=not no_llm)
    report = _run(defender.analyze_diff(diff_text, title="Defender PR review"))
    _emit(report, format, output)
    _exit_for(report, strict)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8100, "--port"),
) -> None:
    """Launch the Defender web dashboard + webhook receiver."""
    import uvicorn

    console.print(
        Panel.fit(
            f"Defender dashboard: http://{host}:{port}\n"
            f"Webhooks: /webhook/github  ·  /webhook/gitlab",
            title="Defender",
        )
    )
    uvicorn.run("defender.web.app:app", host=host, port=port, reload=False)


def _resolve_diff(diff_file: str | None, stdin: bool, git: str | None) -> str:
    if stdin:
        return sys.stdin.read()
    if diff_file:
        return Path(diff_file).read_text(encoding="utf-8")
    if git:
        args = git.split()
        return subprocess.run(
            ["git", "diff", *args], capture_output=True, text=True, check=False
        ).stdout
    # Default: staged changes.
    return subprocess.run(
        ["git", "diff", "--cached"], capture_output=True, text=True, check=False
    ).stdout


def _render_table(report: ComplianceReport) -> None:
    color = {"pass": "green", "warn": "yellow", "fail": "red"}[report.verdict.value]
    console.print(
        Panel(
            f"[bold {color}]{report.verdict.value.upper()}[/bold {color}]  "
            f"score [bold]{report.overall_score}/100[/bold]  "
            f"backend [cyan]{report.model_provider}[/cyan]",
            title="Defender verdict",
        )
    )

    dim_table = Table(title="Quality layers", show_lines=False)
    dim_table.add_column("Layer")
    dim_table.add_column("Score", justify="right")
    dim_table.add_column("Findings", justify="right")
    dim_table.add_column("Summary")
    for d in report.dimensions:
        dim_table.add_row(
            d.dimension.value.title(), str(d.score), str(len(d.findings)), d.summary
        )
    console.print(dim_table)

    findings = sorted(
        report.all_findings(), key=lambda f: f.severity.rank, reverse=True
    )
    if findings:
        f_table = Table(title="Findings")
        f_table.add_column("Sev")
        f_table.add_column("Rule")
        f_table.add_column("Location")
        f_table.add_column("Title")
        sev_color = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }
        for f in findings:
            f_table.add_row(
                f"[{sev_color[f.severity.value]}]{f.severity.value.upper()}[/]",
                f.id,
                f.location(),
                f.title,
            )
        console.print(f_table)
    console.print(f"[dim]{report.gate_reason}[/dim]")


if __name__ == "__main__":
    app()
