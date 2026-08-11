"""Serialization: JSON, SARIF 2.1.0, and Markdown renderers.

- JSON: machine-readable, the canonical artifact.
- SARIF: so findings light up in GitHub/GitLab code-scanning UIs natively.
- Markdown: the human-friendly PR comment body.
"""

from __future__ import annotations

import json

from defender.core.models import ComplianceReport, Severity, Verdict

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# Text badges (this project bans emoji in source).
_VERDICT_BADGE = {Verdict.PASS: "[PASS]", Verdict.WARN: "[WARN]", Verdict.FAIL: "[FAIL]"}
_SEV_BADGE = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED ]",
    Severity.LOW: "[LOW ]",
    Severity.INFO: "[INFO]",
}


def to_json(report: ComplianceReport, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def to_sarif(report: ComplianceReport) -> str:
    rules_seen: dict[str, dict] = {}
    results = []
    for f in report.all_findings():
        rules_seen.setdefault(
            f.id,
            {
                "id": f.id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "properties": {
                    "dimension": f.dimension.value,
                    "frameworks": f.frameworks,
                },
            },
        )
        result = {
            "ruleId": f.id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "properties": {"severity": f.severity.value, "source": f.source},
        }
        if f.file:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line or 1},
                    }
                }
            ]
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Defender",
                        "informationUri": "https://defender.local",
                        "version": "0.1.0",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def to_markdown(report: ComplianceReport) -> str:
    badge = _VERDICT_BADGE[report.verdict]
    lines = [
        f"## {badge} Defender Compliance Report — {report.verdict.value.upper()}",
        "",
        f"**Overall score:** {report.overall_score}/100  ",
        f"**Model backend:** `{report.model_provider}` ({report.model_name})  ",
        f"**Files analyzed:** {len(report.files_analyzed)}  ",
        "",
        f"> {report.executive_summary}",
        "",
        "### Quality layers",
        "",
        "| Layer | Score | Findings | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for d in report.dimensions:
        lines.append(
            f"| {d.dimension.value.title()} | {d.score}/100 | "
            f"{len(d.findings)} | {d.summary} |"
        )

    findings = sorted(
        report.all_findings(), key=lambda f: f.severity.rank, reverse=True
    )
    if findings:
        lines += ["", "### Findings", ""]
        for f in findings:
            se = _SEV_BADGE[f.severity]
            fw = f" · _{', '.join(f.frameworks)}_" if f.frameworks else ""
            lines.append(
                f"- {se} **[{f.severity.value.upper()}] {f.title}** "
                f"(`{f.id}`) — {f.location()}{fw}"
            )
            lines.append(f"  - {f.message}")
            if f.remediation:
                lines.append(f"  - _Fix:_ {f.remediation}")
    else:
        lines += ["", "_No findings. Clean change set._"]

    lines += ["", f"---", f"_Gate: {report.gate_reason}_"]
    return "\n".join(lines)
