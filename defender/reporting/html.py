"""Standalone HTML report renderer.

Produces a single self-contained HTML file (Tailwind via CDN, dark brand theme
matching the Defender product site) that a bank's release manager can open,
print to PDF, or attach to an audit ticket. No build step, no server required.
"""

from __future__ import annotations

import html

from defender.core.models import ComplianceReport, Severity, Verdict

_VERDICT_CLASS = {
    Verdict.PASS: ("bg-emerald-500/15 text-emerald-300 border-emerald-500/30", "PASS"),
    Verdict.WARN: ("bg-amber-500/15 text-amber-300 border-amber-500/30", "WARN"),
    Verdict.FAIL: ("bg-red-500/15 text-red-300 border-red-500/30", "FAIL"),
}
_SEV_CLASS = {
    Severity.CRITICAL: "bg-red-500/20 text-red-300 border-red-500/30",
    Severity.HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/30",
    Severity.MEDIUM: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    Severity.LOW: "bg-sky-500/20 text-sky-300 border-sky-500/30",
    Severity.INFO: "bg-slate-500/20 text-slate-300 border-slate-500/30",
}


def _esc(text: object) -> str:
    return html.escape(str(text or ""))


def to_html(report: ComplianceReport) -> str:
    v_class, v_label = _VERDICT_CLASS[report.verdict]
    counts = report.counts_by_severity()

    dim_rows = "".join(
        f"""<tr class="border-b border-white/5">
          <td class="py-2 px-3 font-medium">{_esc(d.dimension.value.title())}</td>
          <td class="py-2 px-3">{_score_bar(d.score)}</td>
          <td class="py-2 px-3 text-center">{len(d.findings)}</td>
          <td class="py-2 px-3 text-slate-400 text-sm">{_esc(d.summary)}</td>
        </tr>"""
        for d in report.dimensions
    )

    findings = sorted(
        report.all_findings(), key=lambda f: f.severity.rank, reverse=True
    )
    finding_cards = "".join(_finding_card(f) for f in findings) or (
        '<p class="text-slate-500">No findings. Clean change set.</p>'
    )

    files = "".join(
        f'<li class="text-sm text-slate-400">{_esc(p)}</li>'
        for p in report.files_analyzed
    ) or '<li class="text-sm text-slate-600">none</li>'

    stats_html = "".join(
        [
            _stat("Score", f"{report.overall_score}/100"),
            _stat("Critical", counts["critical"]),
            _stat("High", counts["high"]),
            _stat("Medium", counts["medium"]),
            _stat("Low", counts["low"]),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Defender Report — {_esc(report.change_id)}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body {{ background:#05060a; color:#e5e7eb; font-family:'Inter',ui-sans-serif,system-ui; }}
  .glass {{ background:rgba(255,255,255,0.035); border:1px solid rgba(255,255,255,0.08); }}
  code, .mono {{ font-family:'JetBrains Mono',ui-monospace,monospace; }}
  .grad-text {{ background:linear-gradient(90deg,#818cf8,#22d3ee 60%); -webkit-background-clip:text; background-clip:text; color:transparent; }}
</style>
</head>
<body class="antialiased">
<div class="max-w-5xl mx-auto p-6">
  <header class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-bold">Defender <span class="grad-text">Compliance Report</span></h1>
      <p class="text-slate-400 text-sm mt-1">Change <code>{_esc(report.change_id)}</code>
        &middot; backend <code>{_esc(report.model_provider)}</code>
        ({_esc(report.model_name)})</p>
    </div>
    <span class="px-4 py-2 rounded-lg border text-lg font-bold {v_class}">
      {v_label}</span>
  </header>

  <section class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
    {stats_html}
  </section>

  <section class="glass rounded-xl p-4 mb-6">
    <h2 class="font-semibold mb-2">Executive summary</h2>
    <p class="text-slate-400 text-sm leading-relaxed">
      {_esc(report.executive_summary)}</p>
    <p class="mt-3 text-sm font-medium text-slate-300">Gate decision: {_esc(report.gate_reason)}</p>
  </section>

  <section class="glass rounded-xl p-4 mb-6">
    <h2 class="font-semibold mb-3">Quality layers</h2>
    <table class="w-full text-left">
      <thead><tr class="text-slate-500 text-sm border-b border-white/10">
        <th class="py-2 px-3">Layer</th><th class="py-2 px-3">Score</th>
        <th class="py-2 px-3 text-center">Findings</th>
        <th class="py-2 px-3">Summary</th></tr></thead>
      <tbody>{dim_rows}</tbody>
    </table>
  </section>

  <section class="glass rounded-xl p-4 mb-6">
    <h2 class="font-semibold mb-3">Findings ({len(findings)})</h2>
    <div class="space-y-3">{finding_cards}</div>
  </section>

  <section class="glass rounded-xl p-4">
    <h2 class="font-semibold mb-2">Files analyzed</h2>
    <ul class="list-disc list-inside">{files}</ul>
  </section>

  <footer class="text-center text-xs text-slate-600 mt-8">
    Generated by Defender — AI Code Compliance Defender for banking. Built on Google ADK.
  </footer>
</div>
</body>
</html>"""


def _stat(label: str, value: object) -> str:
    return f"""<div class="glass rounded-xl p-4 text-center">
      <div class="text-2xl font-bold">{_esc(value)}</div>
      <div class="text-xs text-slate-500 uppercase tracking-wide">{_esc(label)}</div>
    </div>"""


def _score_bar(score: float) -> str:
    color = "bg-emerald-500" if score >= 80 else "bg-amber-500" if score >= 50 else "bg-red-500"
    return f"""<div class="flex items-center gap-2">
      <div class="w-24 bg-white/10 rounded-full h-2">
        <div class="{color} h-2 rounded-full" style="width:{score}%"></div></div>
      <span class="text-sm text-slate-300">{score}</span></div>"""


def _finding_card(f) -> str:
    sev = _SEV_CLASS[f.severity]
    fw = (
        f'<span class="text-xs text-slate-500">{_esc(", ".join(f.frameworks))}</span>'
        if f.frameworks
        else ""
    )
    rem = (
        f'<p class="text-sm text-emerald-400 mt-1">Fix: {_esc(f.remediation)}</p>'
        if f.remediation
        else ""
    )
    return f"""<div class="border border-white/10 rounded-lg p-3 bg-white/[0.02]">
      <div class="flex items-center gap-2 mb-1 flex-wrap">
        <span class="text-xs font-bold px-2 py-0.5 rounded border {sev}">
          {f.severity.value.upper()}</span>
        <span class="font-medium">{_esc(f.title)}</span>
        <code class="text-xs text-slate-500">{_esc(f.id)}</code>
      </div>
      <p class="text-sm text-slate-500">{_esc(f.location())} &middot; {_esc(f.source)}</p>
      <p class="text-sm text-slate-300 mt-1">{_esc(f.message)}</p>
      {rem}{fw}
    </div>"""
