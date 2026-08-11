"""End-to-end engine tests: orchestration, scoring, and gate policy."""

import pytest

from defender.core.config import Settings
from defender.core.models import Verdict
from defender.engine import Defender
from defender.reporting import to_html, to_json, to_markdown, to_sarif


@pytest.fixture
def strict_settings():
    return Settings(
        defender_model_provider="mock",
        defender_gate_min_score=80,
        defender_gate_block_severity="high",
    )


async def test_clean_code_passes(strict_settings):
    defender = Defender(settings=strict_settings)
    diff = (
        "diff --git a/ok.py b/ok.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n+++ b/ok.py\n@@ -0,0 +1,2 @@\n"
        "+def add(a, b):\n+    return a + b\n"
    )
    report = await defender.analyze_diff(diff)
    assert report.verdict == Verdict.PASS
    assert report.overall_score == 100.0


async def test_vulnerable_code_fails(strict_settings):
    defender = Defender(settings=strict_settings)
    diff = (
        "diff --git a/bad.py b/bad.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n+++ b/bad.py\n@@ -0,0 +1,3 @@\n"
        '+password = "supersecretvalue"\n'
        "+num = 4111111111111111\n"
        "+eval(user_input)\n"
    )
    report = await defender.analyze_diff(diff)
    assert report.verdict == Verdict.FAIL
    assert report.overall_score < 80
    ids = {f.id for f in report.all_findings()}
    assert "SEC-HARDCODED-SECRET" in ids
    assert "PCI-PAN-LITERAL" in ids


async def test_all_dimensions_present(strict_settings):
    defender = Defender(settings=strict_settings)
    report = await defender.analyze_diff("")
    assert len(report.dimensions) == 6


async def test_report_renders_all_formats(strict_settings):
    defender = Defender(settings=strict_settings)
    df = "diff --git a/x.py b/x.py\nnew file mode 100644\n--- /dev/null\n+++ b/x.py\n@@ -0,0 +1,1 @@\n+eval(x)\n"
    report = await defender.analyze_diff(df)
    assert '"verdict"' in to_json(report)
    assert "sarif" in to_sarif(report).lower()
    assert "Defender Compliance Report" in to_markdown(report)
    assert "<html" in to_html(report).lower()


async def test_gate_severity_policy_low_threshold():
    # With block_severity=low, even a lone TODO should FAIL.
    settings = Settings(
        defender_model_provider="mock",
        defender_gate_min_score=0,
        defender_gate_block_severity="low",
    )
    defender = Defender(settings=settings, use_llm=False)
    df = "diff --git a/t.py b/t.py\nnew file mode 100644\n--- /dev/null\n+++ b/t.py\n@@ -0,0 +1,1 @@\n+# TODO fix later\n"
    report = await defender.analyze_diff(df)
    assert report.verdict == Verdict.FAIL
