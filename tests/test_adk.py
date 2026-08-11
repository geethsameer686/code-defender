"""Genuine-ADK engine wiring test (no network).

Stubs the ADK pipeline so we can assert the engine's ADK code path merges LLM
findings with static findings correctly, without hitting the gateway.
"""

import json

import defender.adk as adk_pkg
from defender.core.config import Settings
from defender.core.models import Dimension
from defender.engine import Defender


async def _fake_run_adk_analysis(code, model_name, user_name=""):
    """Pretend the ADK ParallelAgent returned one finding per dimension."""
    out = {}
    for dim in Dimension:
        out[dim] = json.dumps(
            {
                "narrative": f"ADK {dim.value} narrative.",
                "findings": [
                    {
                        "id": f"AI-{dim.value.upper()}-TEST",
                        "severity": "medium",
                        "title": f"{dim.value} issue",
                        "message": "stubbed",
                    }
                ],
            }
        )
    return out


async def test_adk_engine_merges_static_and_agent(monkeypatch):
    monkeypatch.setattr(adk_pkg, "run_adk_analysis", _fake_run_adk_analysis)

    settings = Settings(
        defender_model_provider="adk",
        defender_model_name="gemini-2.5-flash-lite@001",
    )
    defender = Defender(settings=settings, use_llm=True)
    assert defender.use_adk is True  # real ADK path selected

    diff = (
        "diff --git a/x.py b/x.py\nnew file mode 100644\n--- /dev/null\n"
        "+++ b/x.py\n@@ -0,0 +1,1 @@\n"
        '+password = "supersecretvalue"\n'
    )
    report = await defender.analyze_diff(diff)

    assert report.model_provider == "adk"
    assert report.model_name == "gemini-2.5-flash-lite@001"
    # One ADK finding per dimension + the static hardcoded-secret finding.
    agent = [f for f in report.all_findings() if f.source == "agent"]
    static = [f for f in report.all_findings() if f.source == "static"]
    assert len(agent) == len(list(Dimension))
    assert any(f.id == "SEC-HARDCODED-SECRET" for f in static)
    # Every dimension got a narrative from the ADK agent.
    assert all(d.agent_narrative for d in report.dimensions)
