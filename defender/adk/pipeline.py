"""ADK pipeline — genuine Google ADK agentic orchestration for Defender.

Builds one ``LlmAgent`` per validation dimension, composes them under an ADK
``ParallelAgent`` (concurrent fan-out — the shift-left agentic evaluation), and
executes the whole thing with an ADK ``Runner``. Each agent writes its JSON
verdict into session state via ``output_key``; we read them back after the run.

The model behind every agent is :class:`GatewayLlm`, so ADK does the agent
orchestration while the actual inference happens on the Walmart LLM Gateway.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent, ParallelAgent
from google.adk.runners import InMemoryRunner
from google.genai import types

from defender.agents.specialists import ALL_AGENT_CLASSES
from defender.adk.gateway_llm import GatewayLlm
from defender.core.models import Dimension

APP_NAME = "defender"
_OUTPUT_PREFIX = "defender_"


def _instruction_for(cls) -> str:
    dim = cls.dimension.value
    return (
        f"[DEFENDER_DIMENSION={dim}]\n{cls.system_prompt}\n\n"
        "You will receive added source code from a change set. Respond with ONLY "
        "a single JSON object of the form "
        '{"narrative": "<2-3 sentence assessment>", "findings": [{"id": "AI-'
        f'{dim.upper()}-<slug>", "severity": "low|medium|high|critical", '
        '"title": "...", "message": "...", "remediation": "...", '
        '"file": "<path>", "line": <int or null>}]}. '
        "Only report genuine issues; return an empty findings list if clean."
    )


def build_parallel_agent(model_name: str, user_name: str = "") -> ParallelAgent:
    """Construct the ADK ParallelAgent with one LlmAgent per dimension."""
    sub_agents = []
    for cls in ALL_AGENT_CLASSES:
        dim = cls.dimension.value
        model = GatewayLlm(model=model_name, user_name=user_name)
        sub_agents.append(
            LlmAgent(
                name=f"{_OUTPUT_PREFIX}{dim}_agent",
                model=model,
                instruction=_instruction_for(cls),
                description=f"Defender {dim} analyzer",
                output_key=f"{_OUTPUT_PREFIX}{dim}",
            )
        )
    return ParallelAgent(name="defender_parallel", sub_agents=sub_agents)


async def run_adk_analysis(
    code: str, model_name: str, user_name: str = ""
) -> dict[Dimension, str]:
    """Run the ADK ParallelAgent over `code`; return raw JSON text per dimension."""
    parallel = build_parallel_agent(model_name, user_name)
    runner = InMemoryRunner(agent=parallel, app_name=APP_NAME)

    session = await runner.session_service.create_session(
        app_name=APP_NAME, user_id="defender"
    )
    message = types.Content(
        role="user", parts=[types.Part.from_text(text=code)]
    )

    async for _event in runner.run_async(
        user_id="defender", session_id=session.id, new_message=message
    ):
        pass  # events stream; final state is read from the session below.

    final = await runner.session_service.get_session(
        app_name=APP_NAME, user_id="defender", session_id=session.id
    )
    state = final.state if final else {}

    out: dict[Dimension, str] = {}
    for cls in ALL_AGENT_CLASSES:
        dim = cls.dimension
        out[dim] = str(state.get(f"{_OUTPUT_PREFIX}{dim.value}", "") or "")
    return out


def adk_available() -> bool:
    try:
        import google.adk  # noqa: F401

        return True
    except Exception:
        return False
