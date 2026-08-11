"""Google ADK / Gemini provider.

This is the flagship BYOM backend. It uses Google's Agent Development Kit
(google-adk) with an `LlmAgent` when available, and falls back to the raw
google-genai client otherwise. Imports are lazy so the package installs and
runs (in mock mode) without any Google dependencies present.
"""

from __future__ import annotations

from defender.models.base import ModelProvider


class GeminiADKProvider(ModelProvider):
    """Runs analyzer prompts through a Google ADK LlmAgent backed by Gemini."""

    provider_name = "gemini"

    def __init__(self, model: str, api_key: str = "", use_vertex: bool = False):
        super().__init__(model)
        self._api_key = api_key
        self._use_vertex = use_vertex
        self._agent = None
        self._runner = None
        self._genai = None

    def _ensure_client(self) -> None:
        if self._agent is not None or self._genai is not None:
            return
        try:
            # Preferred path: Google ADK agent runtime.
            from google.adk.agents import LlmAgent  # type: ignore

            self._agent = LlmAgent(
                name="defender_analyzer",
                model=self.model,
                instruction=(
                    "You are a code-compliance analyzer for regulated banking "
                    "systems. Always answer with a single JSON object."
                ),
            )
        except Exception:  # pragma: no cover - depends on optional dep
            self._agent = None

        if self._agent is None:
            # Fallback path: raw google-genai client.
            from google import genai  # type: ignore

            self._genai = genai.Client(api_key=self._api_key or None)

    async def complete(self, system: str, user: str) -> str:
        self._ensure_client()

        if self._agent is not None:  # pragma: no cover - needs live ADK + key
            from google.adk.runners import InMemoryRunner  # type: ignore
            from google.genai import types  # type: ignore

            runner = InMemoryRunner(agent=self._agent, app_name="defender")
            session = await runner.session_service.create_session(
                app_name="defender", user_id="defender"
            )
            content = types.Content(
                role="user",
                parts=[types.Part.from_text(text=f"{system}\n\n{user}")],
            )
            chunks: list[str] = []
            async for event in runner.run_async(
                user_id="defender", session_id=session.id, new_message=content
            ):
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if getattr(part, "text", None):
                            chunks.append(part.text)
            return "".join(chunks)

        # google-genai fallback.
        assert self._genai is not None  # pragma: no cover
        resp = self._genai.models.generate_content(  # pragma: no cover
            model=self.model, contents=f"{system}\n\n{user}"
        )
        return getattr(resp, "text", "") or ""
