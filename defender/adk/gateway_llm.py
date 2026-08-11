"""GatewayLlm — a genuine Google ADK ``BaseLlm`` backed by the Walmart Gateway.

This is what makes Defender *actually* run on the Google ADK agentic framework
(not "ADK-style"): ADK's ``LlmAgent`` / ``ParallelAgent`` / ``Runner`` drive the
orchestration, and every model call this subclass receives is forwarded to the
Walmart PROD LLM Gateway via the tested ``call_gemini()`` in ``gemini_llm.py``.

ADK contract (v2.x):
    async def generate_content_async(self, llm_request, stream=False)
        -> AsyncGenerator[LlmResponse, None]
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.genai import types

from defender.models.gateway import _load_call_gemini


class GatewayLlm(BaseLlm):
    """ADK model that proxies to the Walmart LLM Gateway (Gemini 2.5)."""

    # Extra (non-ADK) attributes; BaseLlm is a pydantic model so declare them.
    user_name: str = ""
    temperature: float = 0.1

    def __init__(self, model: str = "gemini-2.5-flash-lite@001", **kwargs):
        super().__init__(model=model, **kwargs)
        # call_gemini is loaded lazily and kept off the pydantic schema.
        object.__setattr__(self, "_call_gemini", _load_call_gemini())

    async def generate_content_async(
        self, llm_request, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        system = _extract_system_instruction(llm_request)
        user = _extract_user_text(llm_request)

        kwargs = {
            "user_input": user,
            "system_prompt": system or "You are a helpful assistant.",
            "model": self.model,
            "temperature": self.temperature,
        }
        if self.user_name:
            kwargs["user_name"] = self.user_name

        text = await asyncio.to_thread(self._call_gemini, **kwargs)
        yield LlmResponse(
            content=types.Content(
                role="model", parts=[types.Part.from_text(text=text or "")]
            ),
            turn_complete=True,
        )


def _extract_system_instruction(llm_request) -> str:
    config = getattr(llm_request, "config", None)
    if config is None:
        return ""
    si = getattr(config, "system_instruction", None)
    if si is None:
        return ""
    if isinstance(si, str):
        return si
    # Content or list[Part]
    parts = getattr(si, "parts", None) or (si if isinstance(si, list) else [])
    return "\n".join(getattr(p, "text", "") or "" for p in parts).strip()


def _extract_user_text(llm_request) -> str:
    contents = getattr(llm_request, "contents", None) or []
    chunks: list[str] = []
    for content in contents:
        if getattr(content, "role", None) == "model":
            continue
        for part in getattr(content, "parts", None) or []:
            if getattr(part, "text", None):
                chunks.append(part.text)
    return "\n".join(chunks).strip()
