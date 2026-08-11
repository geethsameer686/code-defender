"""Walmart PROD LLM Gateway provider.

Wraps the tested ``call_gemini()`` from the repo-root ``gemini_llm.py`` so
Defender's analyzer agents run against Gemini 2.5 Flash Lite via the Walmart
LLM Gateway. DRY on purpose: we reuse the existing, working gateway wiring
(endpoint, auth headers, CA bundle) instead of re-implementing it here.

``call_gemini`` is synchronous, so we offload it to a worker thread to keep the
orchestrator's ``asyncio.gather`` fan-out non-blocking.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
from typing import Callable

from defender.models.base import ModelProvider


def _load_call_gemini() -> Callable[..., str]:
    """Import call_gemini from the repo-root gemini_llm.py, robustly."""
    try:
        module = importlib.import_module("gemini_llm")
    except ModuleNotFoundError:
        # Not on sys.path (e.g. running via the installed console script).
        cwd = os.getcwd()
        if cwd not in sys.path:
            sys.path.insert(0, cwd)
        module = importlib.import_module("gemini_llm")
    return module.call_gemini


class GatewayGeminiProvider(ModelProvider):
    provider_name = "gateway"

    def __init__(
        self,
        model: str = "gemini-2.5-flash-lite@001",
        user_name: str = "",
        temperature: float = 0.1,
    ):
        super().__init__(model)
        self._call_gemini = _load_call_gemini()
        self._user_name = user_name
        self._temperature = temperature

    async def complete(self, system: str, user: str) -> str:
        kwargs = {
            "user_input": user,
            "system_prompt": system,
            "model": self.model,
            "temperature": self._temperature,
        }
        if self._user_name:
            kwargs["user_name"] = self._user_name
        return await asyncio.to_thread(self._call_gemini, **kwargs)
