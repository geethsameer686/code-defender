"""Model provider abstraction — the Bring-Your-Own-Model (BYOM) layer.

Every LLM-backed analyzer talks to a `ModelProvider`, never to a vendor SDK
directly. That is the whole point of BYOM for regulated banks: swap Gemini for
an on-prem Ollama model (or an offline deterministic mock) without touching a
single line of agent logic.

Providers return a JSON string shaped like:
    {"narrative": "...", "findings": [ {finding dict}, ... ]}
Agents are defensive: if parsing fails, they degrade gracefully to static-only.
"""

from __future__ import annotations

import abc
import json
from typing import Any


class ModelProvider(abc.ABC):
    """Interface every model backend must implement."""

    provider_name: str = "base"

    def __init__(self, model: str):
        self.model = model

    @property
    def name(self) -> str:
        return self.provider_name

    @abc.abstractmethod
    async def complete(self, system: str, user: str) -> str:
        """Return the model's raw completion for the given system+user prompt."""
        raise NotImplementedError

    @staticmethod
    def extract_json(text: str) -> dict[str, Any]:
        """Best-effort JSON extraction from a model response.

        LLMs love wrapping JSON in prose or ```json fences. We cope.
        """
        text = text.strip()
        if not text:
            return {}
        # Strip common code fences.
        if text.startswith("```"):
            text = text.split("```", 2)[1] if "```" in text[3:] else text[3:]
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:]
        # Find the outermost JSON object.
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end < start:
            return {}
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return {}
