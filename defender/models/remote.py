"""OpenAI-compatible and on-prem Ollama providers.

Both hit an OpenAI-style or Ollama HTTP endpoint via httpx so no vendor SDK is
strictly required. The Ollama provider is the recommended on-prem / air-gapped
BYOM story for regulated banking deployments.
"""

from __future__ import annotations

import httpx

from defender.models.base import ModelProvider


class OpenAIProvider(ModelProvider):
    provider_name = "openai"

    def __init__(self, model: str, api_key: str, base_url: str):
        super().__init__(model)
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    async def complete(self, system: str, user: str) -> str:  # pragma: no cover
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]


class OllamaProvider(ModelProvider):
    provider_name = "ollama"

    def __init__(self, model: str, base_url: str):
        super().__init__(model)
        self._base_url = base_url.rstrip("/")

    async def complete(self, system: str, user: str) -> str:  # pragma: no cover
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json={
                    "model": self.model,
                    "stream": False,
                    "format": "json",
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            resp.raise_for_status()
            return resp.json().get("message", {}).get("content", "")
