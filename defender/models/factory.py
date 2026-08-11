"""Provider factory — resolves the configured BYOM backend.

Falls back to the offline mock if a real provider is requested but its optional
dependency or credentials are missing. Defender never crashes just because a key
is absent; it degrades to deterministic mode and says so in the report.
"""

from __future__ import annotations

from defender.core.config import Settings, get_settings
from defender.models.base import ModelProvider
from defender.models.mock import MockProvider


def get_provider(settings: Settings | None = None) -> ModelProvider:
    settings = settings or get_settings()
    provider = settings.effective_model_provider
    model = settings.defender_model_name

    if provider == "mock":
        return MockProvider(model)

    if provider == "gateway":
        # Walmart PROD LLM Gateway (Gemini 2.5 Flash Lite) via gemini_llm.py.
        try:
            from defender.models.gateway import GatewayGeminiProvider

            return GatewayGeminiProvider(
                model=model or "gemini-2.5-flash-lite@001",
                user_name=settings.llm_gateway_user_name,
            )
        except Exception:
            return MockProvider(model)

    if provider == "gemini":
        try:
            from defender.models.gemini import GeminiADKProvider

            return GeminiADKProvider(
                model=model,
                api_key=settings.google_api_key,
                use_vertex=settings.google_genai_use_vertexai,
            )
        except Exception:
            return MockProvider(model)

    if provider == "openai":
        if not settings.openai_api_key:
            return MockProvider(model)
        from defender.models.remote import OpenAIProvider

        # OPENAI_MODEL wins if set; otherwise fall back to a sane OpenAI
        # default rather than whatever Gemini model name happens to be
        # configured in DEFENDER_MODEL_NAME.
        openai_model = settings.openai_model or model or "gpt-4o-mini"
        return OpenAIProvider(
            openai_model, settings.openai_api_key, settings.openai_base_url
        )

    if provider == "ollama":
        from defender.models.remote import OllamaProvider

        return OllamaProvider(settings.ollama_model, settings.ollama_base_url)

    # Unknown provider name -> safe default.
    return MockProvider(model)
