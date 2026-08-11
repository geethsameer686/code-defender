"""Central configuration for Defender, loaded from environment / .env.

Everything tunable — the model provider, gate policy, and VCS secrets — flows
through here so no other module reads os.environ directly.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from defender.core.models import Severity


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="", extra="ignore", case_sensitive=False
    )

    # --- Model / BYOM ---
    defender_model_provider: str = "mock"
    defender_model_name: str = "gemini-2.0-flash"

    # Walmart PROD LLM Gateway (provider=gateway, via gemini_llm.py)
    llm_gateway_user_name: str = ""

    google_api_key: str = ""
    google_genai_use_vertexai: bool = False
    google_cloud_project: str = ""
    google_cloud_location: str = "us-central1"

    openai_api_key: str = Field(
        default="",
        # Accept both the standard OPENAI_API_KEY and the shorthand OPENAIKEY
        # some people export by habit -- either one is honored.
        validation_alias=AliasChoices("OPENAI_API_KEY", "OPENAIKEY", "openai_api_key"),
    )
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = Field(
        default="gpt-4o-mini",
        validation_alias=AliasChoices("OPENAI_MODEL", "openai_model"),
    )

    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"

    # --- Gate policy ---
    defender_gate_min_score: int = 80
    defender_gate_block_severity: str = "high"

    # --- VCS integrations ---
    github_webhook_secret: str = ""
    github_token: str = ""
    gitlab_webhook_secret: str = ""
    gitlab_token: str = ""

    @property
    def block_severity(self) -> Severity:
        try:
            return Severity(self.defender_gate_block_severity.lower())
        except ValueError:
            return Severity.HIGH

    @property
    def effective_model_provider(self) -> str:
        """The provider Defender actually uses, after BYOM key precedence.

        If an OpenAI API key is present (OPENAI_API_KEY or OPENAIKEY), it
        always wins -- regardless of DEFENDER_MODEL_PROVIDER -- and the
        Walmart LLM Gateway / ADK / Gemini paths are switched off. This lets
        anyone bring their own OpenAI key without touching any other config.
        """
        if self.openai_api_key.strip():
            return "openai"
        return self.defender_model_provider.lower().strip()


@lru_cache
def get_settings() -> Settings:
    return Settings()
