"""Tests for BYOM provider precedence (Settings.effective_model_provider).

Covers the "bring your own OpenAI key" requirement: if an OpenAI API key is
present -- via OPENAI_API_KEY or the OPENAIKEY shorthand -- it always wins
over whatever DEFENDER_MODEL_PROVIDER is configured (gateway/adk/gemini),
switching off the Walmart LLM Gateway / ADK path automatically.
"""

from defender.core.config import Settings
from defender.models.factory import get_provider


def test_no_openai_key_keeps_configured_provider():
    s = Settings(defender_model_provider="adk", openai_api_key="")
    assert s.effective_model_provider == "adk"


def test_openai_key_overrides_adk():
    s = Settings(defender_model_provider="adk", openai_api_key="sk-test")
    assert s.effective_model_provider == "openai"


def test_openai_key_overrides_gateway():
    s = Settings(defender_model_provider="gateway", openai_api_key="sk-test")
    assert s.effective_model_provider == "openai"


def test_openai_key_overrides_mock_default():
    s = Settings(defender_model_provider="mock", openai_api_key="sk-test")
    assert s.effective_model_provider == "openai"


def test_openai_key_alias_env_var(monkeypatch):
    """The shorthand OPENAIKEY (no underscore) must be honored, not just the
    standard OPENAI_API_KEY -- this is a user-facing requirement, not an
    implementation detail."""
    monkeypatch.setenv("OPENAIKEY", "sk-shorthand")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    s = Settings()
    assert s.openai_api_key == "sk-shorthand"
    assert s.effective_model_provider == "openai"


def test_get_provider_returns_openai_when_key_present():
    s = Settings(defender_model_provider="adk", openai_api_key="sk-test")
    provider = get_provider(s)
    assert provider.name == "openai"


def test_get_provider_falls_back_to_mock_without_key():
    s = Settings(defender_model_provider="openai", openai_api_key="")
    provider = get_provider(s)
    assert provider.name == "mock"


def test_openai_model_default_is_not_the_gemini_default():
    s = Settings(openai_api_key="sk-test")
    provider = get_provider(s)
    assert provider.model == "gpt-4o-mini"


def test_openai_model_env_override_respected(monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4.1-mini")
    s = Settings(openai_api_key="sk-test")
    provider = get_provider(s)
    assert provider.model == "gpt-4.1-mini"
