"""Test configuration.

Force the deterministic offline mock provider for the entire suite so tests
never depend on network access, the Walmart VPN, or the live LLM gateway — even
when a developer's local .env points DEFENDER_MODEL_PROVIDER at 'gateway'.
"""

import os

# Must be set before defender.core.config.get_settings() is first evaluated.
os.environ["DEFENDER_MODEL_PROVIDER"] = "mock"
os.environ["DEFENDER_MODEL_NAME"] = "mock-model"

from defender.core.config import get_settings  # noqa: E402

get_settings.cache_clear()
