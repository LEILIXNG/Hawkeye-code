"""Builds an LLMProvider from the currently active LLMConfig DB row, with a
fallback to the .env-based OPENAI_* variables used by Phase 0's scripts so
existing local setups keep working without touching /settings first.
"""
import os

from dotenv import load_dotenv

from llm_gateway.providers.openai_compatible import OpenAICompatibleProvider
from scanner.common import ROOT

load_dotenv(ROOT / ".env")  # no-op if missing; real env vars still take priority


def provider_and_model_from_config(llm_config) -> tuple[OpenAICompatibleProvider, str]:
    """llm_config is an apps.api.models.LLMConfig row, or None to fall back
    entirely to environment variables."""
    if llm_config is not None:
        api_key = llm_config.api_key or os.environ.get("OPENAI_API_KEY", "")
        base_url = llm_config.base_url or os.environ.get("OPENAI_BASE_URL")
        model = llm_config.verify_model or os.environ.get("OPENAI_VERIFY_MODEL", "gpt-4o-mini")
    else:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        base_url = os.environ.get("OPENAI_BASE_URL")
        model = os.environ.get("OPENAI_VERIFY_MODEL", "gpt-4o-mini")

    if not api_key:
        raise ValueError(
            "No LLM API key configured. Set it via POST /settings/llm or the "
            "OPENAI_API_KEY environment variable (.env)."
        )
    return OpenAICompatibleProvider(base_url=base_url, api_key=api_key), model
