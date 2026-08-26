"""Provider abstraction so verify.py doesn't care which LLM backend is
configured. See docs/framework.md section 5.1.

Phase 1 only ships OpenAICompatibleProvider (llm_gateway/providers/
openai_compatible.py) — it already covers every backend actually in use
(official OpenAI, DeepSeek, Kimi, 通义千问 compatible-mode, Zhipu GLM, and
any self-hosted OpenAI-protocol gateway) since they all speak the same
Chat Completions API. A dedicated claude.py (different protocol) and
local_ollama.py are still on the framework's supplier list but out of
scope until something actually needs them.
"""
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def chat(self, messages: list[dict], model: str, response_format: str | None = None) -> str:
        """Return the model's raw text output. response_format='json' asks
        for structured JSON output where the backend supports it."""

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Send a minimal request to verify the config works. Returns
        (success, error_message) — error_message is "" on success."""
