"""Generic OpenAI Chat Completions protocol adapter. Covers OpenAI,
DeepSeek, Kimi, 通义千问 (compatible-mode), Zhipu GLM, and any self-hosted
gateway that speaks the same protocol — see docs/framework.md section 5.
"""
from openai import OpenAI

from llm_gateway.providers.base import LLMProvider


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, base_url: str | None, api_key: str):
        self.client = OpenAI(base_url=base_url or None, api_key=api_key)

    def chat(self, messages: list[dict], model: str, response_format: str | None = None) -> str:
        resp = self.client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=messages,
            response_format={"type": "json_object"} if response_format == "json" else None,
        )
        return resp.choices[0].message.content

    def test_connection(self, model: str = "gpt-4o-mini") -> tuple[bool, str]:
        try:
            self.chat([{"role": "user", "content": "ping"}], model=model)
            return True, ""
        except Exception as e:
            return False, str(e)
