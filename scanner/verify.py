"""E: LLM verification stage, provider-agnostic (see llm_gateway/).

call_llm here takes an llm_gateway LLMProvider instead of talking to the
OpenAI SDK directly, so both the Phase 0 CLI (scripts/02_verify.py) and the
Phase 1 API pipeline (scanner/pipeline.py) share one code path — including
the on-disk cache, which is keyed on the full prompt text per
docs/framework.md section 3's "缓存修正 ③" (whole context, not just the
sink line).
"""
import json

from scanner.common import LLM_CACHE_DIR, load_json, sha256, write_json
from scanner.core import parse_llm_json


def call_llm(provider, model: str, prompt: str) -> dict:
    cache_key = sha256(f"{model}:{prompt}")
    cache_file = LLM_CACHE_DIR / f"{cache_key}.json"
    if cache_file.exists():
        return load_json(cache_file)

    for attempt in range(2):
        raw_text = provider.chat(
            [{"role": "user", "content": prompt}],
            model=model,
            response_format="json",
        )
        try:
            result = parse_llm_json(raw_text)
            write_json(cache_file, result)
            return result
        except json.JSONDecodeError:
            if attempt == 0:
                prompt += "\n\n上一次输出不是合法 JSON,请只输出 JSON,不要有任何其他文字。"
                continue
            return {
                "reachable": "uncertain",
                "sanitized": None,
                "confidence": 0,
                "reasoning": "verifier_failed: LLM did not return valid JSON",
                "exploit_scenario": "",
                "remediation": "",
                "raw_output": raw_text,
            }
