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


JSON_RETRY_HINT = "上一次输出不是合法 JSON,请只输出 JSON,不要有任何其他文字。"


def call_llm_cached(provider, model: str, prompt: str, parse=parse_llm_json, retry_hint=JSON_RETRY_HINT):
    """One cached, JSON-parsed call, retried once when the reply will not
    parse. Raises json.JSONDecodeError if the retry fails too -- what a
    failure *means* differs by stage, so the caller decides.

    The cache key is always the original prompt: the retry appends a nudge
    to the text it sends, and keying on that would file the answer under a
    prompt no future run reconstructs.
    """
    cache_file = LLM_CACHE_DIR / f"{sha256(f'{model}:{prompt}')}.json"
    if cache_file.exists():
        return load_json(cache_file)

    sent = prompt
    for attempt in range(2):
        raw_text = provider.chat(
            [{"role": "user", "content": sent}],
            model=model,
            response_format="json",
        )
        try:
            result = parse(raw_text)
        except json.JSONDecodeError:
            if attempt == 0:
                sent = f"{prompt}\n\n{retry_hint}"
                continue
            raise
        write_json(cache_file, result)
        return result


def call_llm(provider, model: str, prompt: str) -> dict:
    """The verify stage's call: an unparseable reply becomes an explicit
    verifier_failed finding rather than an exception, so one bad reply does
    not abandon a scan that is minutes deep."""
    try:
        return call_llm_cached(provider, model, prompt)
    except json.JSONDecodeError:
        return {
            "reachable": "uncertain",
            "sanitized": None,
            "confidence": 0,
            "reasoning": "verifier_failed: LLM did not return valid JSON",
            "exploit_scenario": "",
            "remediation": "",
        }
