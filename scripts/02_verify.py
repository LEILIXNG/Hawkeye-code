"""
Phase 0 / Step 2: minimal LLM verification pass over the candidates produced
by 01_scan.py.

This is deliberately the "cheap" version of the context extractor described
in docs/framework.md section 3 — instead of a real call graph, it just grabs
a fixed line window around the source and sink locations. Good enough to
test whether the verify step itself is useful before investing in proper
cross-function slicing.

Uses the OpenAI Python SDK. This also works against any OpenAI-compatible
endpoint (DeepSeek, Kimi, 通义千问 compatible-mode, a self-hosted gateway,
etc.) by setting OPENAI_BASE_URL — see docs/framework.md section 5 for the
supplier list this is meant to line up with.

Requires OPENAI_API_KEY to be set. Easiest way: copy .env.example to .env
(gitignored, never commit it) and fill in your key there -- it's loaded
automatically. Do not hardcode the key in this file.

Usage:
    python scripts/02_verify.py --target /path/to/repo
    OPENAI_BASE_URL=https://api.deepseek.com/v1 OPENAI_VERIFY_MODEL=deepseek-chat \
        python scripts/02_verify.py --target /path/to/repo
"""
import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from common import (
    CANDIDATES_PATH,
    LLM_CACHE_DIR,
    PROMPTS_DIR,
    ROOT,
    VERIFIED_PATH,
    ensure_data_dir,
    load_json,
    sha256,
    write_json,
)

load_dotenv(ROOT / ".env")  # no-op if the file doesn't exist; real env vars still take priority

CONTEXT_WINDOW = 15  # lines of code above/below each location to include
MODEL = os.environ.get("OPENAI_VERIFY_MODEL", "gpt-4o-mini")


def read_window(target: Path, rel_path: str, line: int, window: int) -> str:
    full_path = target / rel_path
    if not full_path.exists() or line is None:
        return f"(file not found: {rel_path})"
    lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, line - 1 - window)
    end = min(len(lines), line - 1 + window + 1)
    numbered = [f"{i + 1:>5} | {lines[i]}" for i in range(start, end)]
    return "\n".join(numbered)


def build_context(target: Path, candidate: dict) -> str:
    sink_block = read_window(target, candidate["sink_file"], candidate["sink_line"], CONTEXT_WINDOW)
    if candidate["source_file"] == candidate["sink_file"] and candidate["source_line"] == candidate["sink_line"]:
        return f"### {candidate['sink_file']} (source == sink)\n{sink_block}"

    source_block = read_window(target, candidate["source_file"], candidate["source_line"], CONTEXT_WINDOW)
    return (
        f"### Source: {candidate['source_file']}\n{source_block}\n\n"
        f"### Sink: {candidate['sink_file']}\n{sink_block}"
    )


def build_prompt(template: str, candidate: dict, code_context: str) -> str:
    return template.format(
        rule_ids=", ".join(candidate.get("rule_ids", [candidate.get("rule_id", "")])),
        message=" / ".join(candidate.get("messages", [candidate.get("message", "")])),
        cwe=candidate.get("cwe"),
        source_file=candidate["source_file"],
        source_line=candidate["source_line"],
        sink_file=candidate["sink_file"],
        sink_line=candidate["sink_line"],
        code_context=code_context,
    )


def parse_llm_json(raw_text: str) -> dict:
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    return json.loads(text.strip())


def call_llm(client: OpenAI, prompt: str) -> dict:
    cache_key = sha256(prompt)
    cache_file = LLM_CACHE_DIR / f"{cache_key}.json"
    if cache_file.exists():
        return load_json(cache_file)

    for attempt in range(2):
        resp = client.chat.completions.create(
            model=MODEL,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        raw_text = resp.choices[0].message.content
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
                "raw_output": raw_text,
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Path to the repo that was scanned")
    parser.add_argument("--candidates", default=str(CANDIDATES_PATH))
    parser.add_argument("--out", default=str(VERIFIED_PATH))
    parser.add_argument("--limit", type=int, default=None, help="Only verify the first N candidates (for testing)")
    args = parser.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY is not set in the environment.", file=sys.stderr)
        raise SystemExit(1)

    ensure_data_dir()
    target = Path(args.target)
    candidates = load_json(Path(args.candidates))
    if args.limit:
        candidates = candidates[: args.limit]

    template = (PROMPTS_DIR / "verify_taint.md").read_text(encoding="utf-8")
    base_url = os.environ.get("OPENAI_BASE_URL")  # None -> official OpenAI endpoint
    client = OpenAI(base_url=base_url) if base_url else OpenAI()

    verified = []
    for i, candidate in enumerate(candidates, 1):
        print(f"[verify] {i}/{len(candidates)} {candidate['sink_file']}:{candidate['sink_line']}", file=sys.stderr)
        code_context = build_context(target, candidate)
        prompt = build_prompt(template, candidate, code_context)
        finding = call_llm(client, prompt)
        verified.append({**candidate, "finding": finding})

    write_json(Path(args.out), verified)
    print(f"[verify] wrote {args.out}")


if __name__ == "__main__":
    main()
