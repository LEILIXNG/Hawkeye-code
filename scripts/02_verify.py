"""
Phase 0 / Step 2: minimal LLM verification pass over the candidates produced
by 01_scan.py.

This is deliberately the "cheap" version of the context extractor described
in docs/framework.md section 3 — instead of a real call graph, it just grabs
a fixed line window around the source and sink locations. Good enough to
test whether the verify step itself is useful before investing in proper
cross-function slicing.

Goes through llm_gateway (scanner/verify.py + llm_gateway/config.py), which
works against any OpenAI-compatible endpoint (DeepSeek, Kimi, 通义千问
compatible-mode, a self-hosted gateway, etc.) by setting OPENAI_BASE_URL —
see docs/framework.md section 5 for the supplier list this is meant to line
up with.

Requires OPENAI_API_KEY to be set. Easiest way: copy .env.example to .env
(gitignored, never commit it) and fill in your key there -- it's loaded
automatically. Do not hardcode the key in this file.

Usage:
    python scripts/02_verify.py --target /path/to/repo
    OPENAI_BASE_URL=https://api.deepseek.com/v1 OPENAI_VERIFY_MODEL=deepseek-chat \
        python scripts/02_verify.py --target /path/to/repo
"""
import argparse
import sys
from pathlib import Path

from common import CANDIDATES_PATH, PROMPTS_DIR, VERIFIED_PATH, ensure_data_dir, load_json, write_json
from llm_gateway.config import provider_and_model_from_config
from scanner.callgraph import index_workspace
from scanner.core import build_context, build_prompt  # noqa: F401
from scanner.verify import call_llm  # noqa: F401


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Path to the repo that was scanned")
    parser.add_argument("--candidates", default=str(CANDIDATES_PATH))
    parser.add_argument("--out", default=str(VERIFIED_PATH))
    parser.add_argument("--limit", type=int, default=None, help="Only verify the first N candidates (for testing)")
    args = parser.parse_args()

    try:
        provider, model = provider_and_model_from_config(None)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)

    ensure_data_dir()
    target = Path(args.target)
    candidates = load_json(Path(args.candidates))
    if args.limit:
        candidates = candidates[: args.limit]

    template = (PROMPTS_DIR / "verify_taint.md").read_text(encoding="utf-8")
    print("[verify] indexing the call graph", file=sys.stderr)
    index = index_workspace(target)
    print(f"[verify] {len(index.methods)} methods, {len(index.calls)} call sites", file=sys.stderr)

    verified = []
    for i, candidate in enumerate(candidates, 1):
        print(f"[verify] {i}/{len(candidates)} {candidate['sink_file']}:{candidate['sink_line']}", file=sys.stderr)
        code_context = build_context(target, candidate, index)
        prompt = build_prompt(template, candidate, code_context)
        finding = call_llm(provider, model, prompt)
        verified.append({**candidate, "finding": finding})

    write_json(Path(args.out), verified)
    print(f"[verify] wrote {args.out}")


if __name__ == "__main__":
    main()
