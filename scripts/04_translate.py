"""
Phase 0 / Step 4: fill in the other language for each verified finding's
free-text fields, so the report's zh/en toggle switches the prose and not
just the labels.

Reads data/verified.json (or --verified), writes the same list back with
`reasoning_zh`/`reasoning_en` and the same pair for `exploit_scenario` and
`remediation`. The original fields are left untouched -- downstream
(03_eval.py, scanner/render.py) keeps reading them.

Deliberately a separate stage from 02_verify.py: adding the second language
to prompts/verify_taint.md would invalidate every cached verdict and force
a re-verify plus an eval re-run for what is a presentation concern. Skip
this step entirely and the report behaves exactly as it did before.

Uses the same on-disk LLM cache as the verify stage, keyed on the prompt,
so re-running a scan only pays for findings whose text actually changed.
Requires OPENAI_API_KEY the same way 02_verify.py does.

Usage:
    python scripts/04_translate.py
    python scripts/04_translate.py --verified data/verified.json --out data/verified.json
    python scripts/04_translate.py --limit 5
"""
import argparse
import json
import sys
from pathlib import Path

from common import PROMPTS_DIR, VERIFIED_PATH, ensure_data_dir, load_json, write_json

from llm_gateway.config import provider_and_model_from_config
from scanner.translate import (
    LANGUAGE_NAMES,
    apply_translation,
    build_translate_prompt,
    finding_language,
    needs_translation,
    parse_translation,
    validate_translation,
)
from scanner.verify import call_llm_cached


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verified", default=str(VERIFIED_PATH))
    parser.add_argument("--out", default=None, help="defaults to --verified, i.e. rewritten in place")
    parser.add_argument("--limit", type=int, default=None, help="Only translate the first N findings (for testing)")
    args = parser.parse_args()

    ensure_data_dir()
    verified = load_json(Path(args.verified))
    template = (PROMPTS_DIR / "translate_finding.md").read_text(encoding="utf-8")
    provider, model = provider_and_model_from_config(None)

    out = []
    translated_count = failed = 0
    for i, item in enumerate(verified, 1):
        finding = item.get("finding") or {}
        if not needs_translation(finding) or (args.limit is not None and translated_count >= args.limit):
            out.append(item)
            continue

        source = finding_language(finding)
        target = "en" if source == "zh" else "zh"
        print(f"[translate] {i}/{len(verified)} {source}->{target} "
              f"{item.get('sink_file')}:{item.get('sink_line')}", file=sys.stderr)
        prompt = build_translate_prompt(template, finding, target)
        target_name = LANGUAGE_NAMES[target]
        try:
            parsed = call_llm_cached(
                provider, model, prompt,
                parse=lambda raw: parse_translation(raw, target),
                retry_hint=f"上一次输出没有翻译成{target_name},或者不是合法 JSON。"
                           f"请重新翻译,三个字段全部输出{target_name}。",
            )
            # Again, on the value rather than the reply: a cache hit skips
            # the parse callback entirely, so an entry written before this
            # check existed would never be caught by it.
            parsed = validate_translation(parsed, target)
        except Exception as e:
            # Never fatal: a finding keeps its original text on both sides.
            # Losing the whole run because one reply was malformed would cost
            # far more than one untranslated card.
            print(f"[translate]   failed ({type(e).__name__}), keeping original", file=sys.stderr)
            parsed, failed = None, failed + 1
        else:
            translated_count += 1
        out.append({**item, "finding": apply_translation(finding, source, parsed)})

    write_json(Path(args.out or args.verified), out)
    print(f"[translate] {translated_count} translated, {failed} failed, "
          f"{len(verified) - translated_count - failed} skipped", file=sys.stderr)
    print(f"[translate] wrote {args.out or args.verified}", file=sys.stderr)


if __name__ == "__main__":
    main()
