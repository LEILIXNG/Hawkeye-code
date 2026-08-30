"""Orchestrates A -> B -> C -> E -> G for the Phase 1 API.

Kept intentionally synchronous (called from a FastAPI BackgroundTasks
worker, one scan at a time) per docs/framework.md's "单用户同一时刻通常只
跑一个扫描" simplification — no distributed queue.
"""
import sys
from pathlib import Path
from typing import Callable

from scanner.common import (
    PROMPTS_DIR,
    ensure_data_dir,
    load_default_configs,
    load_excluded_paths,
    load_excluded_rules,
    load_out_of_scope_cwes,
)
from scanner.callgraph import index_workspace
from scanner.core import (
    build_context, build_prompt, dedup, dedup_copies, drop_out_of_scope, normalize, run_semgrep,
)
from scanner.ingest import safe_extract
from scanner.render import render
from scanner.translate import (
    LANGUAGE_NAMES,
    apply_translation,
    build_translate_prompt,
    finding_language,
    needs_translation,
    parse_translation,
    validate_translation,
)
from scanner.verify import call_llm, call_llm_cached

DEFAULT_CONFIGS = load_default_configs()
EXCLUDED_RULES = load_excluded_rules()
EXCLUDED_PATHS = load_excluded_paths()
OUT_OF_SCOPE_CWES = load_out_of_scope_cwes()


class PipelineError(Exception):
    pass


def run_pipeline(
    zip_path: Path,
    workspace_dir: Path,
    report_dir: Path,
    project_name: str,
    provider,
    model: str,
    on_status: Callable[[str], None] = lambda status: None,
    translate: bool = True,
) -> dict:
    """Runs the full A/B/C/E/G flow for one scan. Returns the same dict
    shape as scanner.render.render(). Raises PipelineError on failure;
    callers are responsible for recording Scan.status = "failed"."""
    ensure_data_dir()

    on_status("ingesting")
    try:
        safe_extract(zip_path, workspace_dir)
    except Exception as e:
        raise PipelineError(f"ingest failed: {e}") from e

    on_status("scanning")
    try:
        raw = run_semgrep(workspace_dir, DEFAULT_CONFIGS, EXCLUDED_RULES, EXCLUDED_PATHS)
        in_scope = drop_out_of_scope(normalize(raw, workspace_dir), OUT_OF_SCOPE_CWES)
        candidates = dedup_copies(dedup(in_scope), workspace_dir)
    except Exception as e:
        raise PipelineError(f"scan failed: {e}") from e

    on_status("verifying")
    template = (PROMPTS_DIR / "verify_taint.md").read_text(encoding="utf-8")
    # Built once per scan: indexing is a full parse of every .java file, and
    # doing it per candidate would repeat that work for every finding.
    index = index_workspace(workspace_dir)
    verified = []
    try:
        for i, candidate in enumerate(candidates, 1):
            print(f"[pipeline] verifying {i}/{len(candidates)}", file=sys.stderr)
            code_context = build_context(workspace_dir, candidate, index)
            prompt = build_prompt(template, candidate, code_context)
            finding = call_llm(provider, model, prompt)
            verified.append({**candidate, "finding": finding})
    except Exception as e:
        raise PipelineError(f"verify failed: {e}") from e

    # F: fill in the other language for the prose, so the report's zh/en
    # toggle switches what the reader actually reads and not just the
    # labels. Roughly doubles the LLM calls a scan makes, which is why it is
    # a flag: on a rate-limited free endpoint that is the cost that matters.
    # Never fatal -- an untranslated finding shows the same text under both
    # toggles, which is what the report did before this stage existed.
    if translate:
        on_status("translating")
        translate_template = (PROMPTS_DIR / "translate_finding.md").read_text(encoding="utf-8")
        for i, item in enumerate(verified, 1):
            finding = item["finding"]
            if not needs_translation(finding):
                continue
            source = finding_language(finding)
            target = "en" if source == "zh" else "zh"
            print(f"[pipeline] translating {i}/{len(verified)} {source}->{target}", file=sys.stderr)
            name = LANGUAGE_NAMES[target]
            try:
                parsed = call_llm_cached(
                    provider, model,
                    build_translate_prompt(translate_template, finding, target),
                    parse=lambda raw, t=target: parse_translation(raw, t),
                    retry_hint=f"上一次输出没有翻译成{name},或者不是合法 JSON。"
                               f"请重新翻译,三个字段全部输出{name}。",
                )
                item["finding"] = apply_translation(finding, source, validate_translation(parsed, target))
            except Exception as e:
                print(f"[pipeline]   translation failed ({type(e).__name__}), keeping original", file=sys.stderr)
                item["finding"] = apply_translation(finding, source, None)

    on_status("reporting")
    try:
        result = render(verified, project_name, report_dir)
    except Exception as e:
        raise PipelineError(f"report rendering failed: {e}") from e

    on_status("done")
    return result
