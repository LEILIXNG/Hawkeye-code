"""Orchestrates A -> B -> C -> E -> G for the Phase 1 API.

Kept intentionally synchronous (called from a FastAPI BackgroundTasks
worker, one scan at a time) per docs/framework.md's "单用户同一时刻通常只
跑一个扫描" simplification — no distributed queue.
"""
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
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


def verify_all(candidates, workspace_dir, index, template, provider, model, concurrency: int = 1):
    """The verify stage, `concurrency` calls in flight at a time.

    Threads rather than asyncio: the work is one blocking HTTP call per
    candidate through a provider SDK this project does not control, and the
    context building around it is file IO. Nothing here is CPU-bound, so the
    GIL is not what limits it.

    executor.map keeps the results in candidate order -- the report sorts by
    verdict later, but a scan that shuffled its findings run to run would
    make two reports of the same code impossible to diff. It also re-raises
    the first exception, which keeps the existing contract that one hard
    failure (a 429, say) ends the scan rather than yielding a report with
    silent holes in it.
    """
    def verify_one(candidate):
        code_context = build_context(workspace_dir, candidate, index)
        prompt = build_prompt(template, candidate, code_context)
        return {**candidate, "finding": call_llm(provider, model, prompt)}

    total = len(candidates)
    if concurrency <= 1:
        verified = []
        for i, candidate in enumerate(candidates, 1):
            print(f"[pipeline] verifying {i}/{total}", file=sys.stderr)
            verified.append(verify_one(candidate))
        return verified

    print(f"[pipeline] verifying {total} candidates, {concurrency} at a time", file=sys.stderr)
    done = 0
    lock = Lock()

    def verify_and_count(candidate):
        result = verify_one(candidate)
        nonlocal done
        with lock:
            done += 1
            print(f"[pipeline] verifying {done}/{total}", file=sys.stderr)
        return result

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        return list(pool.map(verify_and_count, candidates))


def run_pipeline(
    zip_path: Path,
    workspace_dir: Path,
    report_dir: Path,
    project_name: str,
    provider,
    model: str,
    on_status: Callable[[str], None] = lambda status: None,
    translate: bool = True,
    concurrency: int = 1,
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

    # Its own stage rather than the first thing the verify stage does: this
    # is a tree-sitter parse of every .java file in the workspace, and while
    # it runs no LLM call has been made yet. Folded into "verifying" it read
    # as a scan stuck on its first finding -- 2s on a 162-file project, but
    # it scales with the repo, not with the number of findings.
    on_status("indexing")
    try:
        # Built once per scan: doing it per candidate would repeat the whole
        # parse for every finding.
        index = index_workspace(workspace_dir)
    except Exception as e:
        raise PipelineError(f"call graph failed: {e}") from e

    on_status("verifying")
    template = (PROMPTS_DIR / "verify_taint.md").read_text(encoding="utf-8")
    try:
        verified = verify_all(candidates, workspace_dir, index, template, provider, model, concurrency)
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
