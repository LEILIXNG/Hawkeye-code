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
)
from scanner.callgraph import index_workspace
from scanner.core import build_context, build_prompt, dedup, normalize, run_semgrep
from scanner.ingest import safe_extract
from scanner.render import render
from scanner.verify import call_llm

DEFAULT_CONFIGS = load_default_configs()
EXCLUDED_RULES = load_excluded_rules()
EXCLUDED_PATHS = load_excluded_paths()


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
        candidates = dedup(normalize(raw, workspace_dir))
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

    on_status("reporting")
    try:
        result = render(verified, project_name, report_dir)
    except Exception as e:
        raise PipelineError(f"report rendering failed: {e}") from e

    on_status("done")
    return result
