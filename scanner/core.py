"""Importable core of the A/B/C/E scan stages.

This is the same logic that used to live directly inside scripts/01_scan.py
and scripts/02_verify.py. It moved here so apps/api can import it as a
normal module (numbered scripts aren't valid `import` names) without
duplicating the parsing logic. scripts/01_scan.py and scripts/02_verify.py
now just re-export these functions so they keep working as standalone CLIs
and the existing tests (which load them by file path) keep passing.
"""
import json
import subprocess
import sys
from pathlib import Path

from scanner.common import sha256


def run_semgrep(target: Path, configs: list[str], exclude_rules: list[str] | None = None) -> dict:
    # --no-git-ignore: semgrep's default is to enumerate files via `git
    # ls-files` when the target sits inside a git working tree, which
    # silently skips anything not tracked by git. That's exactly what
    # scanner/pipeline.py's data/workspaces/{scan_id}/ extraction dirs are
    # (data/ is gitignored, see .gitignore) -- without this flag every
    # Phase 1 API scan finds 0 results while the file is right there.
    cmd = ["semgrep", "--json", "--dataflow-traces", "--metrics=off", "--no-git-ignore"]
    for c in configs:
        cmd += ["--config", c]
    for rule_id in exclude_rules or []:
        cmd += ["--exclude-rule", rule_id]
    cmd.append(str(target))

    print(f"[scan] running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):  # semgrep exits 1 when findings exist
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"semgrep failed with exit code {proc.returncode}")
    return json.loads(proc.stdout)


def relpath(target: Path, abs_path: str) -> str:
    try:
        return str(Path(abs_path).resolve().relative_to(target.resolve()))
    except ValueError:
        return abs_path


def extract_source_location(result: dict, target: Path):
    """Pull the taint source location out of --dataflow-traces output, if present.

    Semgrep's --dataflow-traces JSON encodes taint_source as a tagged tuple:
    ["CliLoc", [{"path": ..., "start": {"line": ...}, ...}, "<var name>"]]
    (or ["ToCtx", [...]] in some rule shapes) -- not a plain {"location": ...}
    dict, which is easy to assume by reading the schema name alone.
    """
    trace = result.get("extra", {}).get("dataflow_trace")
    if not trace:
        return None
    source = trace.get("taint_source")
    if not source or not isinstance(source, list) or len(source) < 2:
        return None
    payload = source[1]
    if not isinstance(payload, list) or not payload:
        return None
    loc = payload[0]
    if not isinstance(loc, dict) or "start" not in loc:
        return None
    return {
        "file": relpath(target, loc.get("path", "")),
        "line": loc.get("start", {}).get("line"),
    }


def normalize(raw: dict, target: Path) -> list[dict]:
    candidates = []
    for result in raw.get("results", []):
        sink_file = relpath(target, result["path"])
        sink_line = result["start"]["line"]

        source_loc = extract_source_location(result, target)
        if source_loc and source_loc["line"] is not None:
            source_file, source_line = source_loc["file"], source_loc["line"]
            is_intraprocedural = source_file == sink_file
        else:
            # No dataflow trace available (plain pattern rule, not taint mode) —
            # treat the match location as both source and sink for now.
            source_file, source_line = sink_file, sink_line
            is_intraprocedural = True

        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        dedup_key = sha256(f"{source_file}:{source_line}:{sink_file}:{sink_line}")

        candidates.append({
            "rule_id": result.get("check_id"),
            "message": extra.get("message", "").strip(),
            "severity": extra.get("severity"),
            "cwe": metadata.get("cwe"),
            "owasp": metadata.get("owasp"),
            "source_file": source_file,
            "source_line": source_line,
            "sink_file": sink_file,
            "sink_line": sink_line,
            "dedup_key": dedup_key,
            "is_intraprocedural": is_intraprocedural,
        })
    return candidates


def dedup(candidates: list[dict]) -> list[dict]:
    """Merge candidates that share the same (source, sink) pair; keep every
    distinct rule_id that hit that pair instead of silently dropping any."""
    merged: dict[str, dict] = {}
    for c in candidates:
        key = c["dedup_key"]
        if key not in merged:
            merged[key] = {**c, "rule_ids": [c["rule_id"]], "messages": [c["message"]]}
        else:
            merged[key]["rule_ids"].append(c["rule_id"])
            merged[key]["messages"].append(c["message"])
    return list(merged.values())


CONTEXT_WINDOW = 15  # lines of code above/below each location to include


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
