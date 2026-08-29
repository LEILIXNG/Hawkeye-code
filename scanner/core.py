"""Importable core of the A/B/C/E scan stages.

This is the same logic that used to live directly inside scripts/01_scan.py
and scripts/02_verify.py. It moved here so apps/api can import it as a
normal module (numbered scripts aren't valid `import` names) without
duplicating the parsing logic. scripts/01_scan.py and scripts/02_verify.py
now just re-export these functions so they keep working as standalone CLIs
and the existing tests (which load them by file path) keep passing.
"""
import json
import os
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

from scanner.common import sha256

# Re-exported so `from scanner.core import build_context` keeps working for
# pipeline.py, scripts/02_verify.py and the tests that load them by path.
from scanner.context import (  # noqa: F401
    CONTEXT_WINDOW,
    build_caller_context,
    build_context,
    build_prompt,
    read_window,
)

# Windows refuses to open a path of 260 characters or more unless the
# process opts into long paths, and semgrep does not: it reports such files
# as neither scanned, skipped nor errored -- they simply are not there.
# Measured on the VulnerableApp zip extracted under a long temp path: the
# longest path semgrep scanned was 257 characters, the shortest it silently
# dropped was 260, and the scan came back 29 candidates instead of 44 with
# all ten SQL injection findings among the missing. A security scanner that
# quietly stops looking at a third of the code is worse than one that
# fails, so this is checked before the scan rather than hoped about.
WINDOWS_MAX_PATH = 260

# Directory names semgrep 1.173.0 ignores without being asked (measured, see
# rules/ruleset.yml's exclude_paths note). Files under these are already out
# of the scan, so a too-long path there costs nothing and must not fail the
# run -- an uploaded project's build/ output is the common case. semgrep has
# an --x-ls flag that would answer this exactly, but it is documented as
# internal and subject to change, so this mirrors the measurement instead.
SEMGREP_DEFAULT_IGNORED_DIRS = frozenset(
    {"build", "dist", "node_modules", "vendor", "test", "tests", ".venv"}
)


def long_paths(
    target: Path,
    exclude_paths: list[str] | None = None,
    limit: int = WINDOWS_MAX_PATH,
) -> list[Path]:
    """Files under `target` that Windows cannot open by path, ignoring the
    ones no scan would have looked at anyway.

    Always empty off Windows, where the limit does not apply.
    """
    if os.name != "nt":
        return []

    globs = [g.removeprefix("**/") for g in (exclude_paths or [])]
    found = []
    for path in target.rglob("*"):
        if not path.is_file() or len(str(path)) < limit:
            continue
        parts = path.relative_to(target).parts
        if SEMGREP_DEFAULT_IGNORED_DIRS.intersection(parts[:-1]):
            continue
        # Matches how semgrep reads these: a bare name is a directory at any
        # depth, a multi-segment glob is a run of consecutive directories,
        # and a *.ext glob is a filename pattern.
        dirs = "/" + "/".join(parts[:-1]) + "/"
        if any(
            fnmatch(path.name, g) if g.startswith("*.")
            else (f"/{g}/" in dirs if "/" in g else g in parts[:-1])
            for g in globs
        ):
            continue
        found.append(path)
    return sorted(found)


def run_semgrep(
    target: Path,
    configs: list[str],
    exclude_rules: list[str] | None = None,
    exclude_paths: list[str] | None = None,
) -> dict:
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
    # --exclude globs containing a slash are anchored to the scan root, so
    # ruleset.yml writes those as **/src/it; passed through verbatim here.
    for pattern in exclude_paths or []:
        cmd += ["--exclude", pattern]
    cmd.append(str(target))

    unreachable = long_paths(target, exclude_paths)
    if unreachable:
        longest = max(unreachable, key=lambda p: len(str(p)))
        raise SystemExit(
            f"{len(unreachable)} file(s) under {target} exceed Windows' {WINDOWS_MAX_PATH}-character "
            f"path limit and would be skipped without any warning from semgrep, making this scan "
            f"silently incomplete. Longest ({len(str(longest))} chars): {longest}. "
            f"Move the target (or this tool) somewhere with a shorter path and scan again."
        )

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


# Lines a copied-and-renamed Java module differs by, and the only ones the
# copy fingerprint is allowed to ignore. Everything else has to match byte
# for byte, so two files that merely share a name never collapse.
_COPY_IGNORED_PREFIXES = ("package ", "import ")


def _copy_fingerprint(target: Path, rel_path: str, cache: dict[str, str]) -> str:
    if rel_path not in cache:
        try:
            text = (Path(target) / rel_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Unreadable: fall back to the path itself so this candidate can
            # only ever match itself. Failing to read a file must not merge
            # two findings that might be unrelated.
            cache[rel_path] = f"path:{rel_path}"
        else:
            body = [
                line.rstrip()
                for line in text.splitlines()
                if not line.lstrip().startswith(_COPY_IGNORED_PREFIXES)
            ]
            cache[rel_path] = sha256("\n".join(body))
    return cache[rel_path]


def dedup_copies(candidates: list[dict], target: Path) -> list[dict]:
    """Merge candidates that are the same code shipped at two paths.

    Real Java repos carry the same module twice -- a service and its
    "-platform" fork, a vendored copy, a module renamed into a different
    package. Semgrep reports both, and dedup() above cannot merge them
    because its key is built from paths. The verify stage then spends two
    LLM calls on identical code and, at this project's measured ~16%
    run-to-run flip rate, frequently returns two different verdicts for it:
    on the vmscode corpus 8 of 72 candidates were copies, and 4 of those 8
    pairs disagreed with themselves. A report that judges the same lines
    both reachable and not reachable is worse than one that judges them
    once.

    The surviving candidate keeps the other paths in `duplicate_locations`
    so the report can still point at every copy -- this drops a verify call,
    never a location.

    Line numbers are part of the key, so two copies whose import blocks are
    different lengths simply will not collapse. That is deliberate: the
    fingerprint proves the files are the same, and the line number proves
    the finding is at the same place in them.
    """
    fingerprints: dict[str, str] = {}
    merged: dict[tuple, dict] = {}
    for c in candidates:
        key = (
            _copy_fingerprint(target, c["source_file"], fingerprints), c["source_line"],
            _copy_fingerprint(target, c["sink_file"], fingerprints), c["sink_line"],
            tuple(sorted(c.get("rule_ids") or [c.get("rule_id")])),
        )
        if key not in merged:
            merged[key] = {**c, "duplicate_locations": []}
        else:
            merged[key]["duplicate_locations"].append(c["sink_file"])
    return list(merged.values())


def parse_llm_json(raw_text: str) -> dict:
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    return json.loads(text.strip())
