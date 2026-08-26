"""
Phase 0 / Step 1: run Semgrep against a target repo and normalize the raw
JSON output into a flat list of Candidate dicts, matching the data model
described in docs/framework.md section 2.

Usage:
    python scripts/01_scan.py --target /path/to/repo
    python scripts/01_scan.py --target /path/to/repo --config p/java,p/owasp-top-ten
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from common import CANDIDATES_PATH, ROOT, ensure_data_dir, sha256, write_json

DEFAULT_CONFIGS = [
    "p/java",
    "p/security-audit",
    "p/owasp-top-ten",
    str(ROOT / "rules" / "custom"),  # project-specific rules the public registry misses
]


def run_semgrep(target: Path, configs: list[str]) -> dict:
    cmd = ["semgrep", "--json", "--dataflow-traces", "--metrics=off"]
    for c in configs:
        cmd += ["--config", c]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Path to the repo to scan")
    parser.add_argument(
        "--config", default=",".join(DEFAULT_CONFIGS),
        help="Comma-separated Semgrep config refs (registry short names or local paths)",
    )
    parser.add_argument("--out", default=str(CANDIDATES_PATH))
    args = parser.parse_args()

    ensure_data_dir()
    target = Path(args.target)
    configs = [c.strip() for c in args.config.split(",") if c.strip()]

    raw = run_semgrep(target, configs)
    candidates = normalize(raw, target)
    deduped = dedup(candidates)

    write_json(Path(args.out), deduped)
    print(f"[scan] {len(candidates)} raw findings -> {len(deduped)} deduped candidates")
    print(f"[scan] wrote {args.out}")


if __name__ == "__main__":
    main()
