"""
Phase 0 / Step 1: run Semgrep against a target repo and normalize the raw
JSON output into a flat list of Candidate dicts, matching the data model
described in docs/framework.md section 2.

The actual scan/normalize/dedup logic lives in scanner/core.py (importable
by apps/api too); this file is now a thin CLI wrapper around it.

Usage:
    python scripts/01_scan.py --target /path/to/repo
    python scripts/01_scan.py --target /path/to/repo --config p/java,p/owasp-top-ten
"""
import argparse
from pathlib import Path

from common import (
    CANDIDATES_PATH,
    ensure_data_dir,
    load_default_configs,
    load_excluded_paths,
    load_excluded_rules,
    write_json,
)
from scanner.core import dedup, dedup_copies, extract_source_location, normalize, relpath, run_semgrep  # noqa: F401

DEFAULT_CONFIGS = load_default_configs()
EXCLUDED_RULES = load_excluded_rules()
EXCLUDED_PATHS = load_excluded_paths()


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

    raw = run_semgrep(target, configs, EXCLUDED_RULES, EXCLUDED_PATHS)
    candidates = normalize(raw, target)
    deduped = dedup_copies(dedup(candidates), target)

    write_json(Path(args.out), deduped)
    print(f"[scan] {len(candidates)} raw findings -> {len(deduped)} deduped candidates")
    print(f"[scan] wrote {args.out}")


if __name__ == "__main__":
    main()
