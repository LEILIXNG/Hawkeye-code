"""
Per-rule hit statistics over the reports in data/reports/.

Not a pipeline stage -- an analysis tool for deciding what belongs in
rules/ruleset.yml's `exclude_rules`. The aggregation logic lives in
scanner/rule_stats.py so it can be unit tested; this file is a thin CLI.

Usage:
    python scripts/rule_stats.py
    python scripts/rule_stats.py --noise-only
    python scripts/rule_stats.py --json > data/rule_stats.json
    python scripts/rule_stats.py --candidates data/candidates.json
"""
import argparse
import json
import sys
from pathlib import Path

from common import CANDIDATES_PATH, REPORTS_DIR  # noqa: F401
from scanner.rule_stats import (
    aggregate,
    format_table,
    load_candidates,
    load_report_findings,
    noise_candidates,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reports", default=str(REPORTS_DIR), help="Directory holding <scan_id>/report.json")
    parser.add_argument(
        "--candidates", default=None,
        help=f"Also count an unverified candidates file, e.g. {CANDIDATES_PATH} "
             "(written by scripts/01_scan.py, which makes no LLM calls)",
    )
    parser.add_argument("--noise-only", action="store_true", help="Only rules that never produced a reachable finding")
    parser.add_argument("--json", action="store_true", help="Emit rows as JSON instead of a table")
    args = parser.parse_args()

    reports_dir = Path(args.reports)
    findings = load_report_findings(reports_dir)
    if args.candidates:
        findings += load_candidates(Path(args.candidates))
    rows = aggregate(findings)
    if args.noise_only:
        rows = noise_candidates(rows)

    source = f"{reports_dir}" + (f" + {args.candidates}" if args.candidates else "")
    print(f"[rule_stats] {len(findings)} findings from {source}", file=sys.stderr)
    print(f"[rule_stats] {len(rows)} rules", file=sys.stderr)

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print(format_table(rows) if rows else "(no rules matched)")


if __name__ == "__main__":
    main()
