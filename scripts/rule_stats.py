"""
Per-rule hit statistics over the reports in data/reports/.

Not a pipeline stage -- an analysis tool for deciding what belongs in
rules/ruleset.yml's `exclude_rules` and `exclude_paths`. The aggregation
logic lives in scanner/rule_stats.py so it can be unit tested; this file is
a thin CLI.

Start with --noise-clusters: it answers the question the plain per-rule
table cannot, which is whether a rule's noise is separable at all. A rule
that is useless everywhere and a rule that is useless in one file while
catching real bugs in the next both show up as "mediocre" in the per-rule
view, and they call for different knobs.

Usage:
    python scripts/rule_stats.py
    python scripts/rule_stats.py --noise-only
    python scripts/rule_stats.py --json > data/rule_stats.json
    python scripts/rule_stats.py --candidates data/candidates.json
    python scripts/rule_stats.py --by-file
    python scripts/rule_stats.py --noise-clusters
"""
import argparse
import json
import sys
from pathlib import Path

from common import CANDIDATES_PATH, REPORTS_DIR  # noqa: F401
from scanner.rule_stats import (
    aggregate,
    file_clusters,
    format_cluster_table,
    format_table,
    load_candidates,
    load_report_findings,
    noise_candidates,
    noise_clusters,
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
    parser.add_argument("--by-file", action="store_true", help="Break the same hits down per (rule, file)")
    parser.add_argument(
        "--noise-clusters", action="store_true",
        help="Only (rule, file) pairs that never came back reachable, tagged with which "
             "exclusion knob fits: rule-wide (exclude_rules) or file-only (exclude_paths)",
    )
    parser.add_argument("--json", action="store_true", help="Emit rows as JSON instead of a table")
    args = parser.parse_args()

    reports_dir = Path(args.reports)
    findings = load_report_findings(reports_dir)
    if args.candidates:
        findings += load_candidates(Path(args.candidates))
    clustered = args.by_file or args.noise_clusters
    if args.noise_clusters:
        rows = noise_clusters(findings)
    elif args.by_file:
        rows = file_clusters(findings)
    else:
        rows = aggregate(findings)
        if args.noise_only:
            rows = noise_candidates(rows)

    source = f"{reports_dir}" + (f" + {args.candidates}" if args.candidates else "")
    print(f"[rule_stats] {len(findings)} findings from {source}", file=sys.stderr)
    print(f"[rule_stats] {len(rows)} {'(rule, file) pairs' if clustered else 'rules'}", file=sys.stderr)

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    elif not rows:
        print("(nothing matched)")
    else:
        print(format_cluster_table(rows) if clustered else format_table(rows))


if __name__ == "__main__":
    main()
