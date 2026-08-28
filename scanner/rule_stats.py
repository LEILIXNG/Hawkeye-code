"""Per-rule hit statistics over the reports accumulated in data/reports/.

Answers "which rules are actually earning their keep": every candidate a
rule produces costs one LLM verify call -- wall-clock time, and rate-limit
budget on the free-tier endpoints this project is normally pointed at -- so
a rule that fires steadily and has never once come back reachable is a
candidate for ruleset.yml's `exclude_rules`.

Attribution caveat: candidates are deduped by (source, sink) before
verification, and one deduped candidate can carry several rule_ids. The
verdict belongs to the merged candidate, not to any single rule, so a
finding is counted once for *each* rule that hit it. Rules that mostly fire
alongside others will therefore look busier than they are -- check
`solo_hits` (hits where that rule was the only one to match) before acting
on a rule with a low `yes` count.
"""
import json
from pathlib import Path

from scanner.render import verdict_of

# "unverified" is not a verdict the LLM produces -- it is what a candidate
# from data/candidates.json has, i.e. semgrep ran but the verify stage has
# not. Keeping it as its own bucket means a semgrep-only scan, which makes
# no LLM calls at all, can answer "which rules fire, how often" without
# inflating the uncertain column with candidates nobody has judged.
VERDICTS = ("yes", "no", "uncertain", "failed", "unverified")


def load_report_findings(reports_dir: Path) -> list[dict]:
    """Every finding from every data/reports/*/report.json, tagged with the
    report it came from so per-rule scan counts stay honest."""
    findings = []
    for report_path in sorted(reports_dir.glob("*/report.json")):
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for finding in report.get("findings", []):
            findings.append({**finding, "_report_id": report_path.parent.name})
    return findings


def load_candidates(candidates_path: Path) -> list[dict]:
    """Candidates straight out of the scan stage (scripts/01_scan.py), with
    no verdicts attached -- produced without a single LLM call."""
    try:
        return json.loads(candidates_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def rule_ids_of(finding: dict) -> list[str]:
    ids = finding.get("rule_ids") or ([finding["rule_id"]] if finding.get("rule_id") else [])
    return [i for i in ids if i]


def aggregate(findings: list[dict]) -> list[dict]:
    """One row per rule id, sorted by hits desc then id, so the noisiest
    rules come first."""
    stats: dict[str, dict] = {}
    for finding in findings:
        ids = rule_ids_of(finding)
        verdict = verdict_of(finding) if finding.get("finding") else "unverified"
        for rule_id in ids:
            row = stats.setdefault(
                rule_id,
                {"rule_id": rule_id, "hits": 0, "solo_hits": 0, "reports": set(), **{v: 0 for v in VERDICTS}},
            )
            row["hits"] += 1
            row[verdict] += 1
            if len(ids) == 1:
                row["solo_hits"] += 1
            if finding.get("_report_id"):
                row["reports"].add(finding["_report_id"])

    rows = [{**row, "reports": len(row["reports"])} for row in stats.values()]
    return sorted(rows, key=lambda r: (-r["hits"], r["rule_id"]))


def noise_candidates(rows: list[dict]) -> list[dict]:
    """Rules that have fired on their own at least once, have been through
    verification at least once, and have never produced a reachable
    finding. The verified-at-least-once condition matters: a rule seen only
    in unverified candidates has no evidence either way, and excluding it
    would be guessing."""
    return [
        r for r in rows
        if r["yes"] == 0 and r["solo_hits"] > 0 and (r["hits"] - r["unverified"]) > 0
    ]


def format_table(rows: list[dict]) -> str:
    header = f"{'hits':>5} {'solo':>5} {'yes':>4} {'no':>4} {'unc':>4} {'fail':>4} {'unver':>6} {'rpts':>5}  rule_id"
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(
            f"{r['hits']:>5} {r['solo_hits']:>5} {r['yes']:>4} {r['no']:>4} "
            f"{r['uncertain']:>4} {r['failed']:>4} {r['unverified']:>6} {r['reports']:>5}  {r['rule_id']}"
        )
    return "\n".join(lines)
