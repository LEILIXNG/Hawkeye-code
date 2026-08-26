"""G: turn a verified-candidates list into report.html + report.json.

Phase 1 skips a separate narrate.py LLM pass (framework.md's stage F) —
scanner/verify.py's `reasoning` / `exploit_scenario` fields already give a
human-readable explanation per finding, which is enough for a first
reportable output. A dedicated "batch-generate polished writeup" pass can
be added later without touching this stage's inputs.
"""
import html
from pathlib import Path

from scanner.common import write_json

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
REACHABLE_ORDER = {"yes": 0, "uncertain": 1, "no": 2}


def _sort_key(item: dict):
    finding = item.get("finding") or {}
    return (
        REACHABLE_ORDER.get(finding.get("reachable"), 1),
        SEVERITY_ORDER.get(item.get("severity"), 3),
    )


def build_summary(verified: list[dict]) -> dict:
    summary = {"total": len(verified), "reachable": 0, "uncertain": 0, "not_reachable": 0, "verifier_failed": 0}
    for item in verified:
        finding = item.get("finding") or {}
        reachable = finding.get("reachable")
        if "verifier_failed" in (finding.get("reasoning") or ""):
            summary["verifier_failed"] += 1
        elif reachable == "yes":
            summary["reachable"] += 1
        elif reachable == "no":
            summary["not_reachable"] += 1
        else:
            summary["uncertain"] += 1
    return summary


def _card_html(item: dict) -> str:
    finding = item.get("finding") or {}
    reachable = finding.get("reachable", "uncertain")
    badge_class = {"yes": "badge-yes", "no": "badge-no"}.get(reachable, "badge-uncertain")

    rule_ids = ", ".join(item.get("rule_ids", [item.get("rule_id", "")]))
    message = " / ".join(item.get("messages", [item.get("message", "")]))

    return f"""
    <details class="card">
      <summary>
        <span class="badge {badge_class}">{html.escape(reachable)}</span>
        <span class="severity">{html.escape(item.get("severity") or "")}</span>
        <span class="location">{html.escape(item["sink_file"])}:{item["sink_line"]}</span>
        <span class="rule">{html.escape(rule_ids)}</span>
      </summary>
      <div class="card-body">
        <p><strong>规则说明:</strong> {html.escape(message)}</p>
        <p><strong>CWE:</strong> {html.escape(str(item.get("cwe") or "-"))}
           &nbsp;|&nbsp; <strong>Source:</strong> {html.escape(item["source_file"])}:{item["source_line"]}</p>
        <p><strong>置信度:</strong> {html.escape(str(finding.get("confidence", "-")))}</p>
        <p><strong>判断依据:</strong> {html.escape(finding.get("reasoning") or "")}</p>
        {f'<p><strong>攻击场景:</strong> {html.escape(finding.get("exploit_scenario") or "")}</p>' if finding.get("exploit_scenario") else ""}
      </div>
    </details>
    """


def render_html(verified: list[dict], project_name: str) -> str:
    summary = build_summary(verified)
    ordered = sorted(verified, key=_sort_key)
    cards = "\n".join(_card_html(item) for item in ordered)

    return f"""<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>扫描报告 — {html.escape(project_name)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; }}
  .summary {{ display: flex; gap: 1rem; margin: 1rem 0 2rem; flex-wrap: wrap; }}
  .summary div {{ background: #f4f4f5; border-radius: 8px; padding: 0.6rem 1rem; }}
  .card {{ border: 1px solid #e2e2e5; border-radius: 8px; margin-bottom: 0.6rem; padding: 0.4rem 0.8rem; }}
  .card summary {{ cursor: pointer; display: flex; gap: 0.6rem; align-items: center; padding: 0.4rem 0; }}
  .card-body {{ padding: 0.6rem 0.2rem 0.4rem; line-height: 1.6; }}
  .badge {{ font-size: 0.75rem; font-weight: 600; padding: 0.15rem 0.5rem; border-radius: 999px; color: #fff; }}
  .badge-yes {{ background: #d64545; }}
  .badge-no {{ background: #6b7280; }}
  .badge-uncertain {{ background: #d97706; }}
  .severity {{ font-size: 0.75rem; color: #6b7280; }}
  .location {{ font-family: monospace; font-size: 0.85rem; }}
  .rule {{ font-size: 0.8rem; color: #6b7280; margin-left: auto; }}
</style>
</head>
<body>
  <h1>扫描报告 — {html.escape(project_name)}</h1>
  <div class="summary">
    <div>候选总数: {summary["total"]}</div>
    <div>可达 (yes): {summary["reachable"]}</div>
    <div>不可达 (no): {summary["not_reachable"]}</div>
    <div>不确定: {summary["uncertain"]}</div>
    <div>复核失败: {summary["verifier_failed"]}</div>
  </div>
  {cards}
</body>
</html>
"""


def render(verified: list[dict], project_name: str, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html"
    json_path = out_dir / "report.json"

    html_path.write_text(render_html(verified, project_name), encoding="utf-8")
    write_json(json_path, {"project": project_name, "summary": build_summary(verified), "findings": verified})

    return {"html_path": str(html_path), "json_path": str(json_path), "summary": build_summary(verified)}
