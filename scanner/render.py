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
    is_failed = "verifier_failed" in (finding.get("reasoning") or "")
    filter_bucket = "failed" if is_failed else reachable
    badge_class = {"yes": "badge-yes", "no": "badge-no"}.get(reachable, "badge-uncertain")
    badge_label = "复核失败" if is_failed else html.escape(reachable)
    if is_failed:
        badge_class = "badge-failed"

    rule_ids = ", ".join(item.get("rule_ids", [item.get("rule_id", "")]))
    message = " / ".join(item.get("messages", [item.get("message", "")]))
    confidence = finding.get("confidence")

    return f"""
    <details class="card" data-bucket="{filter_bucket}">
      <summary>
        <span class="badge {badge_class}">{badge_label}</span>
        <span class="severity">{html.escape(item.get("severity") or "")}</span>
        <span class="location">{html.escape(item["sink_file"])}:{item["sink_line"]}</span>
        <span class="rule">{html.escape(rule_ids)}</span>
      </summary>
      <div class="card-body">
        <p><strong>规则说明:</strong> {html.escape(message)}</p>
        <p><strong>CWE:</strong> {html.escape(str(item.get("cwe") or "-"))}
           &nbsp;·&nbsp; <strong>Source:</strong> {html.escape(item["source_file"])}:{item["source_line"]}</p>
        {f'<p><strong>置信度:</strong> {html.escape(str(confidence))}</p>' if confidence is not None else ""}
        <p><strong>判断依据:</strong> {html.escape(finding.get("reasoning") or "")}</p>
        {f'<p><strong>攻击场景:</strong> {html.escape(finding.get("exploit_scenario") or "")}</p>' if finding.get("exploit_scenario") else ""}
      </div>
    </details>
    """


_STAT_CARDS = [
    ("total", "候选总数", "stat-total"),
    ("reachable", "可达 (yes)", "stat-yes"),
    ("not_reachable", "不可达 (no)", "stat-no"),
    ("uncertain", "不确定", "stat-uncertain"),
    ("verifier_failed", "复核失败", "stat-failed"),
]

_FILTERS = [
    ("all", "全部"),
    ("yes", "可达"),
    ("no", "不可达"),
    ("uncertain", "不确定"),
    ("failed", "复核失败"),
]


def render_html(verified: list[dict], project_name: str) -> str:
    summary = build_summary(verified)
    ordered = sorted(verified, key=_sort_key)
    cards = "\n".join(_card_html(item) for item in ordered)

    stat_cards = "\n".join(
        f'<div class="stat {cls}"><div class="stat-value">{summary[key]}</div><div class="stat-label">{label}</div></div>'
        for key, label, cls in _STAT_CARDS
    )
    filter_buttons = "\n".join(
        f'<button class="filter-btn{" active" if key == "all" else ""}" data-filter="{key}">{label}</button>'
        for key, label in _FILTERS
    )

    return f"""<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>扫描报告 — {html.escape(project_name)}</title>
<style>
  :root {{
    --bg: #f6f7f9;
    --surface: #ffffff;
    --border: #e3e5e9;
    --text: #1a1d23;
    --text-muted: #6b7280;
    --text-faint: #9ca3af;
    --primary: #2563eb;
    --primary-soft: #eff4ff;
    --success: #16803c;
    --success-soft: #ecfdf3;
    --danger: #d64545;
    --danger-soft: #fef2f2;
    --warning: #b45309;
    --warning-soft: #fffbeb;
    --neutral: #4b5563;
    --neutral-soft: #f3f4f6;
    --radius: 10px;
    --shadow: 0 1px 2px rgba(16, 24, 40, 0.04), 0 1px 3px rgba(16, 24, 40, 0.06);
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0f1115;
      --surface: #171a21;
      --border: #2a2e37;
      --text: #e8eaed;
      --text-muted: #9aa1ac;
      --text-faint: #6b7280;
      --primary: #5b8def;
      --primary-soft: #16233d;
      --success: #34d399;
      --success-soft: #0f2b21;
      --danger: #f27272;
      --danger-soft: #3a1719;
      --warning: #fbbf24;
      --warning-soft: #3a2a0d;
      --neutral: #9aa1ac;
      --neutral-soft: #20242c;
      --shadow: 0 1px 2px rgba(0, 0, 0, 0.3), 0 1px 3px rgba(0, 0, 0, 0.3);
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    max-width: 920px;
    margin: 0 auto;
    padding: 2.5rem 1.25rem 4rem;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  h1 {{ font-size: 1.5rem; font-weight: 650; margin: 0 0 1.5rem; letter-spacing: -0.01em; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.7rem; margin-bottom: 1.5rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.85rem 1rem; box-shadow: var(--shadow); }}
  .stat-value {{ font-size: 1.5rem; font-weight: 700; line-height: 1.2; }}
  .stat-label {{ font-size: 0.78rem; color: var(--text-muted); margin-top: 0.15rem; }}
  .stat-yes .stat-value {{ color: var(--danger); }}
  .stat-no .stat-value {{ color: var(--success); }}
  .stat-uncertain .stat-value {{ color: var(--warning); }}
  .stat-failed .stat-value {{ color: var(--text-faint); }}
  .filters {{ display: flex; gap: 0.4rem; margin-bottom: 1rem; flex-wrap: wrap; }}
  .filter-btn {{
    font-family: inherit; font-size: 0.8rem; font-weight: 600; cursor: pointer;
    padding: 0.35rem 0.8rem; border-radius: 999px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text-muted);
  }}
  .filter-btn.active {{ background: var(--primary); border-color: var(--primary); color: #fff; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 0.6rem; padding: 0.5rem 0.9rem; box-shadow: var(--shadow); }}
  .card[data-hidden] {{ display: none; }}
  .card summary {{ cursor: pointer; display: flex; gap: 0.6rem; align-items: center; padding: 0.5rem 0; list-style: none; flex-wrap: wrap; }}
  .card summary::-webkit-details-marker {{ display: none; }}
  .card-body {{ padding: 0.6rem 0.2rem 0.5rem; line-height: 1.7; border-top: 1px solid var(--border); margin-top: 0.3rem; }}
  .card-body p {{ margin: 0.4rem 0; font-size: 0.88rem; }}
  .badge {{ font-size: 0.75rem; font-weight: 600; padding: 0.15rem 0.55rem; border-radius: 999px; color: #fff; }}
  .badge-yes {{ background: var(--danger); }}
  .badge-no {{ background: var(--success); }}
  .badge-uncertain {{ background: var(--warning); }}
  .badge-failed {{ background: var(--neutral); }}
  .severity {{ font-size: 0.75rem; color: var(--text-muted); }}
  .location {{ font-family: ui-monospace, monospace; font-size: 0.85rem; }}
  .rule {{ font-size: 0.8rem; color: var(--text-faint); margin-left: auto; }}
  .empty-state {{ text-align: center; color: var(--text-faint); padding: 3rem 0; font-size: 0.9rem; }}
</style>
</head>
<body>
  <h1>扫描报告 — {html.escape(project_name)}</h1>
  <div class="summary">
    {stat_cards}
  </div>
  <div class="filters">
    {filter_buttons}
  </div>
  <div id="card-list">
    {cards if cards.strip() else '<p class="empty-state">没有候选发现</p>'}
  </div>
  <p id="empty-filter" class="empty-state" style="display:none">没有匹配这个筛选条件的发现</p>
<script>
  const cards = Array.from(document.querySelectorAll('.card'));
  const buttons = Array.from(document.querySelectorAll('.filter-btn'));
  const emptyMsg = document.getElementById('empty-filter');
  buttons.forEach((btn) => {{
    btn.addEventListener('click', () => {{
      buttons.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.filter;
      let visible = 0;
      cards.forEach((card) => {{
        const show = filter === 'all' || card.dataset.bucket === filter;
        if (show) {{ card.removeAttribute('data-hidden'); visible++; }}
        else card.setAttribute('data-hidden', '');
      }});
      emptyMsg.style.display = visible === 0 ? 'block' : 'none';
    }});
  }});
</script>
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
