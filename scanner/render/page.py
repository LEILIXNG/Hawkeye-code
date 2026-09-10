"""G: assemble report.html and report.json from a verified-candidates list.

Phase 1 skips a separate narrate.py LLM pass (framework.md's stage F) --
scanner/verify.py's `reasoning` / `exploit_scenario` fields already give a
human-readable explanation per finding, which is enough for a first
reportable output. A dedicated "batch-generate polished writeup" pass can
be added later without touching this stage's inputs.

This module is only page structure: the card, the facet columns, the CSS
and the script each live in their own module beside it.
"""
import html
import json
from collections import Counter
from pathlib import Path

from scanner.common import write_json
from scanner.report_i18n import DEFAULT_LANG, REPORT_I18N
from scanner.render.cards import _card_html
from scanner.render.facets import FACET_PAGE_SIZE, _facet_col_html, _facet_counts
from scanner.render.script import report_script
from scanner.render.styles import REPORT_CSS
from scanner.render.verdicts import (RISK_LEVELS, _sort_key, build_summary, risk_level,
                                     vuln_type_label, with_scores)


_STAT_CARDS = [
    ("total", "stats.total", "stat-total"),
    ("reachable", "stats.reachable", "stat-yes"),
    ("not_reachable", "stats.safe", "stat-no"),
    ("needs_review", "stats.needsReview", "stat-uncertain"),
]

_FILTERS = [
    ("all", "filters.all"),
    ("yes", "filters.yes"),
    ("no", "filters.no"),
    ("uncertain", "filters.uncertain"),
    ("failed", "filters.failed"),
]



def render_html(verified: list[dict], project_name: str) -> str:
    summary = build_summary(verified)
    ordered = sorted(verified, key=_sort_key)
    cards = "\n".join(_card_html(item) for item in ordered)
    total = len(verified)

    stat_values = {**summary, "needs_review": summary["uncertain"] + summary["verifier_failed"]}
    stat_cards = "\n".join(
        f'<div class="stat {cls}"><div class="stat-value">{stat_values[key]}</div>'
        f'<div class="stat-label" data-i18n="{label_key}"></div></div>'
        for key, label_key, cls in _STAT_CARDS
    )
    filter_buttons = "\n".join(
        f'<button class="filter-btn{" active" if key == "all" else ""}" data-filter="{key}" data-i18n="{label_key}"></button>'
        for key, label_key in _FILTERS
    )

    type_counts = _facet_counts(verified, vuln_type_label)
    file_counts = _facet_counts(verified, lambda i: i["sink_file"])
    # Fixed scale order, and levels nothing landed in are dropped rather
    # than shown as "低危 (0)".
    risk_tally = Counter(risk_level(item) for item in verified)
    severity_counts = [(level, risk_tally[level]) for level in RISK_LEVELS if risk_tally[level]]

    facets_html = "".join([
        _facet_col_html("type", type_counts, total),
        _facet_col_html("file", file_counts, total,
                        label_fn=lambda v: html.escape(v.replace(chr(92), "/").rsplit("/", 1)[-1]),
                        page_size=FACET_PAGE_SIZE),
        _facet_col_html("severity", severity_counts, total,
                        label_fn=lambda v: f'<span data-i18n="risk.{v}"></span>'),
    ])

    i18n_json = json.dumps(REPORT_I18N, ensure_ascii=False)
    project_json = json.dumps(project_name, ensure_ascii=False)
    default_lang_json = json.dumps(DEFAULT_LANG)

    return f"""<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>扫描报告 — {html.escape(project_name)}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
  <header class="page-head">
    <h1><span data-i18n="reportTitle"></span> — {html.escape(project_name)}</h1>
    <button id="lang-toggle" type="button"></button>
  </header>
  <div class="summary">
    {stat_cards}
  </div>
  <div class="filters">
    {filter_buttons}
    <button id="toggle-all" class="filter-btn" type="button" data-i18n="actions.expandAll"></button>
  </div>
  <div class="facets">
    {facets_html}
  </div>
  <div id="card-list">
    {cards if cards.strip() else '<p class="empty-state" data-i18n="empty.noFindings"></p>'}
  </div>
  <p id="empty-filter" class="empty-state" data-i18n="empty.noMatch" style="display:none"></p>
<script>{report_script(i18n_json, project_json, default_lang_json)}</script>
</body>
</html>
"""



def render(verified: list[dict], project_name: str, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html"
    json_path = out_dir / "report.json"

    html_path.write_text(render_html(verified, project_name), encoding="utf-8")
    write_json(json_path, {"project": project_name, "summary": build_summary(verified),
                           "findings": [with_scores(item) for item in verified]})

    return {"html_path": str(html_path), "json_path": str(json_path), "summary": build_summary(verified)}
