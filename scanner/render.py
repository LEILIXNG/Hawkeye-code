"""G: turn a verified-candidates list into report.html + report.json.

Phase 1 skips a separate narrate.py LLM pass (framework.md's stage F) —
scanner/verify.py's `reasoning` / `exploit_scenario` fields already give a
human-readable explanation per finding, which is enough for a first
reportable output. A dedicated "batch-generate polished writeup" pass can
be added later without touching this stage's inputs.
"""
import html
import json
import re
from collections import Counter
from pathlib import Path

from scanner.common import write_json
from scanner.report_i18n import DEFAULT_LANG, REPORT_I18N

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
REACHABLE_ORDER = {"yes": 0, "uncertain": 1, "no": 2}

# Matches the short quoted name Semgrep tends to put at the end of a CWE
# description, e.g. "CWE-89: Improper Neutralization ... ('SQL Injection')".
_CWE_SHORT_NAME = re.compile(r"\('([^']+)'\)\s*$")


def _sort_key(item: dict):
    finding = item.get("finding") or {}
    return (
        REACHABLE_ORDER.get(finding.get("reachable"), 1),
        SEVERITY_ORDER.get(item.get("severity"), 3),
    )


VERDICT_SUMMARY_KEYS = {
    "yes": "reachable",
    "no": "not_reachable",
    "uncertain": "uncertain",
    "failed": "verifier_failed",
}


def verdict_of(item: dict) -> str:
    """Which bucket one verified candidate falls into: yes / no / uncertain
    / failed. A verifier failure is recorded in `reasoning` rather than in
    `reachable`, so it has to be checked first."""
    finding = item.get("finding") or {}
    if "verifier_failed" in (finding.get("reasoning") or ""):
        return "failed"
    reachable = finding.get("reachable")
    return reachable if reachable in ("yes", "no") else "uncertain"


def build_summary(verified: list[dict]) -> dict:
    summary = {"total": len(verified), "reachable": 0, "uncertain": 0, "not_reachable": 0, "verifier_failed": 0}
    for item in verified:
        summary[VERDICT_SUMMARY_KEYS[verdict_of(item)]] += 1
    return summary


def _cwe_text(item: dict) -> str | None:
    """A candidate's cwe field is a list of Semgrep's raw CWE strings in
    production (e.g. ["CWE-89: ... ('SQL Injection')"]), but a plain string
    in older fixtures/tests -- normalize both to one string."""
    cwe = item.get("cwe")
    if isinstance(cwe, list):
        return cwe[0] if cwe else None
    return cwe or None


def vuln_type_label(item: dict) -> str:
    """A short, human-readable vulnerability type for grouping/display --
    prefers the quoted short name Semgrep puts at the end of a CWE string
    ("SQL Injection"), falls back to the full CWE text, then to no-CWE."""
    text = _cwe_text(item)
    if not text:
        return "Uncategorized"
    match = _CWE_SHORT_NAME.search(text)
    return match.group(1) if match else text


def _sink_basename(item: dict) -> str:
    return item["sink_file"].replace("\\", "/").rsplit("/", 1)[-1]


def short_location(path: str, keep: int = 2) -> str:
    """The trailing `keep` segments of a path, with a leading ellipsis.

    A real project's sink paths run to 60+ characters of
    src/main/java/org/... that is identical across every finding, which in a
    collapsed card pushes the parts that actually differ off the end of the
    row. The full path stays on the row's title attribute and in the card
    body, so nothing is lost -- only the shared prefix is.
    """
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if len(parts) <= keep:
        return "/".join(parts)
    return ".../" + "/".join(parts[-keep:])


def _facet_counts(verified: list[dict], key_fn) -> list[tuple[str, int]]:
    counts = Counter(key_fn(item) for item in verified)
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _card_html(item: dict) -> str:
    finding = item.get("finding") or {}
    badge_key = filter_bucket = verdict_of(item)
    badge_class = {"yes": "badge-yes", "no": "badge-no", "failed": "badge-failed"}.get(badge_key, "badge-uncertain")

    rule_ids = ", ".join(item.get("rule_ids", [item.get("rule_id", "")]))
    message = " / ".join(item.get("messages", [item.get("message", "")]))
    confidence = finding.get("confidence")
    vuln_type = vuln_type_label(item)
    severity = item.get("severity") or "UNKNOWN"

    return f"""
    <details class="card" data-bucket="{filter_bucket}" data-type="{html.escape(vuln_type)}"
              data-file="{html.escape(item["sink_file"])}" data-severity="{html.escape(severity)}">
      <summary title="{html.escape(item["sink_file"])}:{item["sink_line"]}">
        <span class="badge {badge_class}" data-i18n="reachable.{badge_key}"></span>
        <span class="vuln-type">{html.escape(vuln_type)}</span>
        <span class="severity sev-{html.escape(severity)}">{html.escape(severity)}</span>
        <span class="location"><span class="loc-path">{html.escape(short_location(item["sink_file"]))}</span><span class="loc-line">:{item["sink_line"]}</span></span>
        <span class="rule" title="{html.escape(rule_ids)}">{html.escape(rule_ids)}</span>
      </summary>
      <div class="card-body">
        <p><strong data-i18n="card.type"></strong> {html.escape(vuln_type)}</p>
        <p><strong data-i18n="card.rule"></strong> {html.escape(message)}</p>
        <p><strong data-i18n="card.cwe"></strong> {html.escape(_cwe_text(item) or "-")}
           &nbsp;·&nbsp; <strong data-i18n="card.source"></strong> {html.escape(item["source_file"])}:{item["source_line"]}</p>
        {f'<p><strong data-i18n="card.confidence"></strong> {html.escape(str(confidence))}</p>' if confidence is not None else ""}
        {_duplicates_html(item)}
        <p><strong data-i18n="card.reasoning"></strong> {_bilingual(finding, "reasoning")}</p>
        {f'<p><strong data-i18n="card.exploit"></strong> {_bilingual(finding, "exploit_scenario")}</p>' if finding.get("exploit_scenario") else ""}
        {f'<p class="remediation"><strong data-i18n="card.remediation"></strong> {_bilingual(finding, "remediation")}</p>' if finding.get("remediation") else ""}
      </div>
    </details>
    """


def _bilingual(finding: dict, field: str) -> str:
    """A span carrying both languages of one LLM free-text field, swapped by
    the page's applyI18n() exactly like a data-i18n label.

    Falls back to the single original on both sides when 04_translate.py has
    not run, so an untranslated report renders precisely as it did before --
    the stage is optional and the reader should not be able to tell it was
    skipped except by the language not changing.
    """
    original = finding.get(field) or ""
    zh = finding.get(f"{field}_zh") or original
    en = finding.get(f"{field}_en") or original
    if not original:
        return ""
    return (f'<span data-text-zh="{html.escape(zh)}" data-text-en="{html.escape(en)}">'
            f'{html.escape(original)}</span>')


def _duplicates_html(item: dict) -> str:
    """The other paths carrying this exact code, when dedup_copies() merged
    a copied module. Verified once, but the reader still has to be told
    every place it lives, or the merge reads as a missing finding."""
    paths = item.get("duplicate_locations") or []
    if not paths:
        return ""
    joined = ", ".join(html.escape(p) for p in paths)
    return f'<p><strong data-i18n="card.duplicates"></strong> {joined}</p>'


# (summary key, i18n key, css class) and (filter bucket, i18n key) -- the
# visible text is filled in by the page's own applyI18n(), not here.
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


# How many facet values a paginated column shows before "show more". Only
# the file column uses it -- a real project has one entry per file with a
# finding, which is far more than the handful of vulnerability types or the
# three severities.
FACET_PAGE_SIZE = 8


def _facet_list_html(facet_name: str, counts: list[tuple[str, int]], total: int, label_fn=html.escape,
                     page_size: int | None = None) -> str:
    items = [
        f'<button class="facet-item active" data-facet="{facet_name}" data-value="">'
        f'<span data-i18n="facet.all"></span> ({total})</button>'
    ]
    for index, (value, count) in enumerate(counts):
        beyond_page = page_size is not None and index >= page_size
        items.append(
            f'<button class="facet-item{" hidden" if beyond_page else ""}" data-facet="{facet_name}"'
            f' data-value="{html.escape(value)}" title="{html.escape(value)}">'
            f'{label_fn(value)} ({count})</button>'
        )
    return "\n".join(items)


def _facet_col_html(facet_name: str, counts: list[tuple[str, int]], total: int, label_fn=html.escape,
                    page_size: int | None = None) -> str:
    """One facet column. The "show more" button sits outside .facet-list so
    it stays put instead of scrolling away with the items it reveals."""
    more = ""
    if page_size is not None and len(counts) > page_size:
        more = (f'<button class="facet-more" type="button" data-facet-more="{facet_name}">'
                f'<span data-i18n="facet.more"></span> <span class="more-count"></span></button>')
    return f"""
    <div class="facet-col">
      <h3 data-i18n="facet.{facet_name}"></h3>
      <div class="facet-list">{_facet_list_html(facet_name, counts, total, label_fn, page_size)}</div>
      {more}
    </div>
    """


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
    severity_counts = _facet_counts(verified, lambda i: i.get("severity") or "UNKNOWN")

    facets_html = "".join([
        _facet_col_html("type", type_counts, total),
        _facet_col_html("file", file_counts, total,
                        label_fn=lambda v: html.escape(v.replace(chr(92), "/").rsplit("/", 1)[-1]),
                        page_size=FACET_PAGE_SIZE),
        _facet_col_html("severity", severity_counts, total),
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
    max-width: 1080px;
    margin: 0 auto;
    padding: 2.5rem 1.25rem 4rem;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  h1 {{ font-size: 1.5rem; font-weight: 650; margin: 0; letter-spacing: -0.01em; }}
  .page-head {{ display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 1.5rem; }}
  #lang-toggle {{
    font-family: inherit; font-size: 0.78rem; font-weight: 600; cursor: pointer; flex-shrink: 0;
    padding: 0.3rem 0.8rem; border-radius: 999px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text-muted);
  }}
  #lang-toggle:hover {{ border-color: var(--text-faint); }}
  h3 {{ font-size: 0.8rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.03em; margin: 0 0 0.5rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.7rem; margin-bottom: 1.5rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.85rem 1rem; box-shadow: var(--shadow); }}
  .stat-value {{ font-size: 1.5rem; font-weight: 700; line-height: 1.2; }}
  .stat-label {{ font-size: 0.78rem; color: var(--text-muted); margin-top: 0.15rem; }}
  .stat-yes .stat-value {{ color: var(--danger); }}
  .stat-no .stat-value {{ color: var(--success); }}
  .stat-uncertain .stat-value {{ color: var(--warning); }}
  .filters {{ display: flex; gap: 0.4rem; margin-bottom: 1.2rem; flex-wrap: wrap; }}
  .filter-btn {{
    font-family: inherit; font-size: 0.8rem; font-weight: 600; cursor: pointer;
    padding: 0.35rem 0.8rem; border-radius: 999px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text-muted);
  }}
  .filter-btn.active {{ background: var(--primary); border-color: var(--primary); color: #fff; }}
  .facets {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
  .facet-col {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.9rem 1rem; box-shadow: var(--shadow); }}
  .facet-list {{ display: flex; flex-direction: column; gap: 0.15rem; max-height: 220px; overflow-y: auto; }}
  .facet-item {{
    font-family: inherit; font-size: 0.82rem; text-align: left; cursor: pointer;
    padding: 0.35rem 0.5rem; border-radius: 6px; border: none; background: none; color: var(--text);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .facet-item:hover {{ background: var(--bg); }}
  .facet-item.active {{ background: var(--primary-soft); color: var(--primary); font-weight: 600; }}
  .facet-item.hidden {{ display: none; }}
  .facet-more {{
    font-family: inherit; font-size: 0.78rem; font-weight: 600; cursor: pointer;
    margin-top: 0.4rem; padding: 0.3rem 0; border: none; background: none;
    color: var(--primary); text-align: left; width: 100%;
  }}
  .facet-more .more-count {{ color: var(--text-faint); font-weight: 400; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 0.6rem; padding: 0.5rem 0.9rem; box-shadow: var(--shadow); }}
  .card[data-hidden] {{ display: none; }}
  /* nowrap, not wrap: a long vulnerability type used to push the rule id
     onto a second line, so rows silently doubled in height depending on how
     wordy their CWE name was. Everything that can lose characters without
     losing meaning (the path, the rule id) ellipsises instead. */
  .card summary {{ cursor: pointer; display: flex; gap: 0.6rem; align-items: center; padding: 0.5rem 0; list-style: none; flex-wrap: nowrap; }}
  .card summary > .badge, .card summary > .vuln-type, .card summary > .severity {{ flex-shrink: 0; }}
  .card summary::-webkit-details-marker {{ display: none; }}
  .card-body {{ padding: 0.6rem 0.2rem 0.5rem; line-height: 1.7; border-top: 1px solid var(--border); margin-top: 0.3rem; }}
  .card-body p {{ margin: 0.4rem 0; font-size: 0.88rem; }}
  .card-body p.remediation {{ border-left: 3px solid var(--primary); padding: 0.35rem 0 0.35rem 0.6rem;
                              background: var(--primary-soft); border-radius: 0 4px 4px 0; }}
  .badge {{ font-size: 0.75rem; font-weight: 600; padding: 0.15rem 0.55rem; border-radius: 999px; color: #fff; }}
  .badge-yes {{ background: var(--danger); }}
  .badge-no {{ background: var(--success); }}
  .badge-uncertain {{ background: var(--warning); }}
  .badge-failed {{ background: var(--neutral); }}
  .vuln-type {{ font-size: 0.82rem; font-weight: 650; }}
  .severity {{
    font-size: 0.68rem; font-weight: 700; letter-spacing: 0.03em;
    padding: 0.1rem 0.4rem; border-radius: 4px;
    background: var(--neutral-soft); color: var(--neutral);
  }}
  .sev-ERROR {{ background: var(--danger-soft); color: var(--danger); }}
  .sev-WARNING {{ background: var(--warning-soft); color: var(--warning); }}
  /* The line number is split out and pinned so it survives the ellipsis:
     several findings can share one file and differ only by line, and
     truncating "File.java:118" down to "File.java:..." makes those rows
     indistinguishable -- exactly the information the row exists to carry. */
  .location {{ display: flex; min-width: 0; font-family: ui-monospace, monospace; font-size: 0.82rem; color: var(--text-muted); }}
  .loc-path {{ min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .loc-line {{ flex-shrink: 0; }}
  /* Capped and ellipsised rather than wrapped: a long rule id used to push
     itself onto a second line and double the height of every collapsed row.
     The full id is on the element's title. */
  .rule {{
    font-size: 0.78rem; color: var(--text-faint); margin-left: auto;
    max-width: 40%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }}
  #toggle-all {{ margin-left: auto; }}
  .empty-state {{ text-align: center; color: var(--text-faint); padding: 3rem 0; font-size: 0.9rem; }}
</style>
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
<script>
  const I18N = {i18n_json};
  const PROJECT = {project_json};
  const langToggle = document.getElementById('lang-toggle');

  // Shares the tool page's storage key, so a language picked there carries
  // over to reports opened from it. Reading it throws when the report is
  // opened straight off disk in some browsers -- fall back to the default.
  let lang = {default_lang_json};
  try {{ lang = localStorage.getItem('hawkeye-lang') || lang; }} catch (err) {{}}
  if (!I18N[lang]) lang = {default_lang_json};

  const t = (path) => path.split('.').reduce((o, k) => (o ? o[k] : undefined), I18N[lang]);

  function applyI18n() {{
    document.documentElement.lang = lang;
    document.title = t('reportTitle') + ' — ' + PROJECT;
    document.querySelectorAll('[data-i18n]').forEach((el) => {{
      const val = t(el.dataset.i18n);
      if (typeof val === 'string') el.textContent = val;
    }});
    langToggle.textContent = t('langToggle');
    // The LLM's own prose, carried in both languages by scanner/translate.py.
    // Untranslated findings hold the same text in both attributes, so this
    // is a no-op for them rather than a blank.
    document.querySelectorAll('[data-text-zh]').forEach((el) => {{
      const val = lang === 'zh' ? el.dataset.textZh : el.dataset.textEn;
      if (typeof val === 'string') el.textContent = val;
    }});
  }}

  langToggle.addEventListener('click', () => {{
    lang = lang === 'zh' ? 'en' : 'zh';
    try {{ localStorage.setItem('hawkeye-lang', lang); }} catch (err) {{}}
    applyI18n();
  }});

  applyI18n();

  const cards = Array.from(document.querySelectorAll('.card'));
  // [data-filter] matters: #toggle-all shares .filter-btn for its pill
  // styling, and without the attribute it got wired up as a verdict filter
  // too -- one click set the verdict to undefined and hid every card.
  const reachableButtons = Array.from(document.querySelectorAll('.filter-btn[data-filter]'));
  const facetButtons = Array.from(document.querySelectorAll('.facet-item'));
  const emptyMsg = document.getElementById('empty-filter');

  const active = {{ reachable: 'all', type: '', file: '', severity: '' }};

  function applyFilters() {{
    let visible = 0;
    cards.forEach((card) => {{
      const matchesReachable = active.reachable === 'all' || card.dataset.bucket === active.reachable;
      const matchesType = !active.type || card.dataset.type === active.type;
      const matchesFile = !active.file || card.dataset.file === active.file;
      const matchesSeverity = !active.severity || card.dataset.severity === active.severity;
      const show = matchesReachable && matchesType && matchesFile && matchesSeverity;
      if (show) {{ card.removeAttribute('data-hidden'); visible++; }}
      else card.setAttribute('data-hidden', '');
    }});
    emptyMsg.style.display = visible === 0 ? 'block' : 'none';
  }}

  reachableButtons.forEach((btn) => {{
    btn.addEventListener('click', () => {{
      reachableButtons.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      active.reachable = btn.dataset.filter;
      applyFilters();
    }});
  }});

  // Only the cards a filter is currently showing are opened, so "expand
  // all" after narrowing to one file does not also unfold the 40 findings
  // the reader just filtered away. The label lives in data-i18n rather than
  // in textContent so applyI18n() keeps it correct across a language switch.
  const toggleAll = document.getElementById('toggle-all');
  toggleAll.addEventListener('click', () => {{
    const expand = toggleAll.dataset.i18n === 'actions.expandAll';
    cards.filter((c) => !c.hasAttribute('data-hidden')).forEach((c) => {{ c.open = expand; }});
    toggleAll.dataset.i18n = expand ? 'actions.collapseAll' : 'actions.expandAll';
    applyI18n();
  }});

  // Reveals one more page of facet values per click. A facet hidden this
  // way is only hidden from the list -- it never affects which cards match,
  // so revealing more cannot change the current filtering.
  document.querySelectorAll('.facet-more').forEach((btn) => {{
    const facet = btn.dataset.facetMore;
    const stillHidden = () =>
      Array.from(document.querySelectorAll('.facet-item[data-facet="' + facet + '"].hidden'));
    const refresh = () => {{
      const left = stillHidden().length;
      btn.querySelector('.more-count').textContent = left ? '(' + left + ')' : '';
      btn.style.display = left ? '' : 'none';
    }};
    btn.addEventListener('click', () => {{
      stillHidden().slice(0, {FACET_PAGE_SIZE}).forEach((el) => el.classList.remove('hidden'));
      refresh();
    }});
    refresh();
  }});

  facetButtons.forEach((btn) => {{
    btn.addEventListener('click', () => {{
      const facet = btn.dataset.facet;
      document.querySelectorAll(`.facet-item[data-facet="${{facet}}"]`).forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      active[facet] = btn.dataset.value;
      applyFilters();
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
