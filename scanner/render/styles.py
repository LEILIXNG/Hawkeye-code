"""The report page's inline stylesheet.

A block of static CSS with one computed value in it, kept out of page.py so
the page-assembly function stays readable as page structure.
"""
from scanner.render.facets import FACET_EXPANDED_ROWS

REPORT_CSS = f"""
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
    /* .facet-list is a flex column with a max-height, so without this the
       items compress to fit instead of overflowing into a scroll: 18 files
       squeezed into 220px rendered as unreadable slivers rather than a
       scrollable list. */
    flex-shrink: 0;
  }}
  .facet-item:hover {{ background: var(--bg); }}
  .facet-item.active {{ background: var(--primary-soft); color: var(--primary); font-weight: 600; }}
  .facet-item.hidden {{ display: none; }}
  /* 1.75rem is one .facet-item plus the list's gap, measured in the browser
     rather than added up from the padding and line-height -- the arithmetic
     came out 5px per row too tall and showed 9.5 rows instead of 8. */
  .facet-list.expanded {{ max-height: calc({FACET_EXPANDED_ROWS} * 1.75rem); }}
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
  .badge-unverified {{ background: var(--neutral); }}
  .unverified-note {{ color: var(--text-muted); font-style: italic; }}
  .badge-failed {{ background: var(--neutral); }}
  .vuln-type {{ font-size: 0.82rem; font-weight: 650; }}
  .severity {{
    font-size: 0.68rem; font-weight: 700; letter-spacing: 0.03em;
    padding: 0.1rem 0.4rem; border-radius: 4px;
    background: var(--neutral-soft); color: var(--neutral);
  }}
  .cvss {{ font-size: 0.72rem; font-weight: 600; color: var(--text-muted); font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .risk-critical {{ background: var(--danger); color: #fff; }}
  .risk-high {{ background: var(--danger-soft); color: var(--danger); }}
  .risk-medium {{ background: var(--warning-soft); color: var(--warning); }}
  .risk-low {{ background: var(--neutral-soft); color: var(--neutral); }}
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
"""
