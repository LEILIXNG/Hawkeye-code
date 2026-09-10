"""The report page's inline script: language switching, the verdict/facet
filters and the expand-all toggle.

Takes its three constants pre-serialized so this module never has to know
what an i18n table or a project name is.
"""


def report_script(i18n_json: str, project_json: str, default_lang_json: str) -> str:
    return f"""
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

  // Reveals the rest of a facet's values in one click, then turns the list
  // into a scroll area. A facet hidden this way is only hidden from the
  // list -- it never affects which cards match, so revealing more cannot
  // change the current filtering.
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
      stillHidden().forEach((el) => el.classList.remove('hidden'));
      // Only now does the list get a scrollbar, and only as tall as
      // FACET_EXPANDED_ROWS -- the closed list is always short enough to
      // read without one.
      btn.parentElement.querySelector('.facet-list').classList.add('expanded');
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
"""
