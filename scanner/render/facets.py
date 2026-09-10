"""The facet sidebar: counting one item-derived key across the findings, and
rendering a column of filter buttons for it."""
import html
from collections import Counter

# How many facet values a paginated column shows before "show more". Only
# the file column uses it -- a real project has one entry per file with a
# finding, which is far more than the handful of vulnerability types or the
# three severities. Sized so the closed list never needs a scrollbar: a
# scrolling facet list is the thing that made this column unreadable.
FACET_PAGE_SIZE = 5

# After the one click that reveals the rest, the list becomes a scroll area
# this many rows tall. One click rather than a page at a time: paging
# through 18 files four clicks at a time is worse than scrolling them.
FACET_EXPANDED_ROWS = 8


def _facet_counts(verified: list[dict], key_fn) -> list[tuple[str, int]]:
    counts = Counter(key_fn(item) for item in verified)
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


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
