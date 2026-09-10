"""The report renderer.

Split out of a single 633-line module: the public entry points below are
the same names, importable from `scanner.render` exactly as before -- the
package boundary is an internal detail, not an API change.
"""
from scanner.render.cards import _card_html
from scanner.render.facets import FACET_EXPANDED_ROWS, FACET_PAGE_SIZE, _facet_counts
from scanner.render.page import render, render_html
from scanner.render.verdicts import (REACHABLE_ORDER, RISK_LEVELS, SEVERITY_ORDER,
                                     VERDICT_SUMMARY_KEYS, _cwe_text, build_summary, risk_level,
                                     short_location, vuln_type_label, verdict_of, with_scores)

__all__ = [
    "FACET_EXPANDED_ROWS", "FACET_PAGE_SIZE", "REACHABLE_ORDER", "RISK_LEVELS", "SEVERITY_ORDER",
    "VERDICT_SUMMARY_KEYS", "build_summary", "render", "render_html", "risk_level",
    "short_location", "verdict_of", "vuln_type_label", "with_scores",
]
