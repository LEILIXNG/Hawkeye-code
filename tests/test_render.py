"""Unit tests for scanner/render.py's deterministic summary/sort logic
(the HTML string itself isn't asserted line-by-line -- that's presentation,
not logic worth pinning down in a unit test)."""
import re

from scanner.render import (FACET_PAGE_SIZE, RISK_LEVELS, _card_html, build_summary, render,
                            render_html, risk_level, short_location)
from scanner.report_i18n import REPORT_I18N


def make_item(reachable="yes", severity="ERROR", verifier_failed=False, exploit_scenario_present=False,
              remediation="", **overrides):
    finding = {
        "reachable": reachable,
        "sanitized": False,
        "confidence": 80,
        "reasoning": "verifier_failed: LLM did not return valid JSON" if verifier_failed else "because reasons",
        "exploit_scenario": "attacker sends a crafted parameter" if exploit_scenario_present else "",
        "remediation": remediation,
    }
    item = {
        "rule_id": "rule.x",
        "rule_ids": ["rule.x"],
        "message": "msg",
        "messages": ["msg"],
        "severity": severity,
        "cwe": "CWE-89",
        "source_file": "A.java",
        "source_line": 1,
        "sink_file": "A.java",
        "sink_line": 2,
        "dedup_key": "k",
        "finding": finding,
    }
    item.update(overrides)
    return item


class TestBuildSummary:
    def test_counts_each_bucket(self):
        verified = [
            make_item(reachable="yes"),
            make_item(reachable="no"),
            make_item(reachable="uncertain"),
            make_item(verifier_failed=True, reachable="uncertain"),
        ]
        summary = build_summary(verified)
        assert summary == {
            "total": 4,
            "reachable": 1,
            "uncertain": 1,
            "not_reachable": 1,
            "verifier_failed": 1,
        }

    def test_empty_list(self):
        summary = build_summary([])
        assert summary["total"] == 0


class TestRender:
    def test_writes_html_and_json(self, tmp_path):
        verified = [make_item(reachable="yes"), make_item(reachable="no")]
        result = render(verified, "demo-project", tmp_path)

        html_path = tmp_path / "report.html"
        json_path = tmp_path / "report.json"
        assert html_path.exists()
        assert json_path.exists()
        assert result["summary"]["total"] == 2
        assert "demo-project" in html_path.read_text(encoding="utf-8")


def flatten_keys(table: dict, prefix: str = "") -> set[str]:
    keys = set()
    for key, value in table.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            keys |= flatten_keys(value, f"{path}.")
        else:
            keys.add(path)
    return keys


class TestReportI18n:
    def test_languages_have_identical_key_sets(self):
        zh = flatten_keys(REPORT_I18N["zh"])
        en = flatten_keys(REPORT_I18N["en"])
        assert zh == en

    def test_every_rendered_key_is_translated(self, tmp_path):
        """Nothing in the page should stay blank -- the markup carries only
        i18n keys, so a typo'd key renders as empty text with no error."""
        verified = [
            make_item(reachable="yes", exploit_scenario_present=True),
            make_item(reachable="no"),
            make_item(reachable="uncertain"),
            make_item(verifier_failed=True, reachable="uncertain"),
        ]
        render(verified, "demo-project", tmp_path)
        page = (tmp_path / "report.html").read_text(encoding="utf-8")

        used = set(re.findall(r'data-i18n="([^"]+)"', page))
        assert used, "expected the page to be driven by data-i18n keys"
        for table in REPORT_I18N.values():
            assert used <= flatten_keys(table)


class TestRemediation:
    """The one line in a card the reader is meant to act on. Rendered only
    when the model actually produced one -- an empty paragraph with a
    heading and nothing after it reads as a bug."""

    def test_shown_when_the_model_produced_one(self):
        html_out = render_html([make_item(reachable="yes", remediation="Use #{sortParam} instead")], "p")
        assert 'data-i18n="card.remediation"' in html_out
        assert "Use #{sortParam} instead" in html_out

    def test_omitted_when_empty(self):
        html_out = render_html([make_item(reachable="no")], "p")
        assert "card.remediation" not in html_out

    def test_escaped_like_every_other_llm_field(self):
        """It quotes the scanned source back at the reader, same as
        reasoning and exploit_scenario, so it is untrusted text."""
        html_out = render_html([make_item(remediation='<img src=x onerror="alert(1)">')], "p")
        assert "<img src=x" not in html_out
        assert "&lt;img" in html_out


class TestBilingualProse:
    """The report toggle switched labels but not the LLM's own prose, which
    is most of what a reader reads. 04_translate.py fills in the other side;
    these pin that the page carries both and that skipping that stage
    changes nothing."""

    def test_both_languages_reach_the_page(self):
        item = make_item(reachable="yes", remediation="Use #{p}")
        item["finding"]["remediation_zh"] = "改用 #{p}"
        item["finding"]["remediation_en"] = "Use #{p}"
        out = render_html([item], "p")
        assert 'data-text-zh="改用 #{p}"' in out
        assert 'data-text-en="Use #{p}"' in out

    def test_an_untranslated_finding_carries_the_original_on_both_sides(self):
        """The stage is optional, and a reader should not be able to tell it
        was skipped except by the language not changing."""
        out = render_html([make_item(reachable="yes")], "p")
        assert 'data-text-zh="because reasons"' in out
        assert 'data-text-en="because reasons"' in out

    def test_translations_are_escaped_as_attributes(self):
        """They quote the scanned source back at the reader, and now they do
        it inside an HTML attribute, where a bare quote breaks out."""
        item = make_item(reachable="yes")
        item["finding"]["reasoning_zh"] = '" onmouseover="alert(1)'
        out = render_html([item], "p")
        assert 'onmouseover="alert(1)' not in out
        assert "&quot;" in out


class TestShortLocation:
    def test_keeps_a_short_path_whole(self):
        assert short_location("A.java") == "A.java"
        assert short_location("web/A.java") == "web/A.java"

    def test_ellipsises_the_shared_prefix_of_a_deep_path(self):
        deep = "src/main/java/org/sasanlabs/service/vulnerability/sqli/SQLInjection.java"
        assert short_location(deep) == ".../sqli/SQLInjection.java"

    def test_normalizes_windows_separators(self):
        assert short_location(r"src\main\java\A.java") == ".../java/A.java"

    def test_full_path_stays_on_the_row_title(self):
        item = {
            "sink_file": "src/main/java/org/x/Deep.java", "sink_line": 7,
            "source_file": "src/main/java/org/x/Deep.java", "source_line": 3,
            "rule_id": "r", "message": "m", "severity": "ERROR",
            "finding": {"reachable": "yes", "reasoning": "why"},
        }
        card = _card_html(item)
        assert 'title="src/main/java/org/x/Deep.java:7"' in card
        assert '<span class="loc-path">.../x/Deep.java</span><span class="loc-line">:7</span>' in card


class TestFacetPagination:
    def _items(self, html_text, facet):
        return re.findall(rf'<button class="facet-item([^"]*)" data-facet="{facet}"', html_text)

    def test_file_facet_hides_everything_past_the_first_page(self):
        items = [make_item(sink_file=f"src/main/java/F{n}.java") for n in range(20)]
        page = render_html(items, "demo")
        classes = self._items(page, "file")

        # 20 files + the "All" entry, which is never paginated away.
        assert len(classes) == 21
        assert sum(" hidden" in c for c in classes) == 20 - FACET_PAGE_SIZE
        assert 'data-facet-more="file"' in page

    def test_a_short_file_list_gets_no_show_more_button(self):
        items = [make_item(sink_file=f"src/F{n}.java") for n in range(FACET_PAGE_SIZE)]
        page = render_html(items, "demo")

        assert "hidden" not in "".join(self._items(page, "file"))
        assert 'data-facet-more="file"' not in page

    def test_other_facets_are_never_paginated(self):
        items = [make_item(sink_file=f"src/F{n}.java") for n in range(20)]
        page = render_html(items, "demo")

        assert "hidden" not in "".join(self._items(page, "severity"))
        assert 'data-facet-more="severity"' not in page
        assert 'data-facet-more="type"' not in page


class TestRiskLevel:
    def test_a_confirmed_path_carries_the_cwe_cvss_band(self):
        # 9.8, 7.5 and 5.9 respectively -- see scanner/cvss.py.
        assert risk_level(make_item(cwe="CWE-89", reachable="yes")) == "critical"
        assert risk_level(make_item(cwe="CWE-22", reachable="yes")) == "high"
        assert risk_level(make_item(cwe="CWE-327", reachable="yes")) == "medium"

    def test_the_engine_severity_no_longer_decides_anything(self):
        # ERROR covers both an unauthenticated SQL injection and a weak
        # hash, which is the reason the grading moved to CVSS.
        for severity in ("ERROR", "WARNING", "INFO", None):
            assert risk_level(make_item(cwe="CWE-89", severity=severity, reachable="yes")) == "critical"
            assert risk_level(make_item(cwe="CWE-327", severity=severity, reachable="yes")) == "medium"

    def test_not_reachable_bottoms_out_however_high_the_score(self):
        # These are the findings the summary counts as safe -- a 9.8 the
        # verifier proved unreachable must not outrank a reachable 5.9.
        assert risk_level(make_item(cwe="CWE-89", reachable="no")) == "low"
        assert risk_level(make_item(cwe="CWE-22", reachable="no")) == "low"
        # RISK_LEVELS runs highest first, so a bigger index is a lower risk.
        safe_injection = RISK_LEVELS.index(risk_level(make_item(cwe="CWE-89", reachable="no")))
        live_weak_hash = RISK_LEVELS.index(risk_level(make_item(cwe="CWE-327", reachable="yes")))
        assert safe_injection > live_weak_hash

    def test_no_verdict_is_one_step_down_not_the_floor(self):
        # uncertain/verifier_failed are missing evidence, not evidence of
        # safety. Deliberately a whole band rather than CVSS Temporal
        # RC:U, whose 0.92 multiplier leaves a 9.8 Critical.
        assert risk_level(make_item(cwe="CWE-89", reachable="uncertain")) == "high"
        assert risk_level(make_item(cwe="CWE-89", verifier_failed=True)) == "high"
        assert risk_level(make_item(cwe="CWE-22", reachable="uncertain")) == "medium"
        assert risk_level(make_item(cwe="CWE-327", reachable="uncertain")) == "low"

    def test_an_unclassified_weakness_uses_the_default_band(self):
        # Not critical: something nobody has classified should not outrank a
        # confirmed injection in the report's own ordering.
        item = make_item(reachable="yes")
        item["cwe"] = None
        assert risk_level(item) == "high"

    def test_the_facet_keeps_scale_order_and_drops_empty_levels(self):
        items = [make_item(severity="WARNING", reachable="no")] + [make_item(severity="ERROR", reachable="yes")] * 2
        page = render_html(items, "demo")
        values = re.findall(r'data-facet="severity" data-value="([^"]*)"', page)

        # critical before low even though low was rendered first, and no
        # "high (0)" entry for a level nothing landed in.
        assert values == ["", "critical", "low"]


class TestPublicSurface:
    """render.py became the scanner/render/ package; the names below are what
    pipeline.py, render_md.py, rule_stats.py and the tests import, so the
    package boundary has to keep re-exporting every one of them."""

    def test_every_public_entry_point_is_importable_from_scanner_render(self):
        import scanner.render as render

        for name in ("render", "render_html", "with_scores", "verdict_of", "build_summary",
                     "risk_level", "vuln_type_label", "short_location", "RISK_LEVELS",
                     "FACET_PAGE_SIZE", "FACET_EXPANDED_ROWS"):
            assert hasattr(render, name), name

    def test_the_page_is_assembled_from_the_split_modules(self):
        from scanner.render.facets import FACET_EXPANDED_ROWS
        from scanner.render.styles import REPORT_CSS

        page = render_html([make_item()], "demo")
        assert REPORT_CSS in page
        assert str(FACET_EXPANDED_ROWS) in REPORT_CSS
        assert "const I18N" in page
        assert '<div class="facet-col">' in page
