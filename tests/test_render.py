"""Unit tests for scanner/render.py's deterministic summary/sort logic
(the HTML string itself isn't asserted line-by-line -- that's presentation,
not logic worth pinning down in a unit test)."""
import re

from scanner.render import (FACET_PAGE_SIZE, _card_html, build_summary, render, render_html,
                            short_location)
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
