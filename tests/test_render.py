"""Unit tests for scanner/render.py's deterministic summary/sort logic
(the HTML string itself isn't asserted line-by-line -- that's presentation,
not logic worth pinning down in a unit test)."""
import re

from scanner.render import build_summary, render, render_html
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
