"""Unit tests for scanner/render_md.py -- the Markdown export. Same rule as
test_render.py: the deterministic structure is asserted, not every line of
prose."""
from scanner.render_md import render_markdown


def make_item(reachable="yes", severity="ERROR", sink_file="src/main/java/A.java", sink_line=10, **overrides):
    item = {
        "rule_id": "rule.x",
        "messages": ["a message"],
        "cwe": ["CWE-89: Improper Neutralization ... ('SQL Injection')"],
        "source_file": "src/main/java/A.java",
        "source_line": 3,
        "sink_file": sink_file,
        "sink_line": sink_line,
        "severity": severity,
        "finding": {
            "reachable": reachable,
            "confidence": 90,
            "reasoning": "because reasons",
            "exploit_scenario": "attacker sends a crafted parameter",
            "remediation": "use a prepared statement",
        },
    }
    item.update(overrides)
    return item


class TestRenderMarkdown:
    def test_headline_and_summary_table(self):
        out = render_markdown([make_item(), make_item(reachable="no")], "demo")

        assert out.startswith("# 扫描报告 — demo")
        assert "| 候选总数 | 可达漏洞 | 安全数量 | 需要人工复查 |" in out
        assert "| 2 | 1 | 1 | 0 |" in out

    def test_findings_are_grouped_by_risk_highest_first(self):
        items = [
            make_item(severity="ERROR", reachable="no"),        # 低危
            make_item(severity="WARNING", reachable="yes"),     # 高危
            make_item(severity="ERROR", reachable="yes"),       # 致命
        ]
        out = render_markdown(items, "demo")

        assert out.index("## 致命 (1)") < out.index("## 高危 (1)") < out.index("## 低危 (1)")

    def test_a_level_nothing_landed_in_gets_no_heading(self):
        out = render_markdown([make_item(severity="ERROR", reachable="yes")], "demo")

        assert "## 致命 (1)" in out
        assert "中危" not in out

    def test_a_finding_carries_its_location_and_prose(self):
        out = render_markdown([make_item(sink_file="src/x/Y.java", sink_line=42)], "demo")

        assert "### 1. SQL Injection — `src/x/Y.java:42`" in out
        assert "**判断依据:** because reasons" in out
        assert "**攻击场景:** attacker sends a crafted parameter" in out
        assert "**修复建议:** use a prepared statement" in out

    def test_english_export_uses_the_english_table(self):
        out = render_markdown([make_item()], "demo", lang="en")

        assert out.startswith("# Scan report — demo")
        assert "## Critical (1)" in out
        assert "**Reasoning:** because reasons" in out

    def test_an_unknown_language_falls_back_rather_than_raising(self):
        assert render_markdown([make_item()], "demo", lang="fr").startswith("# 扫描报告")

    def test_translated_prose_wins_over_the_original(self):
        item = make_item()
        item["finding"]["reasoning_en"] = "translated english"
        item["finding"]["reasoning_zh"] = "翻译过的中文"

        assert "翻译过的中文" in render_markdown([item], "demo")
        assert "translated english" in render_markdown([item], "demo", lang="en")

    def test_multiline_prose_is_flattened_into_one_list_item(self):
        # A newline inside a "- **label** ..." item would end the item and
        # leave the rest as a stray paragraph.
        item = make_item()
        item["finding"]["reasoning"] = "first line\nsecond line"

        assert "**判断依据:** first line second line" in render_markdown([item], "demo")

    def test_an_empty_report_says_so_instead_of_rendering_nothing(self):
        out = render_markdown([], "demo")

        assert "| 0 | 0 | 0 | 0 |" in out
        assert "没有候选发现" in out

    def test_windows_separators_are_normalised_in_exported_paths(self):
        out = render_markdown([make_item(sink_file=r"src\main\java\A.java", sink_line=9)], "demo")

        assert "`src/main/java/A.java:9`" in out
        assert "\\" not in out
