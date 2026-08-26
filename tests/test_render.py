"""Unit tests for scanner/render.py's deterministic summary/sort logic
(the HTML string itself isn't asserted line-by-line -- that's presentation,
not logic worth pinning down in a unit test)."""
from scanner.render import build_summary, render


def make_item(reachable="yes", severity="ERROR", verifier_failed=False, **overrides):
    finding = {
        "reachable": reachable,
        "sanitized": False,
        "confidence": 80,
        "reasoning": "verifier_failed: LLM did not return valid JSON" if verifier_failed else "because reasons",
        "exploit_scenario": "",
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
