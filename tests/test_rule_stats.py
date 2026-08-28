"""Unit tests for scanner/rule_stats.py's aggregation -- the part that
decides what evidence there is for excluding a rule, so it has to be right
before any rule id gets added to ruleset.yml."""
import json

from scanner.rule_stats import (
    aggregate,
    load_candidates,
    load_report_findings,
    noise_candidates,
    rule_ids_of,
)


def finding(rule_ids, reachable="yes", verified=True, reasoning="because"):
    item = {"rule_ids": list(rule_ids), "rule_id": rule_ids[0]}
    if verified:
        item["finding"] = {"reachable": reachable, "reasoning": reasoning}
    return item


class TestRuleIdsOf:
    def test_prefers_the_merged_list(self):
        assert rule_ids_of({"rule_ids": ["a", "b"], "rule_id": "a"}) == ["a", "b"]

    def test_falls_back_to_the_single_id(self):
        assert rule_ids_of({"rule_id": "a"}) == ["a"]

    def test_tolerates_neither(self):
        assert rule_ids_of({}) == []


class TestAggregate:
    def test_counts_a_finding_once_per_rule_that_hit_it(self):
        rows = {r["rule_id"]: r for r in aggregate([finding(["a", "b"])])}
        assert rows["a"]["hits"] == 1 and rows["b"]["hits"] == 1

    def test_solo_hits_only_counts_findings_no_other_rule_matched(self):
        rows = {r["rule_id"]: r for r in aggregate([finding(["a", "b"]), finding(["a"])])}
        assert rows["a"]["hits"] == 2 and rows["a"]["solo_hits"] == 1
        assert rows["b"]["hits"] == 1 and rows["b"]["solo_hits"] == 0

    def test_buckets_each_verdict(self):
        rows = aggregate([
            finding(["a"], reachable="yes"),
            finding(["a"], reachable="no"),
            finding(["a"], reachable="uncertain"),
            finding(["a"], reasoning="verifier_failed: no JSON"),
            finding(["a"], verified=False),
        ])
        row = rows[0]
        assert (row["hits"], row["yes"], row["no"], row["uncertain"], row["failed"], row["unverified"]) == (5, 1, 1, 1, 1, 1)

    def test_unverified_candidates_do_not_land_in_uncertain(self):
        row = aggregate([finding(["a"], verified=False)])[0]
        assert row["unverified"] == 1 and row["uncertain"] == 0

    def test_reports_counts_distinct_reports(self):
        rows = aggregate([
            {**finding(["a"]), "_report_id": "r1"},
            {**finding(["a"]), "_report_id": "r1"},
            {**finding(["a"]), "_report_id": "r2"},
        ])
        assert rows[0]["reports"] == 2

    def test_sorted_by_hits_then_id(self):
        rows = aggregate([finding(["b"]), finding(["a"]), finding(["a"])])
        assert [r["rule_id"] for r in rows] == ["a", "b"]

    def test_empty_input(self):
        assert aggregate([]) == []


class TestNoiseCandidates:
    def test_flags_a_rule_that_only_ever_came_back_not_reachable(self):
        rows = aggregate([finding(["a"], reachable="no"), finding(["a"], reachable="no")])
        assert [r["rule_id"] for r in noise_candidates(rows)] == ["a"]

    def test_does_not_flag_a_rule_with_no_verdicts_yet(self):
        """Unverified hits are not evidence -- excluding on them is guessing."""
        rows = aggregate([finding(["a"], verified=False), finding(["a"], verified=False)])
        assert noise_candidates(rows) == []

    def test_does_not_flag_a_rule_that_ever_produced_a_reachable_finding(self):
        rows = aggregate([finding(["a"], reachable="yes"), finding(["a"], reachable="no")])
        assert noise_candidates(rows) == []

    def test_does_not_flag_a_rule_that_never_hit_alone(self):
        """Verdicts belong to the merged candidate, so a rule that only ever
        fired alongside another has no verdict that is really its own."""
        rows = aggregate([finding(["a", "b"], reachable="no")])
        assert [r["rule_id"] for r in noise_candidates(rows)] == []


class TestLoaders:
    def test_load_report_findings_tags_each_with_its_report(self, tmp_path):
        for name in ("scan1", "scan2"):
            d = tmp_path / name
            d.mkdir()
            (d / "report.json").write_text(json.dumps({"findings": [finding(["a"])]}), encoding="utf-8")

        loaded = load_report_findings(tmp_path)
        assert sorted(f["_report_id"] for f in loaded) == ["scan1", "scan2"]

    def test_load_report_findings_skips_unreadable_reports(self, tmp_path):
        (tmp_path / "broken").mkdir()
        (tmp_path / "broken" / "report.json").write_text("{not json", encoding="utf-8")
        assert load_report_findings(tmp_path) == []

    def test_load_candidates_missing_file(self, tmp_path):
        assert load_candidates(tmp_path / "nope.json") == []
