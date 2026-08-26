"""Unit tests for the deterministic parts of scripts/01_scan.py.

These never call Semgrep or an LLM -- they operate on hand-built dicts
shaped like real Semgrep --dataflow-traces JSON output (captured from an
actual run against VulnerableApp, see MEMORY.md's note on the tagged-tuple
taint_source format).
"""
from pathlib import Path


def make_result(check_id="rule.id", path="C:\\repo\\A.java", start_line=51,
                 severity="ERROR", cwe=None, owasp=None, dataflow_trace=None):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start_line, "col": 1},
        "end": {"line": start_line, "col": 10},
        "extra": {
            "message": f"finding for {check_id}",
            "severity": severity,
            "metadata": {"cwe": cwe, "owasp": owasp},
            "dataflow_trace": dataflow_trace,
        },
    }


def make_trace(path, line):
    """Shape matches real Semgrep output: a tagged tuple, not {"location": ...}."""
    return {
        "taint_source": ["CliLoc", [{"path": path, "start": {"line": line}, "end": {"line": line}}, "username"]],
        "taint_sink": ["CliLoc", [{"path": path, "start": {"line": line}}, "sql"]],
    }


class TestExtractSourceLocation:
    def test_returns_none_when_no_trace(self, scan_module):
        result = make_result(dataflow_trace=None)
        assert scan_module.extract_source_location(result, Path("C:\\repo")) is None

    def test_returns_none_when_trace_missing_taint_source(self, scan_module):
        result = make_result(dataflow_trace={"taint_sink": ["CliLoc", [{}, "x"]]})
        assert scan_module.extract_source_location(result, Path("C:\\repo")) is None

    def test_parses_tagged_tuple_shape(self, scan_module):
        trace = make_trace("C:\\repo\\A.java", 44)
        result = make_result(dataflow_trace=trace)
        loc = scan_module.extract_source_location(result, Path("C:\\repo"))
        assert loc is not None
        assert loc["line"] == 44
        assert loc["file"] == "A.java"

    def test_defensive_on_malformed_payload(self, scan_module):
        # taint_source present but payload isn't the [location, varname] list
        # shape -- must not raise, must return None.
        result = make_result(dataflow_trace={"taint_source": ["CliLoc", "not-a-list"]})
        assert scan_module.extract_source_location(result, Path("C:\\repo")) is None


class TestNormalize:
    def test_cross_function_candidate_keeps_distinct_source_and_sink(self, scan_module):
        raw = {"results": [make_result(
            check_id="java.spring-sqli", path="C:\\repo\\Auth.java", start_line=51,
            dataflow_trace=make_trace("C:\\repo\\Auth.java", 44),
        )]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        assert len(candidates) == 1
        c = candidates[0]
        assert c["source_line"] == 44
        assert c["sink_line"] == 51
        assert c["is_intraprocedural"] is True  # same file, just different lines

    def test_pattern_rule_without_trace_uses_sink_as_source(self, scan_module):
        raw = {"results": [make_result(dataflow_trace=None)]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        c = candidates[0]
        assert c["source_line"] == c["sink_line"] == 51
        assert c["is_intraprocedural"] is True


class TestDedup:
    def test_merges_findings_at_the_same_source_and_sink(self, scan_module):
        raw = {"results": [
            make_result(check_id="rule.a", path="C:\\repo\\Crypto.java", start_line=88, dataflow_trace=None),
            make_result(check_id="rule.b", path="C:\\repo\\Crypto.java", start_line=88, dataflow_trace=None),
        ]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        deduped = scan_module.dedup(candidates)
        assert len(deduped) == 1
        assert set(deduped[0]["rule_ids"]) == {"rule.a", "rule.b"}

    def test_keeps_distinct_sources_sharing_one_sink_separate(self, scan_module):
        """Regression test for the bug flagged in the framework review: the
        CommandInjection Level1~5 handlers all funnel into the same sink
        line, but each has a different source (a different HTTP entry
        point) and must be reported as separate candidates, not merged."""
        sink_path = "C:\\repo\\CommandInjection.java"
        raw = {"results": [
            make_result(check_id="cmd-inject", path=sink_path, start_line=47,
                        dataflow_trace=make_trace(sink_path, 68)),   # Level 1 entry
            make_result(check_id="cmd-inject", path=sink_path, start_line=47,
                        dataflow_trace=make_trace(sink_path, 83)),   # Level 2 entry
        ]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        deduped = scan_module.dedup(candidates)
        assert len(deduped) == 2
        source_lines = {c["source_line"] for c in deduped}
        assert source_lines == {68, 83}


class TestRelpath:
    def test_path_inside_target_becomes_relative(self, scan_module):
        rel = scan_module.relpath(Path("C:/repo"), "C:/repo/src/Main.java")
        assert rel in ("src\\Main.java", "src/Main.java")

    def test_path_outside_target_falls_back_to_original(self, scan_module):
        rel = scan_module.relpath(Path("C:/repo"), "D:/elsewhere/Main.java")
        assert rel == "D:/elsewhere/Main.java"
