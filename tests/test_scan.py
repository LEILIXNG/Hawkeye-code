"""Unit tests for the deterministic parts of scripts/01_scan.py.

These never call Semgrep or an LLM -- they operate on hand-built dicts
shaped like real Semgrep --dataflow-traces JSON output (captured from an
actual run against VulnerableApp, see MEMORY.md's note on the tagged-tuple
taint_source format).
"""
import os
from pathlib import Path

import pytest

from scanner.core import long_paths, run_semgrep


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


@pytest.mark.skipif(os.name != "nt", reason="the MAX_PATH limit only exists on Windows")
class TestLongPaths:
    """semgrep does not report files it cannot open past Windows' MAX_PATH --
    they show up as neither scanned, skipped nor errored -- so this is the
    only thing standing between a too-deep workspace and a scan that quietly
    covers a third of the code. `limit` is injected here so the cases stay
    readable instead of building 260-character fixtures.
    """

    def plant(self, root: Path, rel: str):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x", encoding="utf-8")
        return target

    def test_flags_a_source_file_past_the_limit(self, tmp_path):
        deep = self.plant(tmp_path, "src/main/java/Deep.java")
        assert long_paths(tmp_path, limit=len(str(deep))) == [deep]

    def test_ignores_files_semgrep_would_not_have_scanned_anyway(self, tmp_path):
        """An uploaded project's build output is over the limit constantly
        and costs nothing -- failing the scan for it would be a false alarm."""
        planted = self.plant(tmp_path, "build/classes/Deep.class")
        assert long_paths(tmp_path, limit=len(str(planted))) == []

    def test_ignores_files_under_a_configured_exclude_path(self, tmp_path):
        planted = self.plant(tmp_path, "target/generated/Deep.java")
        limit = len(str(planted))
        assert long_paths(tmp_path, ["target"], limit=limit) == []
        assert long_paths(tmp_path, [], limit=limit) == [planted]

    def test_honours_an_unanchored_exclude_glob(self, tmp_path):
        planted = self.plant(tmp_path, "moduleA/src/it/Deep.java")
        assert long_paths(tmp_path, ["**/src/it"], limit=len(str(planted))) == []

    def test_honours_a_file_glob(self, tmp_path):
        planted = self.plant(tmp_path, "web/app.min.js")
        assert long_paths(tmp_path, ["*.min.js"], limit=len(str(planted))) == []

    def test_stays_quiet_when_everything_fits(self, tmp_path):
        self.plant(tmp_path, "src/A.java")
        assert long_paths(tmp_path, limit=4096) == []


class TestRunSemgrepRefusesAnIncompleteScan:
    """The guard has to abort *before* semgrep runs. Reporting 29 findings
    where there are 44, with no error anywhere, is the failure mode this
    whole check exists for -- so monkeypatch the detection and assert the
    scan stops rather than trusting that the wiring is still connected.
    """

    def test_raises_instead_of_scanning(self, tmp_path, monkeypatch):
        monkeypatch.setattr("scanner.core.long_paths", lambda *a, **k: [tmp_path / "TooDeep.java"])

        def fail_if_called(*a, **k):
            raise AssertionError("semgrep was launched despite unreadable files")

        monkeypatch.setattr("scanner.core.subprocess.run", fail_if_called)

        with pytest.raises(SystemExit, match="silently incomplete"):
            run_semgrep(tmp_path, ["rules/custom"])

    def test_runs_normally_when_nothing_is_out_of_reach(self, tmp_path, monkeypatch):
        monkeypatch.setattr("scanner.core.long_paths", lambda *a, **k: [])

        class Proc:
            returncode = 0
            stdout = '{"results": []}'
            stderr = ""

        monkeypatch.setattr("scanner.core.subprocess.run", lambda *a, **k: Proc())
        assert run_semgrep(tmp_path, ["rules/custom"]) == {"results": []}
