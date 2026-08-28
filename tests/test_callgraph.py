"""Unit tests for scanner/callgraph.py.

The call graph exists to answer one question the sink's own file cannot:
can a request reach this method. Every test here is a small Java source
written to disk and parsed for real -- there are no hand-built index
fixtures, because the thing most likely to break is the tree-sitter node
walking, and a fixture would skip exactly that.
"""
from pathlib import Path

import pytest

from scanner.callgraph import (
    Index,
    callers_of,
    enclosing_method,
    enclosing_method as _enclosing,
    index_workspace,
    trace_to_entry_points,
)


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


class TestIndexing:
    def test_finds_methods_and_their_arity(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void none() {}
                void two(String a, int b) { helper(a); }
            }
        """}))
        by_name = {m.name: m for m in idx.methods}
        assert by_name["none"].arity == 0
        assert by_name["two"].arity == 2

    def test_records_call_sites_with_their_caller(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void caller() { callee("x"); }
            }
        """}))
        call = next(c for c in idx.calls if c.callee == "callee")
        assert call.arity == 1 and call.caller.name == "caller"

    def test_paths_are_relative_and_posix(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"pkg/deep/A.java": "class A { void m() {} }"}))
        assert idx.methods[0].file == "pkg/deep/A.java"


class TestEntryPoints:
    def test_mapping_annotation_on_the_method(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                @GetMapping("/x")
                public String handler() { return ""; }
            }
        """}))
        assert idx.methods[0].entry_reason == "@GetMapping"

    def test_request_annotation_on_a_parameter(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String handler(@RequestParam String q) { return q; }
            }
        """}))
        assert "@RequestParam" in idx.methods[0].entry_reason

    def test_servlet_request_parameter_type(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String handler(HttpServletRequest request) { return ""; }
            }
        """}))
        assert "HttpServletRequest" in idx.methods[0].entry_reason

    def test_plain_method_is_not_an_entry_point(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String helper(String q) { return q; }
            }
        """}))
        assert idx.methods[0].entry_reason == "" and not idx.methods[0].is_entry_point


class TestEnclosingMethod:
    def test_picks_the_innermost_method(self, tmp_path):
        """An anonymous class inside a method puts one declaration inside
        another; the sink belongs to the tighter one."""
        src = """
            class A {
                void outer() {
                    Runnable r = new Runnable() {
                        public void run() { sink(); }
                    };
                }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "sink()" in l)
        assert enclosing_method(idx, "A.java", sink_line).name == "run"

    def test_returns_none_outside_any_method(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": "class A {\n  int field = 1;\n}"}))
        assert enclosing_method(idx, "A.java", 2) is None

    def test_accepts_windows_separators(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"pkg/A.java": "class A { void m() { x(); } }"}))
        assert enclosing_method(idx, "pkg\\A.java", 1).name == "m"


class TestTraceToEntryPoints:
    CROSS_FILE = {
        "web/Controller.java": """
            class Controller {
                @GetMapping("/login")
                public String login(@RequestParam String username) {
                    return service.authenticate(username);
                }
            }
        """,
        "svc/Service.java": """
            class Service {
                public String authenticate(String username) {
                    return jdbc.query("SELECT * FROM u WHERE n='" + username + "'");
                }
            }
        """,
    }

    def test_finds_the_caller_in_another_file(self, tmp_path):
        """The case semgrep OSS cannot see: the sink is in Service.java and
        the only thing that makes it exploitable is in Controller.java."""
        idx = index_workspace(workspace(tmp_path, self.CROSS_FILE))
        sink = enclosing_method(idx, "svc/Service.java", 3)
        assert sink.name == "authenticate"

        chains = trace_to_entry_points(idx, "svc/Service.java", 4)
        assert len(chains) == 1
        assert chains[0][-1].caller.name == "login"
        assert chains[0][-1].caller.file == "web/Controller.java"

    def test_sink_already_in_a_handler_reports_an_empty_chain(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                @PostMapping("/x")
                public String handler(@RequestParam String q) { return exec(q); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 4) == [[]]

    def test_no_chain_when_nothing_reaches_the_method(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void orphan() { exec("x"); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 3) == []

    def test_arity_has_to_match(self, tmp_path):
        """A same-named method with a different parameter count is a
        different method, and treating it as a caller would invent a path."""
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                @GetMapping("/x")
                public String handler(@RequestParam String q) { return helper(q, 1); }
                void helper(String a) { exec(a); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 5) == []

    def test_every_caller_of_a_shared_sink_is_reported(self, tmp_path):
        """CommandInjection's shape: one helper, several handlers, and only
        some of them validate. Showing one of them would be worse than
        showing none, because it reads as the whole story."""
        src = """
            class A {
                @GetMapping("/1")
                public String one(@RequestParam String q) { return helper(q); }
                @GetMapping("/2")
                public String two(@RequestParam String q) { return helper(validate(q)); }
                String helper(String a) { return exec(a); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(a)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert sorted(c[-1].caller.name for c in chains) == ["one", "two"]

    def test_recursion_terminates(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void a(String x) { b(x); }
                void b(String x) { a(x); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 3) == []

    def test_depth_limit_is_honoured(self, tmp_path):
        files = {"A.java": """
            class A {
                @GetMapping("/x")
                public String entry(@RequestParam String q) { return one(q); }
                String one(String x) { return two(x); }
                String two(String x) { return three(x); }
                String three(String x) { return exec(x); }
            }
        """}
        idx = index_workspace(workspace(tmp_path, files))
        sink_line = 7
        assert enclosing_method(idx, "A.java", sink_line).name == "three"
        assert len(trace_to_entry_points(idx, "A.java", sink_line, max_depth=3)[0]) == 3
        assert trace_to_entry_points(idx, "A.java", sink_line, max_depth=2) == []


class TestCallersOf:
    def test_matches_on_name_and_arity(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void caller() { target("a"); target("a", "b"); }
                void target(String a) {}
            }
        """}))
        target = next(m for m in idx.methods if m.name == "target")
        assert [c.arity for c in callers_of(idx, target)] == [1]

    def test_empty_index_is_safe(self):
        assert callers_of(Index(), _enclosing(Index(), "A.java", 1) or _dummy()) == []


def _dummy():
    from scanner.callgraph import Method
    return Method(file="A.java", name="x", arity=0, start_line=1, end_line=1)
