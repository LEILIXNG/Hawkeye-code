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
    ANY_ARITY,
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

    def test_two_routes_to_one_handler_report_it_once(self, tmp_path):
        """The breadth-first walk expands each method once, so a diamond
        yields one shortest chain rather than one chain per route. The
        depth-first version returned both, which is how a single sink came
        back with 740 chains for a context builder that prints four."""
        src = """
            class A {
                @GetMapping("/x")
                public String entry(@RequestParam String q) { left(q); right(q); }
                String left(String x) { return shared(x); }
                String right(String x) { return shared(x); }
                String shared(String x) { return exec(x); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(x)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert len(chains) == 1
        assert chains[0][-1].caller.name == "entry"

    def test_distinct_handlers_behind_a_shared_helper_are_all_found(self, tmp_path):
        """Expanding a method once must not cost an entry point: `shared` is
        reached by one route, but both handlers call it and both matter."""
        src = """
            class A {
                @GetMapping("/1")
                public String one(@RequestParam String q) { return shared(q); }
                @GetMapping("/2")
                public String two(@RequestParam String q) { return shared(q); }
                String shared(String x) { return deep(x); }
                String deep(String x) { return exec(x); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(x)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert sorted(c[-1].caller.name for c in chains) == ["one", "two"]

    def test_chains_come_back_shortest_first(self, tmp_path):
        """build_caller_context prints the first few, so the nearest handler
        has to be among them."""
        src = """
            class A {
                @GetMapping("/near")
                public String near(@RequestParam String q) { return sink(q); }
                @GetMapping("/far")
                public String far(@RequestParam String q) { return hop(q); }
                String hop(String x) { return sink(x); }
                String sink(String x) { return exec(x); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(x)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert [len(c) for c in chains] == [1, 2]
        assert chains[0][-1].caller.name == "near"

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


class TestEntryPointStrength:
    """A mapping annotation, or a parameter the framework binds, only ever
    appears on a real handler. A parameter *type* does not -- any helper can
    be handed an HttpServletRequest or a MultipartFile. Treating the weak
    signal as proof made the search stop at the helper and never reach the
    handlers that call it, which is where the validation lives.
    """

    UPLOAD = """
        class Upload {
            @VulnerableAppRequestMapping(value = "LEVEL_1")
            public String levelOne(@RequestParam MultipartFile file) {
                return store(root, file.getOriginalFilename(), file);
            }

            @VulnerableAppRequestMapping(value = "LEVEL_2")
            public String levelTwo(@RequestParam MultipartFile file) {
                return store(root, sanitize(file.getOriginalFilename()), file);
            }

            private String store(Path root, String fileName, MultipartFile file) {
                return root.resolve(fileName).toString();
            }
        }
    """

    def test_a_helper_taking_a_request_type_still_reports_its_callers(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"Upload.java": self.UPLOAD}))
        store = next(m for m in idx.methods if m.name == "store")
        assert store.entry_reason, "the MultipartFile parameter is still worth noting"
        assert not store.entry_definitive, "but it is a hint, not proof"

        chains = trace_to_entry_points(idx, "Upload.java", store.start_line + 1)

        assert chains != [[]], "the helper must not be mistaken for the handler"
        assert len(chains) == 2, "both level handlers call it"
        assert {c[-1].caller.name for c in chains} == {"levelOne", "levelTwo"}

    def test_a_mapping_annotation_is_proof_and_stops_the_search(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"Upload.java": self.UPLOAD}))
        handler = next(m for m in idx.methods if m.name == "levelOne")
        assert handler.entry_definitive

        assert trace_to_entry_points(idx, "Upload.java", handler.start_line + 1) == [[]]

    def test_an_annotated_parameter_is_proof(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String handler(@RequestBody Payload body) { return sink(body); }
            }
        """}))
        method = next(m for m in idx.methods if m.name == "handler")
        assert method.entry_definitive and "RequestBody" in method.entry_reason

    def test_a_hinted_entry_with_no_callers_is_still_reported_as_the_handler(self, tmp_path):
        """Otherwise a real servlet-style handler nothing calls would come
        back as unreachable, which is worse than the hint."""
        idx = index_workspace(workspace(tmp_path, {"S.java": """
            class S {
                protected void doGet(HttpServletRequest request) {
                    sink(request);
                }
            }
        """}))
        method = next(m for m in idx.methods if m.name == "doGet")
        assert method.entry_reason and not method.entry_definitive

        assert trace_to_entry_points(idx, "S.java", method.start_line + 1) == [[]]


class TestMyBatisMappers:
    """A mapper XML is the one place in this module where the link is
    resolved rather than guessed: <mapper namespace> names the interface and
    <select id> names the method, so these tests pin that the span, the
    arity lookup and the namespace requirement all hold."""

    MAPPER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.x.dao.LogMapper">
  <sql id="cols">id, detail</sql>
  <select id="listLogs" resultType="Log">
    select <include refid="cols"/> from log
    <if test="sorts != null">
      order by ${sorts}
    </if>
  </select>
  <update id="touch">update log set seen = 1</update>
</mapper>
"""

    INTERFACE_JAVA = """
        package com.x.dao;
        public interface LogMapper {
            List<Log> listLogs(LogQuery query);
            void touch();
        }
    """

    CONTROLLER_JAVA = """
        package com.x.web;
        class LogController {
            @GetMapping("/logs")
            public Object logs(@RequestParam String sorts) { return service.find(sorts); }
        }
        class LogService {
            Object find(String sorts) { return logMapper.listLogs(new LogQuery(sorts)); }
        }
    """

    def mapper_workspace(self, tmp_path, **overrides):
        files = {
            "src/main/resources/mapper/LogMapper.xml": self.MAPPER_XML,
            "src/main/java/com/x/dao/LogMapper.java": self.INTERFACE_JAVA,
            "src/main/java/com/x/web/LogController.java": self.CONTROLLER_JAVA,
        }
        files.update(overrides)
        return workspace(tmp_path, files)

    def test_a_statement_becomes_a_method_spanning_its_tag(self, tmp_path):
        idx = index_workspace(self.mapper_workspace(tmp_path))
        statement = next(m for m in idx.methods if m.file.endswith("LogMapper.xml") and m.name == "listLogs")
        assert statement.start_line == 6 and statement.end_line == 11

    def test_arity_comes_from_the_interface_the_namespace_names(self, tmp_path):
        idx = index_workspace(self.mapper_workspace(tmp_path))
        by_name = {m.name: m for m in idx.methods if m.file.endswith(".xml")}
        assert by_name["listLogs"].arity == 1
        assert by_name["touch"].arity == 0

    def test_a_sink_in_the_xml_traces_back_to_the_request_handler(self, tmp_path):
        """The whole point: the ${sorts} line inside <select> is 25 of the 64
        vmscode candidates, and before this it reported no entry point."""
        root = self.mapper_workspace(tmp_path)
        chains = trace_to_entry_points(index_workspace(root), "src/main/resources/mapper/LogMapper.xml", 9)
        assert chains
        assert chains[0][-1].caller.name == "logs"

    def test_sql_fragments_are_not_statements(self, tmp_path):
        idx = index_workspace(self.mapper_workspace(tmp_path))
        assert not [m for m in idx.methods if m.name == "cols"]

    def test_xml_without_a_mapper_namespace_is_ignored(self, tmp_path):
        """Otherwise any config file holding <select id="..."> would join the
        call graph and start answering questions about reachability."""
        idx = index_workspace(workspace(tmp_path, {
            "conf/menu.xml": '<?xml version="1.0"?><menu><select id="listLogs">x</select></menu>',
        }))
        assert idx.methods == []

    def test_overloads_fall_back_to_matching_any_arity(self, tmp_path):
        """One node per statement, not one per overload: registering both
        would make trace_to_entry_points pick one and lose the other's
        callers."""
        root = self.mapper_workspace(tmp_path, **{"src/main/java/com/x/dao/LogMapper.java": """
            package com.x.dao;
            public interface LogMapper {
                List<Log> listLogs(LogQuery query);
                List<Log> listLogs(LogQuery query, Page page);
            }
        """})
        idx = index_workspace(root)
        statement = next(m for m in idx.methods if m.file.endswith(".xml") and m.name == "listLogs")
        assert statement.arity == ANY_ARITY
        assert {c.arity for c in callers_of(idx, statement)} >= {1}

    def test_an_unresolvable_namespace_still_matches_callers(self, tmp_path):
        root = workspace(tmp_path, {
            "src/main/resources/mapper/LogMapper.xml": self.MAPPER_XML,
            "src/main/java/com/x/web/LogController.java": self.CONTROLLER_JAVA,
        })
        idx = index_workspace(root)
        statement = next(m for m in idx.methods if m.file.endswith(".xml") and m.name == "listLogs")
        assert statement.arity == ANY_ARITY
        assert [c.caller.name for c in callers_of(idx, statement)] == ["find"]

    def test_malformed_xml_is_skipped_rather_than_raised(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {
            "mapper/Broken.xml": '<mapper namespace="com.x.A"><select id="q">unclosed',
        }))
        assert idx.methods == []
