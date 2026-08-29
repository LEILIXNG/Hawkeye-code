"""Unit tests for scanner/context.py's code windows.

What the verify stage sees is the whole product here: a window that cuts a
method in half hides the signature, and the signature is where
@RequestParam says whether the value is user-controlled -- the exact
question being asked. So these tests are about boundaries, not formatting.

Like tests/test_callgraph.py, every case parses real Java off disk rather
than hand-building an Index, because the part most likely to break is the
agreement between tree-sitter's method spans and the slicing here.
"""
from pathlib import Path

from scanner.callgraph import index_workspace
from scanner.context import (
    CALLEE_MAX_LINES,
    CONTEXT_WINDOW,
    MAX_CALLEE_BODIES,
    build_callee_context,
    build_context,
    METHOD_HEAD_LINES,
    MAX_METHOD_LINES,
    read_method_window,
    read_window,
)


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


def line_numbers(block: str) -> list[int]:
    out = []
    for row in block.splitlines():
        head = row.split("|")[0].strip()
        if head.isdigit():
            out.append(int(head))
    return out


LONG_BODY = "\n".join(f"        int filler{i} = {i};" for i in range(MAX_METHOD_LINES + 40))

SAMPLE = """package demo;

class Demo {

    private static final String CONST = "x";

    @GetMapping("/one")
    public String handler(@RequestParam String name) {
        String local = name;
        return sink(local);
    }

    public String neighbour(String other) {
        return "untouched-neighbour-marker";
    }
}
"""


class TestReadMethodWindow:
    def test_snaps_to_the_whole_method_including_its_annotations(self, tmp_path):
        root = workspace(tmp_path, {"Demo.java": SAMPLE})
        index = index_workspace(root)
        sink_line = SAMPLE.splitlines().index("        return sink(local);") + 1

        block = read_method_window(root, "Demo.java", sink_line, index)

        assert "@GetMapping" in block, "the mapping annotation is the entry-point evidence"
        assert "@RequestParam String name" in block, "the signature answers 'is this user-controlled'"
        assert "return sink(local);" in block

    def test_does_not_bleed_into_the_neighbouring_method(self, tmp_path):
        """The old fixed window pulled in whatever happened to sit within 15
        lines, which on short methods is the next method's body."""
        root = workspace(tmp_path, {"Demo.java": SAMPLE})
        index = index_workspace(root)
        sink_line = SAMPLE.splitlines().index("        return sink(local);") + 1

        plain = read_window(root, "Demo.java", sink_line, CONTEXT_WINDOW)
        snapped = read_method_window(root, "Demo.java", sink_line, index)

        assert "untouched-neighbour-marker" in plain
        assert "untouched-neighbour-marker" not in snapped

    def test_falls_back_to_a_plain_window_without_an_index(self, tmp_path):
        root = workspace(tmp_path, {"Demo.java": SAMPLE})
        sink_line = SAMPLE.splitlines().index("        return sink(local);") + 1

        assert read_method_window(root, "Demo.java", sink_line, None) == read_window(
            root, "Demo.java", sink_line, CONTEXT_WINDOW
        )

    def test_falls_back_when_the_line_sits_outside_any_method(self, tmp_path):
        """Field initialisers and static blocks have no enclosing method; the
        context must not come back empty for them."""
        root = workspace(tmp_path, {"Demo.java": SAMPLE})
        index = index_workspace(root)
        field_line = SAMPLE.splitlines().index('    private static final String CONST = "x";') + 1

        block = read_method_window(root, "Demo.java", field_line, index)

        assert "CONST" in block

    def test_missing_file_is_reported_not_raised(self, tmp_path):
        index = index_workspace(workspace(tmp_path, {"Demo.java": SAMPLE}))
        assert "file not found" in read_method_window(tmp_path, "Nope.java", 3, index)

    def test_clamps_at_the_file_edges(self, tmp_path):
        root = workspace(tmp_path, {"Demo.java": SAMPLE})
        numbers = line_numbers(read_window(root, "Demo.java", 1, CONTEXT_WINDOW))
        assert numbers[0] == 1, "a window at line 1 must not start below it"
        assert numbers == sorted(numbers)


class TestLongMethods:
    def build(self, tmp_path):
        source = (
            "class Big {\n"
            "    @PostMapping(\"/big\")\n"
            "    public String handler(@RequestParam String name) {\n"
            f"{LONG_BODY}\n"
            "        return sink(name);\n"
            "    }\n"
            "}\n"
        )
        root = workspace(tmp_path, {"Big.java": source})
        sink_line = source.splitlines().index("        return sink(name);") + 1
        return root, index_workspace(root), sink_line, source

    def test_keeps_the_head_and_the_sink_and_says_what_it_dropped(self, tmp_path):
        root, index, sink_line, _ = self.build(tmp_path)

        block = read_method_window(root, "Big.java", sink_line, index)

        assert "@PostMapping" in block, "the head is kept precisely because it is the signature"
        assert "@RequestParam String name" in block
        assert "return sink(name);" in block, "the sink itself is never the part dropped"
        assert "lines omitted" in block, "an elision must be visible, not silent"

    def test_stays_far_smaller_than_the_method(self, tmp_path):
        root, index, sink_line, source = self.build(tmp_path)

        block = read_method_window(root, "Big.java", sink_line, index)

        assert len(line_numbers(block)) < len(source.splitlines())
        assert len(line_numbers(block)) <= METHOD_HEAD_LINES + 2 * CONTEXT_WINDOW + 1

    def test_the_omitted_count_matches_the_gap(self, tmp_path):
        """A wrong count here would misdescribe the code the model is reading."""
        root, index, sink_line, _ = self.build(tmp_path)

        block = read_method_window(root, "Big.java", sink_line, index)
        numbers = line_numbers(block)
        stated = int(next(r for r in block.splitlines() if "lines omitted" in r).split("...")[1].split()[0])
        gap = max(b - a - 1 for a, b in zip(numbers, numbers[1:]))

        assert stated == gap


CALLEES = """
class Handler {

    @GetMapping("/read")
    public String handle(String tool) {
        String cleaned = sanitize(tool);
        String other = java.nio.file.Paths.get(cleaned).toString();
        return root.resolve(cleaned).toString();
    }

    static String sanitize(String value) {
        return value.replaceAll("[^a-z0-9_-]", "");
    }

    static String neverReached() {
        return "called-after-the-sink-marker";
    }
}
"""


class TestCalleeContext:
    def candidate(self, line):
        return {"sink_file": "Handler.java", "sink_line": line,
                "source_file": "Handler.java", "source_line": line}

    def build(self, tmp_path, source=CALLEES):
        root = workspace(tmp_path, {"Handler.java": source})
        sink_line = source.splitlines().index("        return root.resolve(cleaned).toString();") + 1
        return root, index_workspace(root), sink_line

    def test_includes_the_body_of_a_sanitizer_called_before_the_sink(self, tmp_path):
        """The caller context says a request can get here; this says whether
        it was cleaned on the way. Without it the verifier has to guess what
        sanitize() does, and on the real corpus it guessed wrong."""
        root, index, sink_line = self.build(tmp_path)

        block = build_callee_context(root, self.candidate(sink_line), index)

        assert "sanitize()" in block
        assert "[^a-z0-9_-]" in block, "the body is the whole point, not just the name"

    def test_library_calls_resolve_to_nothing_and_drop_out(self, tmp_path):
        """This is what keeps the block small, and it needs no allowlist:
        Paths.get is not defined in the workspace, so it cannot be shown."""
        root, index, sink_line = self.build(tmp_path)

        block = build_callee_context(root, self.candidate(sink_line), index)

        assert "Paths" not in block and "resolve()" not in block

    def test_ignores_methods_called_after_the_sink(self, tmp_path):
        """A value reaching the sink was computed before it."""
        sink_stmt = "        String result = root.resolve(cleaned).toString();"
        source = CALLEES.replace(
            "        return root.resolve(cleaned).toString();",
            sink_stmt + "\n        neverReached();\n        return result;",
        )
        root = workspace(tmp_path, {"Handler.java": source})
        sink_line = source.splitlines().index(sink_stmt) + 1

        block = build_callee_context(root, self.candidate(sink_line), index_workspace(root))

        assert "sanitize()" in block, "the call before the sink is still shown"
        assert "called-after-the-sink-marker" not in block
        assert "neverReached()" not in block

    def test_says_how_many_it_left_out(self, tmp_path):
        many = "\n".join(f"    static String helper{i}(String v) {{ return v; }}" for i in range(6))
        calls = " + ".join(f"helper{i}(tool)" for i in range(6))
        source = (
            "class Handler {\n"
            "    @GetMapping(\"/read\")\n"
            "    public String handle(String tool) {\n"
            f"        String cleaned = {calls};\n"
            "        return root.resolve(cleaned).toString();\n"
            "    }\n"
            f"{many}\n"
            "}\n"
        )
        root = workspace(tmp_path, {"Handler.java": source})
        sink_line = source.splitlines().index("        return root.resolve(cleaned).toString();") + 1

        block = build_callee_context(root, self.candidate(sink_line), index_workspace(root))

        shown = [r for r in block.splitlines() if r.startswith("helper") and "() in " in r]
        assert len(shown) == MAX_CALLEE_BODIES, "capped, not unbounded"
        assert "(+3 more called methods not shown)" in block

    def test_truncates_a_long_callee_and_says_so(self, tmp_path):
        filler = "\n".join(f"        int f{i} = {i};" for i in range(CALLEE_MAX_LINES + 20))
        source = (
            "class Handler {\n"
            "    @GetMapping(\"/read\")\n"
            "    public String handle(String tool) {\n"
            "        String cleaned = sanitize(tool);\n"
            "        return root.resolve(cleaned).toString();\n"
            "    }\n"
            "    static String sanitize(String value) {\n"
            f"{filler}\n"
            "        return value;\n"
            "    }\n"
            "}\n"
        )
        root = workspace(tmp_path, {"Handler.java": source})
        sink_line = source.splitlines().index("        return root.resolve(cleaned).toString();") + 1

        block = build_callee_context(root, self.candidate(sink_line), index_workspace(root))

        assert "more lines" in block
        assert len(line_numbers(block)) <= CALLEE_MAX_LINES

    def test_nothing_to_show_produces_no_section(self, tmp_path):
        root = workspace(tmp_path, {"Handler.java": """
            class Handler {
                @GetMapping("/read")
                public String handle(String tool) {
                    return java.nio.file.Paths.get(tool).toString();
                }
            }
        """})
        index = index_workspace(root)
        method = next(m for m in index.methods if m.name == "handle")

        assert build_callee_context(root, self.candidate(method.start_line + 2), index) == ""

    def test_build_context_omits_the_section_without_an_index(self, tmp_path):
        root, index, sink_line = self.build(tmp_path)

        assert "Methods called on the way" not in build_context(root, self.candidate(sink_line))
        assert "Methods called on the way" in build_context(root, self.candidate(sink_line), index)

    def test_skips_boolean_predicates(self, tmp_path):
        """The block answers "what did this do to the value". A predicate
        answers a different question, and showing its body measurably made
        the verifier treat the existence of a check as proof the check was
        sufficient -- it called two real SSRF findings sanitized."""
        source = (
            "class Handler {\n"
            "    @GetMapping(\"/read\")\n"
            "    public String handle(String tool) {\n"
            "        if (!isUrlValid(tool)) { return \"blocked\"; }\n"
            "        String cleaned = sanitize(tool);\n"
            "        return root.resolve(cleaned).toString();\n"
            "    }\n"
            "    static boolean isUrlValid(String v) {\n"
            "        return !v.equals(\"169.254.169.254\");\n"
            "    }\n"
            "    static String sanitize(String v) { return v.replaceAll(\"[^a-z]\", \"\"); }\n"
            "}\n"
        )
        root = workspace(tmp_path, {"Handler.java": source})
        sink_line = source.splitlines().index("        return root.resolve(cleaned).toString();") + 1

        block = build_callee_context(root, self.candidate(sink_line), index_workspace(root))

        assert "sanitize()" in block, "value transformers are the point of the block"
        assert "isUrlValid" not in block
        assert "169.254.169.254" not in block

    def test_skips_names_that_resolve_to_more_than_one_method(self, tmp_path):
        """The call graph matches on name and arity with no type resolution.
        An extra plausible *caller chain* is a cheap trade; printing some
        unrelated class's toString() as the method called on the way to the
        sink states something false."""
        source = (
            "class Handler {\n"
            "    @GetMapping(\"/read\")\n"
            "    public String handle(StringBuilder builder) {\n"
            "        String cleaned = builder.toString();\n"
            "        return root.resolve(cleaned).toString();\n"
            "    }\n"
            "    static String only(String v) { return v; }\n"
            "}\n"
            "class Unrelated {\n"
            "    public String toString() { return \"unrelated-marker\"; }\n"
            "}\n"
            "class AlsoUnrelated {\n"
            "    public String toString() { return \"also-unrelated-marker\"; }\n"
            "}\n"
        )
        root = workspace(tmp_path, {"Handler.java": source})
        sink_line = source.splitlines().index("        return root.resolve(cleaned).toString();") + 1

        block = build_callee_context(root, self.candidate(sink_line), index_workspace(root))

        assert "unrelated-marker" not in block
        assert "also-unrelated-marker" not in block
