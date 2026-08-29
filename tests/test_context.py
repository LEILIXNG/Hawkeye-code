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
    CONTEXT_WINDOW,
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
