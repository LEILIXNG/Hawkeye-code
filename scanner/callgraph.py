"""D: a reverse call graph over the Java sources in a workspace.

Semgrep OSS taint analysis is intraprocedural, so a candidate's reported
"source" is only ever the nearest tainted expression inside the same method.
On the corpus that means AuthLoginService.java:44 -> :51, where line 44 is a
local `sql` string -- true, and useless for deciding exploitability, because
the thing that decides it is that `username` came from an @RequestParam in
AuthenticationVulnerability.java, a different file entirely. The verify stage
was being handed one method and asked a question only its callers can answer.

This walks the other way: given a sink location, find the method containing
it, then the methods that call that method, and so on, until it reaches
something a request can enter through. It is a name-and-arity call graph, not
a resolved one -- there is no type resolution here, so two same-named methods
with the same parameter count are indistinguishable. That is deliberate: the
chains it produces are handed to the LLM as context, and an extra plausible
caller costs a few lines of prompt, while a missing one costs the answer.
docs/framework.md section D calls for exactly this, minus the Java sidecar
that CLAUDE.md replaced with Python.
"""
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_java
from tree_sitter import Language, Node, Parser

# Annotations that put a method (or one of its parameters) directly on the
# request path. VulnerableAppRequestMapping is this corpus's own wrapper
# around Spring's mapping annotations.
REQUEST_MAPPING_ANNOTATIONS = frozenset({
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
    "DeleteMapping", "PatchMapping", "VulnerableAppRequestMapping",
})
REQUEST_PARAM_ANNOTATIONS = frozenset({
    "RequestParam", "RequestBody", "PathVariable", "RequestHeader",
    "CookieValue", "ModelAttribute", "RequestPart",
})
REQUEST_PARAM_TYPES = frozenset({"HttpServletRequest", "MultipartFile", "HttpEntity"})

MAX_DEPTH = 3


@dataclass
class Method:
    file: str
    name: str
    arity: int
    start_line: int
    end_line: int
    entry_reason: str = ""

    @property
    def is_entry_point(self) -> bool:
        return bool(self.entry_reason)


@dataclass
class Call:
    file: str
    callee: str
    arity: int
    line: int
    caller: Method | None


@dataclass
class Index:
    methods: list[Method] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)

    def methods_named(self, name: str, arity: int) -> list[Method]:
        return [m for m in self.methods if m.name == name and m.arity == arity]


def _parser() -> Parser:
    return Parser(Language(tree_sitter_java.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _annotation_names(node: Node, src: bytes) -> set[str]:
    names = set()
    for child in node.children:
        if child.type in ("annotation", "marker_annotation"):
            name = child.child_by_field_name("name")
            if name is not None:
                names.add(_text(name, src).split(".")[-1])
    return names


def _entry_reason(method_node: Node, src: bytes) -> str:
    """Why a request could enter here, or "" if it could not."""
    modifiers = next((c for c in method_node.children if c.type == "modifiers"), None)
    if modifiers is not None:
        mapped = _annotation_names(modifiers, src) & REQUEST_MAPPING_ANNOTATIONS
        if mapped:
            return f"@{sorted(mapped)[0]}"

    params = method_node.child_by_field_name("parameters")
    if params is None:
        return ""
    for param in params.children:
        if param.type != "formal_parameter":
            continue
        param_modifiers = next((c for c in param.children if c.type == "modifiers"), None)
        if param_modifiers is not None:
            annotated = _annotation_names(param_modifiers, src) & REQUEST_PARAM_ANNOTATIONS
            if annotated:
                return f"@{sorted(annotated)[0]} parameter"
        type_node = param.child_by_field_name("type")
        if type_node is not None and _text(type_node, src).split("<")[0] in REQUEST_PARAM_TYPES:
            return f"{_text(type_node, src)} parameter"
    return ""


def _arity(node: Node, field_name: str) -> int:
    container = node.child_by_field_name(field_name)
    if container is None:
        return 0
    return sum(1 for c in container.children if c.is_named)


def index_workspace(root: Path, parser: Parser | None = None) -> Index:
    """Parse every .java file under `root` into methods and call sites."""
    parser = parser or _parser()
    index = Index()
    for path in sorted(root.rglob("*.java")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None)
    return index


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None) -> None:
    if node.type in ("method_declaration", "constructor_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            current = Method(
                file=rel,
                name=_text(name_node, src),
                arity=_arity(node, "parameters"),
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                entry_reason=_entry_reason(node, src),
            )
            index.methods.append(current)
    elif node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            index.calls.append(Call(
                file=rel,
                callee=_text(name_node, src),
                arity=_arity(node, "arguments"),
                line=node.start_point[0] + 1,
                caller=current,
            ))

    for child in node.children:
        _walk(child, src, rel, index, current)


def enclosing_method(index: Index, file: str, line: int) -> Method | None:
    """The innermost method containing `line`. Nested declarations (anonymous
    classes, lambdas holding methods) mean several can match; the smallest
    span is the one the sink actually sits in."""
    file = file.replace("\\", "/")
    holding = [m for m in index.methods if m.file == file and m.start_line <= line <= m.end_line]
    return min(holding, key=lambda m: m.end_line - m.start_line, default=None)


def callers_of(index: Index, method: Method) -> list[Call]:
    return [c for c in index.calls
            if c.callee == method.name and c.arity == method.arity and c.caller is not None]


def trace_to_entry_points(index: Index, file: str, line: int, max_depth: int = MAX_DEPTH) -> list[list[Call]]:
    """Call chains from a request entry point down to the method holding
    (file, line), nearest caller first.

    Only chains that actually reach an entry point are returned: a chain that
    peters out in internal code says nothing the sink's own context did not
    already say. Recursion and mutual recursion are bounded by both max_depth
    and a per-chain visited set.
    """
    start = enclosing_method(index, file, line)
    if start is None:
        return []
    if start.is_entry_point:
        return [[]]

    found: list[list[Call]] = []
    stack: list[tuple[Method, list[Call], set[tuple[str, str, int]]]] = [
        (start, [], {(start.file, start.name, start.arity)})
    ]
    while stack:
        method, chain, seen = stack.pop()
        if len(chain) >= max_depth:
            continue
        for call in callers_of(index, method):
            caller = call.caller
            key = (caller.file, caller.name, caller.arity)
            if key in seen:
                continue
            extended = chain + [call]
            if caller.is_entry_point:
                found.append(extended)
            else:
                stack.append((caller, extended, seen | {key}))
    return sorted(found, key=len)
