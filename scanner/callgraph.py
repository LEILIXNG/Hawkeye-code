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
from xml.parsers import expat

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

# MyBatis statement tags that a mapper interface method maps onto. <sql> is
# deliberately absent: it is a fragment other statements <include>, not
# something Java calls by name.
MYBATIS_STATEMENT_TAGS = frozenset({"select", "insert", "update", "delete"})

# An arity we could not read off a mapper interface, matched by callers_of()
# against any argument count. A mapper XML names its method but never its
# parameter list, so when the namespace lookup comes up empty a caller with
# the wrong arity is still a better answer than no caller at all -- the same
# trade this module's docstring makes for name matching generally.
ANY_ARITY = -1

MAX_DEPTH = 3


@dataclass
class Method:
    file: str
    name: str
    arity: int
    start_line: int
    end_line: int
    return_type: str = ""
    entry_reason: str = ""
    # Whether entry_reason is proof or only a hint. A mapping annotation, or
    # a parameter the framework binds from the request, only ever appears on
    # a real handler. A parameter *type* does not: any helper can be handed
    # an HttpServletRequest or a MultipartFile, and treating those as proof
    # made trace_to_entry_points stop at the helper and never show the
    # handlers that call it -- which is where the validation lives.
    entry_definitive: bool = False

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


def _entry_reason(method_node: Node, src: bytes) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint.

    Returns ("", False) when nothing suggests a request can enter.
    """
    modifiers = next((c for c in method_node.children if c.type == "modifiers"), None)
    if modifiers is not None:
        mapped = _annotation_names(modifiers, src) & REQUEST_MAPPING_ANNOTATIONS
        if mapped:
            return f"@{sorted(mapped)[0]}", True

    params = method_node.child_by_field_name("parameters")
    if params is None:
        return "", False
    weak = ""
    for param in params.children:
        if param.type != "formal_parameter":
            continue
        param_modifiers = next((c for c in param.children if c.type == "modifiers"), None)
        if param_modifiers is not None:
            annotated = _annotation_names(param_modifiers, src) & REQUEST_PARAM_ANNOTATIONS
            if annotated:
                return f"@{sorted(annotated)[0]} parameter", True
        type_node = param.child_by_field_name("type")
        if not weak and type_node is not None and _text(type_node, src).split("<")[0] in REQUEST_PARAM_TYPES:
            weak = f"{_text(type_node, src)} parameter"
    # Keep looking for an annotated parameter before settling for a type:
    # a handler often has both, and the annotation is the stronger claim.
    return weak, False


def _arity(node: Node, field_name: str) -> int:
    container = node.child_by_field_name(field_name)
    if container is None:
        return 0
    return sum(1 for c in container.children if c.is_named)


def _mybatis_statements(src: bytes) -> tuple[str, list[tuple[str, int, int]]]:
    """`(namespace, [(statement id, start line, end line)])` for a MyBatis
    mapper XML; `("", [])` for any other XML.

    expat rather than a regex because the span has to be right for
    enclosing_method() to place a sink inside a statement, and statements
    nest <if>/<foreach>/<include>/CDATA freely. Parameter-entity parsing is
    turned off explicitly: every mapper opens with a DOCTYPE pointing at
    mybatis.org, and ingested code is untrusted data that must never cause
    a fetch (CLAUDE.md section 4).
    """
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    namespace = ""
    open_statements: list[tuple[str | None, int]] = []
    statements: list[tuple[str, int, int]] = []

    def on_start(name: str, attrs: dict) -> None:
        nonlocal namespace
        tag = name.split(":")[-1]
        if tag == "mapper" and not namespace:
            namespace = attrs.get("namespace", "")
        elif tag in MYBATIS_STATEMENT_TAGS:
            open_statements.append((attrs.get("id"), parser.CurrentLineNumber))

    def on_end(name: str) -> None:
        if name.split(":")[-1] not in MYBATIS_STATEMENT_TAGS or not open_statements:
            return
        statement_id, start_line = open_statements.pop()
        if statement_id:
            statements.append((statement_id, start_line, parser.CurrentLineNumber))

    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    try:
        parser.Parse(src, True)
    except expat.ExpatError:
        # Malformed, or not XML at all. Nothing to link; the sink keeps the
        # plain window it had before.
        return "", []
    return namespace, statements


def index_mybatis_mappers(root: Path, index: Index) -> None:
    """Give every MyBatis mapper statement a Method, so a sink inside the
    XML can be traced back through the Java that calls it.

    Measured on the vmscode corpus: 25 of 64 candidates sat in mapper XML
    and every single one reported "no request entry point", because this
    module only ever parsed .java. The XML carries the missing link itself
    -- <mapper namespace="com.x.XMapper"> names the interface exactly and
    <select id="listX"> names the method -- so unlike the name matching
    everywhere else here, this half is resolved rather than guessed.

    A statement gets one Method. Where the interface declares overloads of
    that name, or cannot be found at all, that Method takes ANY_ARITY:
    registering one node per overload would make trace_to_entry_points pick
    just one of them and lose the others' callers.
    """
    by_file: dict[str, list[Method]] = {}
    for method in index.methods:
        by_file.setdefault(method.file, []).append(method)

    for path in sorted(root.rglob("*.xml")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        namespace, statements = _mybatis_statements(src)
        # No namespace means no mapper: requiring it keeps an unrelated XML
        # that happens to contain <select id="..."> out of the call graph.
        if not namespace or not statements:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        suffix = namespace.replace(".", "/") + ".java"
        declared = next((m for f, m in by_file.items() if f.endswith(suffix)), [])
        for statement_id, start_line, end_line in statements:
            arities = {m.arity for m in declared if m.name == statement_id}
            index.methods.append(Method(
                file=rel,
                name=statement_id,
                arity=arities.pop() if len(arities) == 1 else ANY_ARITY,
                start_line=start_line,
                end_line=end_line,
            ))


def index_workspace(root: Path, parser: Parser | None = None) -> Index:
    """Parse every .java file under `root` into methods and call sites, then
    link the MyBatis mapper statements onto the interfaces they implement."""
    parser = parser or _parser()
    index = Index()
    for path in sorted(root.rglob("*.java")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None)
    index_mybatis_mappers(root, index)
    return index


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None) -> None:
    if node.type in ("method_declaration", "constructor_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            reason, definitive = _entry_reason(node, src)
            return_node = node.child_by_field_name("type")
            current = Method(
                file=rel,
                name=_text(name_node, src),
                arity=_arity(node, "parameters"),
                return_type=_text(return_node, src) if return_node is not None else "",
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                entry_reason=reason,
                entry_definitive=definitive,
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
            if c.callee == method.name
            and (method.arity == ANY_ARITY or c.arity == method.arity)
            and c.caller is not None]


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
    if start.entry_definitive:
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
    if not found and start.is_entry_point:
        # Only a hinted entry (a request-shaped parameter type) and nothing
        # calls it: the hint is the best answer available, so report it as
        # the handler rather than as unreachable.
        return [[]]
    return sorted(found, key=len)
