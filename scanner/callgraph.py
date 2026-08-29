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

# Framework callbacks that carry externally supplied data the same way an HTTP
# handler does: the payload is written by whoever put it on the queue or the
# socket. @Scheduled, @PostConstruct and @Bean are deliberately absent -- the
# framework invokes those too, but with nothing a user chose.
MESSAGE_ENTRY_ANNOTATIONS = frozenset({
    "KafkaListener", "RabbitListener", "RabbitHandler", "JmsListener",
    "SqsListener", "RocketMQMessageListener", "StreamListener",
    "MessageMapping", "SubscribeMapping", "ExceptionHandler",
})

# The servlet/filter entry points, recognised by supertype rather than by name
# alone: `service` and `doFilter` are ordinary words, and treating every method
# called `service` as a request handler would invent entry points all over a
# Spring codebase. rules/ruleset.yml mounts java/servlets/security, so the
# ruleset can already produce candidates in code shaped like this.
SERVLET_SUPERTYPES = frozenset({
    "HttpServlet", "GenericServlet", "Servlet", "Filter", "HttpFilter",
    "OncePerRequestFilter", "HandlerInterceptor", "HandlerInterceptorAdapter",
})
SERVLET_ENTRY_METHODS = frozenset({
    "doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace",
    "service", "doFilter", "preHandle", "postHandle",
})

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

# Hops from a sink back to a request handler. 3 was chosen when the walk was
# depth-first and every extra hop multiplied the work; with the breadth-first
# walk in trace_to_entry_points() the cost is flat enough to set this from
# the code instead. Measured on the vmscode corpus (64 candidates), candidates
# with no reachable entry point: depth 3 -> 22, depth 5 -> 14, depth 7 -> 13,
# depth 10 and 15 -> 13. So 7 is where a real layered Spring app saturates,
# not a round number: the last chain it recovers is TemplateUtil.writeFile <-
# ExportUtil x3 <- VulnerabilityService x3 <- an @PostMapping handler, checked
# hop by hop against the source. The whole sweep costs 1.8s.
MAX_DEPTH = 7


@dataclass
class Owner:
    """The class, interface or anonymous class body a method is declared in.

    Tracked because "nothing calls this method" is not one situation but
    several, and the supertype is what tells them apart. An @Override nobody
    calls inside `new X509TrustManager() {...}` is a TLS callback the JDK
    invokes; the same shape inside a class implementing the application's own
    OaUpdateServiceInterface is a strategy the application dispatches, and can
    carry a message payload. Handing the verify stage the type instead of a
    shrug is the difference between a confident verdict and a coin flip.
    """
    name: str = ""
    supertypes: tuple[str, ...] = ()
    anonymous: bool = False


@dataclass
class Method:
    file: str
    name: str
    arity: int
    start_line: int
    end_line: int
    return_type: str = ""
    owner: Owner = field(default_factory=Owner)
    overrides_supertype: bool = False
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
    # `this.x()` / `super.x()`, which cannot land in an unrelated class. The
    # rest of the graph matches on name and arity alone, and `run()` is the
    # case that proves the cost: MockUserLoginInit.refreshMockUser() calls
    # `this.run()`, and without this flag that edge bridged into a completely
    # different module's OracleAQConsumer.run(), inventing a chain from a
    # @KafkaListener to a JMS connector it has nothing to do with.
    receiver_is_self: bool = False


@dataclass
class Index:
    methods: list[Method] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    # Type name -> its direct supertypes, and the transitive closure of that,
    # built once by index_workspace. Real hierarchies are more than one level
    # deep -- FileInfoDataUpload extends AbstractDeviceDataUpload extends
    # AbstractDataUpload -- and a one-level check silently drops the middle.
    supertypes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    ancestors: dict[str, frozenset[str]] = field(default_factory=dict)

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


def _type_names(node: Node | None, src: bytes) -> tuple[str, ...]:
    """The bare type names under an `extends`/`implements` clause, generics and
    package qualifiers stripped, so `implements java.util.List<String>` and
    `implements List<String>` both read as `List`."""
    if node is None:
        return ()
    names = []
    for child in node.children:
        if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
            names.append(_text(child, src).split("<")[0].split(".")[-1].strip())
        elif child.type == "type_list":
            names.extend(_type_names(child, src))
    return tuple(names)


def _owner_of(node: Node, src: bytes) -> Owner:
    name_node = node.child_by_field_name("name")
    return Owner(
        name=_text(name_node, src) if name_node is not None else "",
        supertypes=(_type_names(node.child_by_field_name("superclass"), src)
                    + _type_names(node.child_by_field_name("interfaces"), src)),
    )


def _entry_reason(method_node: Node, src: bytes, owner: Owner) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint.

    Returns ("", False) when nothing suggests a request can enter.
    """
    if method_node.child_by_field_name("name") is not None and owner.supertypes:
        name = _text(method_node.child_by_field_name("name"), src)
        if name in SERVLET_ENTRY_METHODS and set(owner.supertypes) & SERVLET_SUPERTYPES:
            return f"{name}() of a {sorted(set(owner.supertypes) & SERVLET_SUPERTYPES)[0]}", True

    modifiers = next((c for c in method_node.children if c.type == "modifiers"), None)
    if modifiers is not None:
        mapped = _annotation_names(modifiers, src) & (REQUEST_MAPPING_ANNOTATIONS | MESSAGE_ENTRY_ANNOTATIONS)
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
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner())
    _build_ancestors(index)
    index_mybatis_mappers(root, index)
    return index


def _build_ancestors(index: Index) -> None:
    """Transitive closure of Index.supertypes, cycle-safe. Java forbids cyclic
    inheritance, but this reads whatever is on disk, including half-written or
    generated sources."""
    def walk(name: str, seen: set[str]) -> frozenset[str]:
        if name in index.ancestors:
            return index.ancestors[name]
        reached: set[str] = set()
        for parent in index.supertypes.get(name, ()):
            if parent in seen:
                continue
            reached.add(parent)
            reached |= walk(parent, seen | {parent})
        result = frozenset(reached)
        index.ancestors[name] = result
        return result

    for type_name in list(index.supertypes):
        walk(type_name, {type_name})


TYPE_DECLARATIONS = ("class_declaration", "interface_declaration",
                     "enum_declaration", "record_declaration")


def _walk(node: Node, src: bytes, rel: str, index: Index,
          current: Method | None, owner: Owner) -> None:
    if node.type in TYPE_DECLARATIONS:
        owner = _owner_of(node, src)
        if owner.name:
            index.supertypes[owner.name] = owner.supertypes
    elif node.type == "object_creation_expression" and any(c.type == "class_body" for c in node.children):
        # `new X509TrustManager() { ... }`: the type being instantiated is the
        # only name the methods inside have, and it is the informative one.
        type_node = node.child_by_field_name("type")
        if type_node is not None:
            owner = Owner(name=_text(type_node, src).split("<")[0].split(".")[-1], anonymous=True)

    if node.type in ("method_declaration", "constructor_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            reason, definitive = _entry_reason(node, src, owner)
            return_node = node.child_by_field_name("type")
            modifiers = next((c for c in node.children if c.type == "modifiers"), None)
            current = Method(
                file=rel,
                name=_text(name_node, src),
                arity=_arity(node, "parameters"),
                return_type=_text(return_node, src) if return_node is not None else "",
                owner=owner,
                overrides_supertype=(modifiers is not None
                                     and "Override" in _annotation_names(modifiers, src)),
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                entry_reason=reason,
                entry_definitive=definitive,
            )
            index.methods.append(current)
    elif node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            receiver = node.child_by_field_name("object")
            index.calls.append(Call(
                file=rel,
                callee=_text(name_node, src),
                arity=_arity(node, "arguments"),
                line=node.start_point[0] + 1,
                caller=current,
                receiver_is_self=receiver is not None and receiver.type in ("this", "super"),
            ))

    for child in node.children:
        _walk(child, src, rel, index, current, owner)


def enclosing_method(index: Index, file: str, line: int) -> Method | None:
    """The innermost method containing `line`. Nested declarations (anonymous
    classes, lambdas holding methods) mean several can match; the smallest
    span is the one the sink actually sits in."""
    file = file.replace("\\", "/")
    holding = [m for m in index.methods if m.file == file and m.start_line <= line <= m.end_line]
    return min(holding, key=lambda m: m.end_line - m.start_line, default=None)


def _self_call_can_reach(index: Index, call: Call, method: Method) -> bool:
    """Whether a `this.x()` / `super.x()` call site could be calling `method`.

    Only ever consulted for self-receiver calls, and only ever used to *drop*
    an edge: such a call resolves inside the caller's own class hierarchy,
    never in an unrelated one. Owners we could not name are let through -- a
    lost caller costs the answer, and this exists to remove edges that are
    provably wrong, not merely unproven.

    Both directions of the hierarchy count. `this.x()` in a subclass can land
    on a base-class method, and `this.x()` in an abstract base lands on the
    subclass override -- that is the template-method pattern, and checking
    only one direction quietly deletes it.
    """
    caller_owner, target_owner = call.caller.owner, method.owner
    if not caller_owner.name or not target_owner.name:
        return True
    if target_owner.name == caller_owner.name:
        return True
    return (target_owner.name in index.ancestors.get(caller_owner.name, ())
            or caller_owner.name in index.ancestors.get(target_owner.name, ()))


def callers_of(index: Index, method: Method) -> list[Call]:
    return [c for c in index.calls
            if c.callee == method.name
            and (method.arity == ANY_ARITY or c.arity == method.arity)
            and c.caller is not None
            and (not c.receiver_is_self or _self_call_can_reach(index, c, method))]


def trace_to_entry_points(index: Index, file: str, line: int, max_depth: int = MAX_DEPTH) -> list[list[Call]]:
    """Call chains from a request entry point down to the method holding
    (file, line), nearest caller first.

    Only chains that actually reach an entry point are returned: a chain that
    peters out in internal code says nothing the sink's own context did not
    already say.

    Breadth-first with a *shared* visited set, one shortest chain per entry
    point reached. The depth-first version this replaces carried a per-chain
    visited set, so it enumerated every distinct path and its cost grew
    exponentially with max_depth: on the vmscode corpus, depth 5 produced
    1,914 chains in 5.2s and depth 7 produced 33,248 in 99s, to feed a
    context builder that prints four of them. Expanding each method once is
    what makes a depth worth having affordable.

    Nothing is lost by expanding once. An entry point is found by reaching
    it as some method's caller, and every reachable method still gets
    expanded -- just via whichever route found it first, which under BFS is
    a shortest one. If anything the shared set reaches further, because a
    method entered by its shortest route has more of the depth budget left.
    Four chains to four different handlers also say more than four
    permutations of the route to one.
    """
    start = enclosing_method(index, file, line)
    if start is None:
        return []
    if start.entry_definitive:
        return [[]]

    found: list[list[Call]] = []
    visited = {(start.file, start.name, start.arity)}
    frontier: list[tuple[Method, list[Call]]] = [(start, [])]
    for _ in range(max_depth):
        next_frontier: list[tuple[Method, list[Call]]] = []
        for method, chain in frontier:
            for call in callers_of(index, method):
                caller = call.caller
                key = (caller.file, caller.name, caller.arity)
                if key in visited:
                    continue
                visited.add(key)
                extended = chain + [call]
                if caller.is_entry_point:
                    found.append(extended)
                else:
                    next_frontier.append((caller, extended))
        if not next_frontier:
            break
        frontier = next_frontier
    if not found and start.is_entry_point:
        # Only a hinted entry (a request-shaped parameter type) and nothing
        # calls it: the hint is the best answer available, so report it as
        # the handler rather than as unreachable.
        return [[]]
    return sorted(found, key=len)
