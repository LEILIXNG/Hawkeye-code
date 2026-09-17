"""Parsing Ruby sources into the same Method/Call/Owner shapes the Java,
Python, JS/TS, Go, C++, Rust, C# and PHP sides produce, so index_workspace()
can hand all nine to one shared traversal with no language check anywhere
in traverse.py.

Two things make this module's `_walk()` less uniform than every earlier
language's own: (1) a class body has to be iterated by hand rather than
handed to the generic per-child dispatch, because Ruby's `private`/
`protected`/`public` are not modifiers on a method declaration the way
Java's or C#'s are -- they are ordinary method calls that flip the default
visibility of every `def` that follows them in the same body, so the
walk has to track that state sequentially; (2) a *bare*, zero-argument,
no-parens call (`helper` rather than `helper()` or `self.helper`) is
syntactically indistinguishable from a local-variable read in this
grammar -- tree-sitter parses it as a plain `identifier`, not a `call` --
so such a call is invisible to this module's call graph. A known gap, not
an oversight: the moment a call carries a receiver, parentheses or an
argument, it is an ordinary `call` node and is recorded like any other.

Rails' `resources :users` macro is this project's second cross-file,
macro-expanding route registration (see ruby_entrypoints.py's own
docstring) -- like php_index.py's Laravel `Route::get(...)` resolution,
its pending references are matched globally across the whole index by
controller class name and action method name, not scoped to routes.rb's
own file.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.callgraph.ruby_entrypoints import entry_reason, resources_call, route_verb_call, RESOURCES_ACTIONS
from scanner.callgraph.ruby_syntax import _arity, _camelize, _parser, _short_name, _text, VISIBILITY_KEYWORDS

TYPE_DECLARATIONS = ("class",)


def index_ruby_workspace(root: Path, index: Index) -> None:
    """Parses every .rb file under `root` into `index`'s methods and call
    sites, additively -- the same contract every other index_*_workspace
    function already has. No test-file convention to skip: RSpec/Minitest
    tests live under a project-chosen `spec/`/`test/` directory, which the
    bare `test`/`tests` names in ruleset.yml's exclude_paths already
    catch (`spec/` is not, and is a known gap for a later pass)."""
    parser = _parser()
    pending_refs: list[tuple[str, str, str]] = []
    for path in sorted(root.rglob("*.rb")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(), pending_refs=pending_refs)
    _resolve_named_references(index, pending_refs)


def _resolve_named_references(index: Index, pending_refs: list[tuple[str, str, str]]) -> None:
    """A routes.rb entry naming its target as `controller#action` -- see
    this module's own docstring for why the search is global rather than
    same-file."""
    for class_name, method_name, description in pending_refs:
        for method in index.methods:
            if method.owner.name == class_name and method.name == method_name and not method.entry_definitive:
                method.entry_reason = description
                method.entry_definitive = True


def _superclass_name(node: Node, src: bytes) -> str | None:
    superclass = next((c for c in node.children if c.type == "superclass"), None)
    if superclass is None:
        return None
    type_node = next((c for c in superclass.children if c.type in ("constant", "scope_resolution")), None)
    return _short_name(type_node, src) if type_node is not None else None


def _owner_of(node: Node, src: bytes) -> Owner:
    name_node = node.child_by_field_name("name")
    name = _short_name(name_node, src) if name_node is not None else ""
    superclass = _superclass_name(node, src)
    return Owner(name=name, supertypes=(superclass,) if superclass else ())


def _create_method(decl_node: Node, name: str, src: bytes, rel: str, index: Index, owner: Owner,
                   is_public: bool) -> Method:
    params = decl_node.child_by_field_name("parameters")
    reason, definitive = entry_reason(is_public, owner.supertypes)
    method = Method(
        file=rel, name=name, arity=_arity(params), owner=owner,
        start_line=decl_node.start_point[0] + 1, end_line=decl_node.end_point[0] + 1,
        entry_reason=reason, entry_definitive=definitive,
    )
    index.methods.append(method)
    return method


def _handle_method(node: Node, src: bytes, rel: str, index: Index, owner: Owner, pending_refs: list,
                   is_public: bool) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    method = _create_method(node, _text(name_node, src), src, rel, index, owner, is_public)
    body = node.child_by_field_name("body")
    if body is not None:
        _walk(body, src, rel, index, method, owner, pending_refs)


def _handle_class(node: Node, src: bytes, rel: str, index: Index, pending_refs: list) -> None:
    new_owner = _owner_of(node, src)
    if new_owner.name and new_owner.supertypes:
        existing = index.supertypes.get(new_owner.name, ())
        index.supertypes[new_owner.name] = existing + tuple(t for t in new_owner.supertypes if t not in existing)
    body = node.child_by_field_name("body")
    if body is None:
        return
    # `private`/`protected`/`public` are ordinary bare-identifier statements
    # that flip the default visibility of every `def` after them in this
    # same body -- not a modifier attached to the method declaration itself
    # the way every class-based language handled so far spells it -- so
    # this loop tracks that state by hand instead of delegating every
    # child straight to the generic _walk() dispatch below.
    visibility = "public"
    for child in body.children:
        if child.type == "identifier" and _text(child, src) in VISIBILITY_KEYWORDS:
            visibility = _text(child, src)
            continue
        if child.type in ("method", "singleton_method"):
            _handle_method(child, src, rel, index, new_owner, pending_refs, is_public=(visibility == "public"))
            continue
        _walk(child, src, rel, index, None, new_owner, pending_refs)


def _handle_resources_call(call: Node, src: bytes, pending_refs: list) -> None:
    result = resources_call(call, src)
    if result is None:
        return
    name, only, except_ = result
    controller = _camelize(name) + "Controller"
    for action, verb, suffix in RESOURCES_ACTIONS:
        if only is not None and action not in only:
            continue
        if except_ is not None and action in except_:
            continue
        pending_refs.append((controller, action, f"{verb} /{name}{suffix}"))


def _handle_route_verb_call(call: Node, src: bytes, pending_refs: list) -> None:
    result = route_verb_call(call, src)
    if result is None:
        return
    verb, path, target = result
    controller_part, action = target.split("#", 1)
    pending_refs.append((_camelize(controller_part) + "Controller", action, f"{verb} {path}"))


def _callee_name(call: Node, src: bytes) -> tuple[str | None, bool]:
    method_node = call.child_by_field_name("method")
    if method_node is None:
        return None, False
    receiver = call.child_by_field_name("receiver")
    return _text(method_node, src), receiver is not None and receiver.type == "self"


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         pending_refs: list) -> None:
    if node.type in TYPE_DECLARATIONS:
        _handle_class(node, src, rel, index, pending_refs)
        return

    if node.type == "module":
        # Transparent for owner-tracking purposes, the same simplification
        # php_index.py's namespace handling makes: a class nested in a
        # module is indexed under its own bare name, with no module-prefix
        # tracking (see ruby_syntax.py's own _camelize() docstring for the
        # one place that gap actually matters -- a namespaced controller
        # route target).
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.children:
                _walk(child, src, rel, index, current, owner, pending_refs)
        return

    if node.type in ("method", "singleton_method"):
        # `def self.foo` (`singleton_method`) carries the same name/
        # parameters/body field names as a plain `method` node -- the
        # `object: self` field naming which singleton it opens is not
        # read here, since Owner already comes from the enclosing class.
        _handle_method(node, src, rel, index, owner, pending_refs, is_public=True)
        return

    if node.type == "call":
        callee, receiver_is_self = _callee_name(node, src)
        if callee is not None:
            args = node.child_by_field_name("arguments")
            index.calls.append(Call(
                file=rel, callee=callee, arity=sum(1 for c in args.children if c.is_named) if args else 0,
                line=node.start_point[0] + 1, caller=current, receiver_is_self=receiver_is_self,
            ))
        _handle_route_verb_call(node, src, pending_refs)
        _handle_resources_call(node, src, pending_refs)
        for child in node.children:
            _walk(child, src, rel, index, current, owner, pending_refs)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner, pending_refs)
