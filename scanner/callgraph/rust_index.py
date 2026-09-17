"""Parsing Rust sources into the same Method/Call/Owner shapes the Java,
Python, JS/TS, Go and C++ sides produce, so index_workspace() can hand all
six to one shared traversal with no language check anywhere in traverse.py.

Ownership works differently here than in every OOP language above: a
method is never declared inside the type it belongs to. `struct User { .. }`
and `impl User { fn find(&self) {..} }` are two separate top-level items,
so Owner comes from the nearest enclosing `impl` block, read fresh each
time one is entered, rather than from a class body carrying its own name
the way Java's TYPE_DECLARATIONS walk does. A trait implementation
(`impl Greeter for User`) is the one explicit supertype relationship this
language has -- recognised the same way Java's `implements` is -- and
because a type can gain trait impls from any number of separate `impl ...
for Type` blocks (unlike Java, where one class declaration states every
supertype at once), index.supertypes accumulates per type here instead of
being overwritten by the latest owner computed.

Self-calls are simpler than Go's: `self`/`&self`/`&mut self` is a fixed
grammar production (`self_parameter`, `self` as its own node type), not an
author-chosen receiver name that has to be threaded through the walk and
compared by text.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.callgraph.rust_entrypoints import entry_reason, is_route_registration, iter_route_handlers, route_path
from scanner.callgraph.rust_syntax import _arity, _parser, _short_name, _text, _type_name


def index_rust_workspace(root: Path, index: Index) -> None:
    """Parses every .rs file under `root` into `index`'s methods and call
    sites, additively -- the same contract every other index_*_workspace
    function already has, so a checkout mixing languages ends up in one
    graph rather than several that cannot see each other. No test-file
    convention to skip: Rust's own tests live in a `#[cfg(test)] mod tests`
    block inside the same file they test, not a separate `_test.rs`
    filename the way Go's do."""
    parser = _parser()
    pending_refs: list[tuple[str, str, str]] = []
    for path in sorted(root.rglob("*.rs")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(), pending_refs=pending_refs)
    _resolve_named_references(index, pending_refs)


def _resolve_named_references(index: Index, pending_refs: list[tuple[str, str, str]]) -> None:
    """A route registration naming its handler by reference -- a bare
    function name, a `Self::method` or `module::function` path, or a
    closure bound to a local first -- rather than an inline closure at the
    call site. Same-file only, matched by bare name alone: a wrong
    cross-file or cross-type match would silently promote an unrelated
    same-named function into a false entry point (see go_index.py's own
    version of this pass for the same trade)."""
    for name, file, description in pending_refs:
        for method in index.methods:
            if method.file == file and method.name == name and not method.entry_definitive:
                method.entry_reason = description
                method.entry_definitive = True


def _impl_owner(node: Node, src: bytes) -> Owner:
    type_node = node.child_by_field_name("type")
    trait_node = node.child_by_field_name("trait")
    name = _type_name(type_node, src) if type_node is not None else ""
    supertypes = (_type_name(trait_node, src),) if trait_node is not None else ()
    return Owner(name=name, supertypes=supertypes)


def _create_function_method(func_node: Node, name: str, src: bytes, rel: str, index: Index, owner: Owner,
                            pending_refs: list, reason: str = "", definitive: bool = False) -> Method:
    """Shared by a top-level/impl `fn` and a closure literal handed straight
    to a route call (`get(|req| {...})`) -- both this grammar's
    `function_item` and `closure_expression` name their parameter list
    `parameters`, so one reader covers both."""
    params = func_node.child_by_field_name("parameters")
    method = Method(
        file=rel, name=name, arity=_arity(params, src) if params is not None else 0, owner=owner,
        start_line=func_node.start_point[0] + 1, end_line=func_node.end_point[0] + 1,
        entry_reason=reason, entry_definitive=definitive,
    )
    index.methods.append(method)
    body = func_node.child_by_field_name("body")
    if body is not None:
        _walk(body, src, rel, index, method, owner, pending_refs)
    return method


def _handle_function_item(node: Node, src: bytes, rel: str, index: Index, owner: Owner, pending_refs: list) -> None:
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    if name_node is None or params_node is None:
        return
    reason, definitive = entry_reason(node, params_node, src)
    _create_function_method(node, _text(name_node, src), src, rel, index, owner, pending_refs, reason, definitive)


def _handle_route_registration(args: Node, src: bytes, rel: str, index: Index, pending_refs: list) -> None:
    path = route_path(args, src)
    for verb, handler in iter_route_handlers(args, src):
        description = f"{verb} {path}"
        if handler.type == "closure_expression":
            _create_function_method(handler, description, src, rel, index, Owner(), pending_refs,
                                    reason=description, definitive=True)
        elif handler.type == "identifier":
            pending_refs.append((_text(handler, src), rel, description))
        elif handler.type in ("field_expression", "scoped_identifier"):
            pending_refs.append((_short_name(handler, src), rel, description))


def _callee_name(func: Node, src: bytes) -> tuple[str | None, bool]:
    """The name a call resolves against, and whether its receiver is the
    literal `self` keyword -- Rust's fixed spelling of Java's `this`, unlike
    Go's author-chosen receiver variable (see this module's docstring)."""
    if func.type == "identifier":
        return _text(func, src), False
    if func.type == "field_expression":
        field = func.child_by_field_name("field")
        if field is None:
            return None, False
        value = func.child_by_field_name("value")
        return _text(field, src), value is not None and value.type == "self"
    if func.type == "scoped_identifier":
        name = func.child_by_field_name("name")
        return (_text(name, src), False) if name is not None else (None, False)
    return None, False


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         pending_refs: list) -> None:
    if node.type == "impl_item":
        new_owner = _impl_owner(node, src)
        if new_owner.name and new_owner.supertypes:
            existing = index.supertypes.get(new_owner.name, ())
            index.supertypes[new_owner.name] = existing + tuple(t for t in new_owner.supertypes if t not in existing)
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.children:
                _walk(child, src, rel, index, current, new_owner, pending_refs)
        return

    if node.type == "function_item":
        _handle_function_item(node, src, rel, index, owner, pending_refs)
        return

    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is not None:
            callee, receiver_is_self = _callee_name(func, src)
            if callee is not None:
                index.calls.append(Call(
                    file=rel, callee=callee, arity=sum(1 for c in args.children if c.is_named) if args else 0,
                    line=node.start_point[0] + 1, caller=current, receiver_is_self=receiver_is_self,
                ))
        if args is not None and is_route_registration(node, src):
            # The whole arguments subtree is registration wiring (the path
            # literal, verb calls, handler references) -- walking it again
            # generically below would re-discover an inline closure's body
            # as belonging to whatever function called .route(), not to the
            # synthetic handler Method just created for it above.
            _handle_route_registration(args, src, rel, index, pending_refs)
            for child in node.children:
                if child is not args:
                    _walk(child, src, rel, index, current, owner, pending_refs)
            return

        for child in node.children:
            _walk(child, src, rel, index, current, owner, pending_refs)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner, pending_refs)
