"""Parsing C# sources into the same Method/Call/Owner shapes the Java,
Python, JS/TS, Go, C++ and Rust sides produce, so index_workspace() can
hand all seven to one shared traversal with no language check anywhere in
traverse.py.

Structurally closest to Java's: methods live inside class/interface bodies,
`this` is a fixed keyword (not an author-named receiver the way Go's is),
and a type declaration states its whole base list -- class and interfaces
alike -- in one place. The one difference from Java worth a design choice:
a `partial class` can be declared across several files, each contributing
its own slice of the base list, so index.supertypes accumulates per type
here (the same trade Rust's scattered `impl Trait for Type` blocks forced)
rather than being overwritten by whichever declaration is walked last --
cheap insurance Java's own single-declaration-site guarantee does not need.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.csharp_entrypoints import entry_reason, is_route_registration, route_handler, route_path
from scanner.callgraph.csharp_syntax import _arity, _base_list_names, _modifiers, _parser, _short_name, _text
from scanner.callgraph.model import Call, Index, Method, Owner

TYPE_DECLARATIONS = ("class_declaration", "interface_declaration", "struct_declaration", "record_declaration")


def index_csharp_workspace(root: Path, index: Index) -> None:
    """Parses every .cs file under `root` into `index`'s methods and call
    sites, additively -- the same contract every other index_*_workspace
    function already has. No test-file convention to skip: a C# test
    project is its own directory (`MyApp.Tests/`), not a filename suffix
    beside the source the way Go's `_test.go` is, and does not match the
    bare `test`/`tests` names ruleset.yml's exclude_paths already
    recognises -- a known gap, not attempted here."""
    parser = _parser()
    pending_refs: list[tuple[str, str, str]] = []
    for path in sorted(root.rglob("*.cs")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(), pending_refs=pending_refs)
    _resolve_named_references(index, pending_refs)


def _resolve_named_references(index: Index, pending_refs: list[tuple[str, str, str]]) -> None:
    """A minimal-API registration naming its handler by reference -- a bare
    method name or a `Class.Method` group -- rather than an inline lambda.
    Same-file only, matched by bare name alone (see rust_index.py's own
    version of this pass for the same trade)."""
    for name, file, description in pending_refs:
        for method in index.methods:
            if method.file == file and method.name == name and not method.entry_definitive:
                method.entry_reason = description
                method.entry_definitive = True


def _owner_of(node: Node, src: bytes) -> Owner:
    name_node = node.child_by_field_name("name")
    return Owner(name=_text(name_node, src) if name_node is not None else "",
                 supertypes=_base_list_names(node, src))


def _create_method(decl_node: Node, name: str, src: bytes, rel: str, index: Index, owner: Owner,
                   pending_refs: list, reason: str = "", definitive: bool = False) -> Method:
    """Shared by a declared method/constructor and a lambda handed straight
    to a minimal-API registration call -- both carry their parameter list
    under the field name `parameters`, so one reader covers both."""
    params = decl_node.child_by_field_name("parameters")
    method = Method(
        file=rel, name=name, arity=_arity(params, src), owner=owner,
        start_line=decl_node.start_point[0] + 1, end_line=decl_node.end_point[0] + 1,
        entry_reason=reason, entry_definitive=definitive,
    )
    index.methods.append(method)
    body = decl_node.child_by_field_name("body")
    if body is not None:
        _walk(body, src, rel, index, method, owner, pending_refs)
    return method


def _handle_method_like(node: Node, src: bytes, rel: str, index: Index, owner: Owner,
                        pending_refs: list) -> None:
    """method_declaration or constructor_declaration -- Java's own two node
    types for what this project calls one thing, and this grammar's
    counterpart to that split."""
    name_node = node.child_by_field_name("name")
    if name_node is None or node.child_by_field_name("body") is None:
        # A missing body means an interface signature or an abstract
        # method -- nothing to walk, and the concrete override elsewhere is
        # what a call to this name actually resolves to.
        return
    params_node = node.child_by_field_name("parameters")
    is_public = "public" in _modifiers(node, src)
    reason, definitive = entry_reason(node, params_node, owner.supertypes, is_public, src)
    _create_method(node, _text(name_node, src), src, rel, index, owner, pending_refs, reason, definitive)


def _handle_route_registration(call: Node, args: Node, src: bytes, rel: str, index: Index,
                               pending_refs: list) -> None:
    func = call.child_by_field_name("function")
    name_node = func.child_by_field_name("name") if func is not None else None
    verb = _text(name_node, src).removeprefix("Map").upper() if name_node is not None else "ROUTE"
    path = route_path(args, src)
    handler = route_handler(args)
    if handler is None:
        return
    description = f"{verb} {path}"
    if handler.type == "lambda_expression":
        _create_method(handler, description, src, rel, index, Owner(), pending_refs,
                       reason=description, definitive=True)
    elif handler.type == "identifier":
        pending_refs.append((_text(handler, src), rel, description))
    elif handler.type == "member_access_expression":
        pending_refs.append((_short_name(handler, src), rel, description))


def _callee_name(func: Node, src: bytes) -> tuple[str | None, bool]:
    """The name a call resolves against, and whether its receiver is the
    literal `this` keyword."""
    if func.type == "identifier":
        return _text(func, src), False
    if func.type == "member_access_expression":
        name = func.child_by_field_name("name")
        if name is None:
            return None, False
        expr = func.child_by_field_name("expression")
        return _text(name, src), expr is not None and expr.type == "this"
    return None, False


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         pending_refs: list) -> None:
    if node.type in TYPE_DECLARATIONS:
        new_owner = _owner_of(node, src)
        if new_owner.name and new_owner.supertypes:
            existing = index.supertypes.get(new_owner.name, ())
            index.supertypes[new_owner.name] = existing + tuple(t for t in new_owner.supertypes if t not in existing)
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.children:
                _walk(child, src, rel, index, current, new_owner, pending_refs)
        return

    if node.type in ("method_declaration", "constructor_declaration"):
        _handle_method_like(node, src, rel, index, owner, pending_refs)
        return

    if node.type == "invocation_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is not None:
            callee, receiver_is_self = _callee_name(func, src)
            if callee is not None:
                index.calls.append(Call(
                    file=rel, callee=callee,
                    arity=sum(1 for c in args.children if c.type == "argument") if args is not None else 0,
                    line=node.start_point[0] + 1, caller=current, receiver_is_self=receiver_is_self,
                ))
        if (args is not None and func is not None and func.type == "member_access_expression"
                and is_route_registration(node, src)):
            # The arguments subtree is registration wiring (the path
            # literal, the handler) -- walking it again generically below
            # would re-discover an inline lambda's body as belonging to
            # whatever function called .MapGet(), not to the synthetic
            # handler Method just created for it above.
            _handle_route_registration(node, args, src, rel, index, pending_refs)
            for child in node.children:
                if child is not args:
                    _walk(child, src, rel, index, current, owner, pending_refs)
            return

        for child in node.children:
            _walk(child, src, rel, index, current, owner, pending_refs)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner, pending_refs)
