"""Parsing JavaScript/TypeScript sources into the same Method/Call/Owner
shapes the Java and Python sides produce, so index_workspace() can hand all
three to one shared traversal with no language check anywhere in
traverse.py.

The one real structural difference from the other two languages: a route
handler is very often not a *named* function at all -- `app.get(path, (req,
res) => {...})` passes the handler as a bare expression, with nothing else
in the source ever calling it by name. Java and Python both name every
function before anything can call it; JS does not, so this module creates
a Method for such a handler at the call site itself, synthesizing its name
from the route rather than reading one off a declaration. A second, rarer
shape -- `app.get(path, namedHandler)`, referencing a function declared
elsewhere in the same file -- cannot be resolved on the first pass (the
declaration may come later, or the reference may run before the walk
reaches it), so it is recorded and resolved once the whole file is known.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.js_entrypoints import is_route_registration, nest_decorator_entry, route_description
from scanner.callgraph.js_syntax import (
    FUNCTION_SHAPED_TYPES,
    _arity,
    _call_arity,
    _callee,
    _text,
    parser_for,
)
from scanner.callgraph.model import Call, Index, Method, Owner

# .d.ts is excluded by parser_for() itself (type declarations, no runtime
# code); the two globs below are given to Path.rglob() separately since a
# single "*.ts" pattern matches "*.d.ts" too.
_SOURCE_GLOBS = ("*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx")


def index_js_workspace(root: Path, index: Index) -> None:
    """Parses every JS/TS file under `root` into `index`'s methods and call
    sites, additively -- the same contract python_index.index_python_workspace
    has, so a checkout mixing any of Java, Python and JS/TS ends up in one
    graph rather than several that cannot see each other."""
    pending_refs: list[tuple[str, str, str]] = []
    for glob in _SOURCE_GLOBS:
        for path in sorted(root.rglob(glob)):
            if path.name.endswith(".d.ts"):
                continue
            parser = parser_for(path.suffix)
            if parser is None:
                continue
            try:
                src = path.read_bytes()
            except OSError:
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(),
                 pending_refs=pending_refs)
    _resolve_named_references(index, pending_refs)


def _resolve_named_references(index: Index, pending_refs: list[tuple[str, str, str]]) -> None:
    """`app.get(path, someHandler)` cannot be proven an entry point until
    someHandler's declaration is known -- which the single-pass walk above
    may not have reached yet when it saw the call. Same-file only: JS
    imports are as free-form as Java's or Python's cross-file calls
    already are, and a wrong file match here would silently promote an
    unrelated same-named function into a false entry point."""
    for name, file, description in pending_refs:
        for method in index.methods:
            if method.file == file and method.name == name and not method.entry_reason:
                method.entry_reason = description
                method.entry_definitive = True


def _method_arity(func: Node, src: bytes) -> int:
    params = func.child_by_field_name("parameters")
    if params is not None:
        return _arity(params, src)
    # An arrow function with exactly one parameter and no parens --
    # `x => x + 1` -- carries it under `parameter` (singular), not
    # `parameters`; there is no rest-parameter form of this shape.
    return 1 if func.child_by_field_name("parameter") is not None else 0


def _create_function_method(func: Node, name: str, src: bytes, rel: str, index: Index, owner: Owner,
                            pending_refs: list, entry_reason: str = "", entry_definitive: bool = False) -> Method:
    method = Method(
        file=rel, name=name, arity=_method_arity(func, src), owner=owner,
        start_line=func.start_point[0] + 1, end_line=func.end_point[0] + 1,
        entry_reason=entry_reason, entry_definitive=entry_definitive,
    )
    index.methods.append(method)
    body = func.child_by_field_name("body")
    if body is not None:
        for child in body.children:
            _walk(child, src, rel, index, method, owner, pending_refs)
    return method


def _handle_class(node: Node, src: bytes, rel: str, index: Index, current: Method | None,
                  pending_refs: list) -> None:
    from scanner.callgraph.js_syntax import _base_name

    name_node = node.child_by_field_name("name")
    new_owner = Owner(name=_text(name_node, src) if name_node is not None else "",
                      supertypes=_base_name(node, src))
    if new_owner.name:
        index.supertypes[new_owner.name] = new_owner.supertypes

    body = node.child_by_field_name("body")
    if body is None:
        return
    pending_decorators: list[Node] = []
    for child in body.children:
        if child.type == "decorator":
            pending_decorators.append(child)
            continue
        if child.type == "method_definition":
            _handle_method(child, src, rel, index, new_owner, pending_decorators, pending_refs)
            pending_decorators = []
            continue
        pending_decorators = []
        _walk(child, src, rel, index, current, new_owner, pending_refs)


def _handle_method(node: Node, src: bytes, rel: str, index: Index, owner: Owner,
                   decorators: list[Node], pending_refs: list) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    found = nest_decorator_entry(decorators, src)
    reason, definitive = found if found else ("", False)
    _create_function_method(node, _text(name_node, src), src, rel, index, owner, pending_refs, reason, definitive)


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         pending_refs: list) -> None:
    if node.type == "class_declaration":
        _handle_class(node, src, rel, index, current, pending_refs)
        return

    if node.type == "method_definition":
        # Reached directly rather than through _handle_class's own body
        # loop -- a class_declaration nested somewhere this walk did not
        # special-case. No decorators to read in that path.
        _handle_method(node, src, rel, index, owner, [], pending_refs)
        return

    if node.type == "function_declaration":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            _create_function_method(node, _text(name_node, src), src, rel, index, owner, pending_refs)
        return

    if node.type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if (name_node is not None and name_node.type == "identifier"
                and value_node is not None and value_node.type in FUNCTION_SHAPED_TYPES):
            _create_function_method(value_node, _text(name_node, src), src, rel, index, owner, pending_refs)
            return

    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and left.type == "member_expression" and right is not None \
                and right.type in FUNCTION_SHAPED_TYPES:
            prop = left.child_by_field_name("property")
            if prop is not None:
                _create_function_method(right, _text(prop, src), src, rel, index, owner, pending_refs)
                return

    if node.type == "call_expression":
        args = node.child_by_field_name("arguments")
        obj_name, callee_name, receiver_is_this = _callee(node, src)
        if callee_name:
            index.calls.append(Call(
                file=rel, callee=callee_name, arity=_call_arity(args) if args is not None else 0,
                line=node.start_point[0] + 1, caller=current, receiver_is_self=receiver_is_this,
            ))

        handled_child = None
        if args is not None and is_route_registration(node, src) and args.named_children:
            last = args.named_children[-1]
            if last.type in FUNCTION_SHAPED_TYPES:
                description = route_description(node, src)
                _create_function_method(last, description, src, rel, index, Owner(), pending_refs,
                                        entry_reason=description, entry_definitive=True)
                handled_child = last
            elif last.type == "identifier":
                pending_refs.append((_text(last, src), rel, route_description(node, src)))

        for child in node.children:
            if child is handled_child:
                continue
            _walk(child, src, rel, index, current, owner, pending_refs)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner, pending_refs)
