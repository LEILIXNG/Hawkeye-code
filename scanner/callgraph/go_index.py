"""Parsing Go sources into the same Method/Call/Owner shapes the Java,
Python and JS/TS sides produce, so index_workspace() can hand all four to
one shared traversal with no language check anywhere in traverse.py.

Structurally closest to js_index.py, not to Java's or Python's: Go has no
annotations or decorators, so a route handler is recognised by calling
convention rather than by anything written on the function itself (see
go_entrypoints.py). Its own route-registration call -- `router.GET(path,
handler)`, `http.HandleFunc(path, handler)` -- may carry the handler as an
inline func literal (indexed at the call site, same as JS's arrow-function
handlers), a bare function reference, or a *method value* (`h.GetUser`,
naming a receiver instance's method) -- a shape JS's own two handler forms
do not have an equivalent of. All three of the latter are resolved by name
in a same-file second pass exactly the way JS resolves `app.get(path,
namedHandler)`, since Go, like JS, is not guaranteed to have indexed the
referenced declaration yet when the registration call is reached.

Go's other structural difference from every language here so far: it has
no `this`/`self` keyword. A method's receiver variable is named by the
author (`h`, `svc`, `self`, anything), so Call.receiver_is_self is decided
by comparing a call's receiver identifier against the enclosing method's
own declared receiver name (go_syntax._receiver), threaded through the walk
as `receiver_var`, rather than checked against a fixed keyword.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.go_entrypoints import entry_reason, is_route_registration, route_description
from scanner.callgraph.go_syntax import _arity, _call_arity, _parser, _receiver, _short_name, _text
from scanner.callgraph.model import Call, Index, Method, Owner


def index_go_workspace(root: Path, index: Index) -> None:
    """Parses every .go file under `root` into `index`'s methods and call
    sites, additively -- the same contract index_python_workspace and
    index_js_workspace already have, so a checkout mixing any of these
    languages ends up in one graph rather than several that cannot see each
    other. `_test.go` files are skipped: they are Go's own test-tree
    convention (there is no separate `test/` directory to exclude the way
    ruleset.yml already excludes Java/Python/JS test trees), and mirrors
    the `*_test.go` entry added to ruleset.yml's exclude_paths for the same
    reason.
    """
    parser = _parser()
    pending_refs: list[tuple[str, str, str]] = []
    for path in sorted(root.rglob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(),
             receiver_var=None, pending_refs=pending_refs)
    _resolve_named_references(index, pending_refs)


def _resolve_named_references(index: Index, pending_refs: list[tuple[str, str, str]]) -> None:
    """A route registration naming its handler by reference -- a bare
    function name or a `receiver.Method` value -- rather than an inline
    func literal. Same-file only, matched by bare name alone (a method
    value's receiver type is not checked), for the same reason JS's own
    resolution is: a wrong cross-file or cross-type match would silently
    promote an unrelated same-named function into a false entry point.

    Overwrites a non-definitive entry_reason rather than only an empty one
    -- unlike JS, a Go handler this call-registration pass resolves has
    usually already been given the weaker "handler-shaped parameter" hint
    by go_entrypoints.entry_reason() (it takes an http.ResponseWriter/
    gin.Context parameter, which is exactly what makes it a plausible
    handler in the first place), and proof from an actual registration call
    must be allowed to replace that hint rather than being silently
    dropped because the field was not empty.
    """
    for name, file, description in pending_refs:
        for method in index.methods:
            if method.file == file and method.name == name and not method.entry_definitive:
                method.entry_reason = description
                method.entry_definitive = True


def _create_function_method(func_node: Node, name: str, src: bytes, rel: str, index: Index, owner: Owner,
                            receiver_var: str | None, pending_refs: list,
                            reason: str = "", definitive: bool = False) -> Method:
    params = func_node.child_by_field_name("parameters")
    method = Method(
        file=rel, name=name, arity=_arity(params, src) if params is not None else 0, owner=owner,
        start_line=func_node.start_point[0] + 1, end_line=func_node.end_point[0] + 1,
        entry_reason=reason, entry_definitive=definitive,
    )
    index.methods.append(method)
    body = func_node.child_by_field_name("body")
    if body is not None:
        for child in body.children:
            _walk(child, src, rel, index, method, owner, receiver_var, pending_refs)
    return method


def _handle_named_declaration(node: Node, src: bytes, rel: str, index: Index, pending_refs: list) -> None:
    """function_declaration (a plain top-level func) or method_declaration
    (one with a receiver clause) -- the two node types Go's grammar uses
    for what every other language here calls one thing."""
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    if name_node is None or params_node is None:
        return
    name = _text(name_node, src)
    receiver_node = node.child_by_field_name("receiver")
    if receiver_node is not None:
        receiver_var, receiver_type = _receiver(receiver_node, src)
        owner = Owner(name=receiver_type)
    else:
        receiver_var, owner = None, Owner()
    reason, definitive = entry_reason(name, params_node, src)
    _create_function_method(node, name, src, rel, index, owner, receiver_var, pending_refs, reason, definitive)


def _handle_route_registration_argument(call: Node, args: Node, src: bytes, rel: str, index: Index,
                                        pending_refs: list) -> Node | None:
    """The last argument to a recognised route-registration call: an inline
    func literal is indexed here at the call site (there is nothing else to
    call it by); a bare identifier or a `receiver.Method` value is recorded
    for the same-file second pass instead, since its declaration may not
    have been walked yet. Returns the argument node when it was a func
    literal handled here, so the caller can skip re-walking it generically.
    """
    if not args.named_children:
        return None
    last = args.named_children[-1]
    description = route_description(call, src)
    if last.type == "func_literal":
        _create_function_method(last, description, src, rel, index, Owner(), None, pending_refs,
                                reason=description, definitive=True)
        return last
    if last.type == "identifier":
        pending_refs.append((_text(last, src), rel, description))
    elif last.type == "selector_expression":
        pending_refs.append((_short_name(last, src), rel, description))
    return None


def _callee_name(func: Node, src: bytes, receiver_var: str | None) -> tuple[str | None, bool]:
    """The name a call resolves against, and whether its receiver is the
    enclosing method's own receiver variable -- Go's spelling of Java's
    `this`/Python's `self`, read off the declared receiver name rather than
    a fixed keyword (see this module's docstring)."""
    if func.type == "identifier":
        return _text(func, src), False
    if func.type == "selector_expression":
        field = func.child_by_field_name("field")
        if field is None:
            return None, False
        operand = func.child_by_field_name("operand")
        receiver_is_self = (receiver_var is not None and operand is not None
                            and operand.type == "identifier" and _text(operand, src) == receiver_var)
        return _text(field, src), receiver_is_self
    return None, False


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         receiver_var: str | None, pending_refs: list) -> None:
    if node.type in ("function_declaration", "method_declaration"):
        _handle_named_declaration(node, src, rel, index, pending_refs)
        return

    if node.type == "short_var_declaration":
        # `handler := func(w, r) {...}`: a named local holding a func
        # literal, the same idiom JS's `const handler = (req, res) => ...`
        # is. Only the single-name/single-value shape is handled -- Go
        # allows `a, b := f()` multi-assignment, which never binds a bare
        # func literal on the right anyway.
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None:
            names = [c for c in left.children if c.type == "identifier"]
            values = [c for c in right.children if c.is_named]
            if len(names) == 1 and len(values) == 1 and values[0].type == "func_literal":
                _create_function_method(values[0], _text(names[0], src), src, rel, index, owner, None,
                                        pending_refs)
                return

    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is not None:
            callee, receiver_is_self = _callee_name(func, src, receiver_var)
            if callee is not None:
                index.calls.append(Call(
                    file=rel, callee=callee, arity=_call_arity(args) if args is not None else 0,
                    line=node.start_point[0] + 1, caller=current, receiver_is_self=receiver_is_self,
                ))

        handled_child = None
        if args is not None and is_route_registration(node, src):
            handled_child = _handle_route_registration_argument(node, args, src, rel, index, pending_refs)

        for child in node.children:
            if child is handled_child:
                continue
            _walk(child, src, rel, index, current, owner, receiver_var, pending_refs)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner, receiver_var, pending_refs)
