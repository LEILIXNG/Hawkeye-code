"""Parsing Kotlin sources into the same Method/Call/Owner shapes the Java,
Python, JS/TS, Go, C++, Rust, C#, PHP and Ruby sides produce, so
index_workspace() can hand all ten to one shared traversal with no
language check anywhere in traverse.py.

Structurally closest to Java's for the Spring half: methods live inside
class bodies, `this` is a fixed keyword, annotations sit on a `modifiers`
node. The one thing Java's own walk never has to do: thread a *path
prefix* through the recursion. Ktor builds a route tree out of nested
DSL calls -- `route("/api") { get("/users") { ... } }` -- and the leaf
verb call's own path argument (`/users`) is only half the real path; the
other half comes from however many `route(...)` blocks enclose it. So
`_walk()` here carries one more piece of state past `current`/`owner`
than every earlier language's own version needed: `route_prefix`,
extended each time a `route(...)` call's lambda body is entered and
otherwise passed through unchanged.

A Ktor verb call (`get`/`post`/...) is recognised by a second grammar
quirk this project has not met before: a call ending in a trailing lambda
block carries that lambda as a second, separate child (`annotated_lambda`)
rather than inside its `value_arguments` -- `trailing_lambda_call()` reads
that shape, and the handler is a synthetic Method built straight from the
lambda body, the same "index this closure itself" trade js_index.py's and
rust_index.py's own inline-handler creation make.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.kotlin_entrypoints import HTTP_VERBS, ROUTE_CALL_NAME, entry_reason
from scanner.callgraph.kotlin_syntax import (_annotation_entries, _arity, _first_string_arg, _parser,
                                             _supertype_names, _text, _type_name)
from scanner.callgraph.model import Call, Index, Method, Owner

TYPE_DECLARATIONS = ("class_declaration", "object_declaration")


def index_kotlin_workspace(root: Path, index: Index) -> None:
    """Parses every .kt file under `root` into `index`'s methods and call
    sites, additively -- the same contract every other index_*_workspace
    function already has. No test-file convention to skip: JUnit tests
    live under a project-chosen `src/test/kotlin/` directory, which the
    bare `test`/`tests` names in ruleset.yml's exclude_paths already
    catch (the same Maven/Gradle convention Java's own `src/test/`
    exclusion already covers)."""
    parser = _parser()
    for path in sorted(root.rglob("*.kt")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(), route_prefix="")


def _owner_of(node: Node, src: bytes) -> Owner:
    name_node = node.child_by_field_name("name")
    name = _text(name_node, src) if name_node is not None else ""
    return Owner(name=name, supertypes=_supertype_names(node, src))


def _create_method(decl_node: Node, name: str, src: bytes, rel: str, index: Index, owner: Owner,
                   route_prefix: str, params_node: Node | None = None, body: Node | None = None,
                   reason: str = "", definitive: bool = False) -> Method:
    """Shared by a declared `fun` and a Ktor handler's own lambda body --
    only the former has a real parameter list to read arity off; a
    synthetic handler Method (no `params_node`) is arity 0, the same
    convention rust_index.py's and csharp_index.py's own inline-closure
    handlers use."""
    method = Method(
        file=rel, name=name, arity=_arity(params_node), owner=owner,
        start_line=decl_node.start_point[0] + 1, end_line=decl_node.end_point[0] + 1,
        entry_reason=reason, entry_definitive=definitive,
    )
    index.methods.append(method)
    if body is not None:
        _walk(body, src, rel, index, method, owner, route_prefix)
    return method


def _handle_function(node: Node, src: bytes, rel: str, index: Index, owner: Owner, route_prefix: str) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    modifiers = next((c for c in node.children if c.type == "modifiers"), None)
    reason, definitive = entry_reason(_annotation_entries(modifiers, src), src) if modifiers is not None else ("", False)
    # Neither field carries a name in this grammar -- found by type, the
    # same trap kotlin_syntax.py's own annotation/supertype readers hit.
    params_node = next((c for c in node.children if c.type == "function_value_parameters"), None)
    body = next((c for c in node.children if c.type == "function_body"), None)
    _create_method(node, _text(name_node, src), src, rel, index, owner, route_prefix, params_node, body,
                   reason, definitive)


def _call_head(call_expr: Node, src: bytes) -> tuple[str | None, Node | None]:
    """`(name, value_arguments)` for a plain `name(...)` call -- the
    shape a Ktor verb/route call always has as either the whole call or
    the non-lambda half of a trailing-lambda call."""
    if not call_expr.children:
        return None, None
    first = call_expr.children[0]
    if first.type != "identifier":
        return None, None
    args = next((c for c in call_expr.children[1:] if c.type == "value_arguments"), None)
    return _text(first, src), args


def trailing_lambda_call(call_expr: Node) -> Node | None:
    """The `lambda_literal` a trailing-block call ends in, or None. Such a
    call is always exactly `[<call-or-identifier>, annotated_lambda]` in
    this grammar -- no `value_arguments` field at all when there are no
    parenthesized arguments (`routing { ... }`), and the lambda sitting
    beside, not inside, `value_arguments` when there are (`get("/x")
    { ... }`)."""
    if len(call_expr.children) != 2 or call_expr.children[1].type != "annotated_lambda":
        return None
    return next((c for c in call_expr.children[1].children if c.type == "lambda_literal"), None)


def _callee_name(call_expr: Node, src: bytes) -> tuple[str | None, bool]:
    """The name a call resolves against, and whether its receiver is the
    literal `this` keyword. Handles the three shapes a call's own first
    child can be: a bare name, `receiver.name`, or (a trailing-lambda
    call) another call_expression nested one level in, resolved by
    recursing into it."""
    if not call_expr.children:
        return None, False
    first = call_expr.children[0]
    if first.type == "identifier":
        return _text(first, src), False
    if first.type == "navigation_expression":
        children = first.children
        name_node = children[-1] if children and children[-1].type == "identifier" else None
        receiver = children[0] if children else None
        if name_node is None:
            return None, False
        return _text(name_node, src), receiver is not None and receiver.type == "this_expression"
    if first.type == "call_expression":
        return _callee_name(first, src)
    return None, False


def _call_arity(call_expr: Node) -> int:
    args = next((c for c in call_expr.children if c.type == "value_arguments"), None)
    if args is None and call_expr.children and call_expr.children[0].type == "call_expression":
        args = next((c for c in call_expr.children[0].children if c.type == "value_arguments"), None)
    count = sum(1 for c in args.children if c.type == "value_argument") if args is not None else 0
    # A trailing lambda is itself the call's last argument in Kotlin's own
    # calling convention, not merely syntax sugar sitting beside the rest.
    if call_expr.children and call_expr.children[-1].type == "annotated_lambda":
        count += 1
    return count


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         route_prefix: str) -> None:
    if node.type in TYPE_DECLARATIONS:
        new_owner = _owner_of(node, src)
        if new_owner.name and new_owner.supertypes:
            existing = index.supertypes.get(new_owner.name, ())
            index.supertypes[new_owner.name] = existing + tuple(t for t in new_owner.supertypes if t not in existing)
        body = next((c for c in node.children if c.type == "class_body"), None)
        if body is not None:
            for child in body.children:
                _walk(child, src, rel, index, current, new_owner, route_prefix)
        return

    if node.type == "function_declaration":
        _handle_function(node, src, rel, index, owner, route_prefix)
        return

    if node.type == "call_expression":
        callee, receiver_is_self = _callee_name(node, src)
        if callee is not None:
            index.calls.append(Call(
                file=rel, callee=callee, arity=_call_arity(node),
                line=node.start_point[0] + 1, caller=current, receiver_is_self=receiver_is_self,
            ))

        name, args = _call_head(node.children[0], src) if node.children and node.children[0].type == "call_expression" \
            else _call_head(node, src)
        lambda_node = trailing_lambda_call(node)
        if lambda_node is not None and name is not None:
            if name in HTTP_VERBS:
                full_path = route_prefix + (_first_string_arg(args, src) or "")
                description = f"{name.upper()} {full_path}"
                _create_method(lambda_node, description, src, rel, index, owner, route_prefix,
                               body=lambda_node, reason=description, definitive=True)
                return
            if name == ROUTE_CALL_NAME:
                segment = _first_string_arg(args, src) or ""
                _walk(lambda_node, src, rel, index, current, owner, route_prefix + segment)
                return

        for child in node.children:
            _walk(child, src, rel, index, current, owner, route_prefix)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner, route_prefix)
