"""What makes a Rust function something a request can enter through.

Two shapes cover the two dominant web frameworks. Actix-web and Rocket
handlers are marked with an attribute macro directly on the function --
`#[get("/users/{id}")]` -- the same declarative role Java's @GetMapping and
Python's @app.route play, read here as a preceding `attribute_item` sibling
rather than a wrapping node, since that is how this grammar attaches them.
Axum has no such macro in its core crate; a handler is proven instead by a
route-registration *call* -- `.route("/users/:id", get(handler))` -- the
same calling-convention shape go_entrypoints.py and js_entrypoints.py
already recognise, extended here to also cover actix's own builder style
(`web::get().to(handler)`), which nests the handler under a `.to(...)` call
chained onto the verb instead of passing it as the verb call's own argument.

The one fallback with no attribute or registration-call equivalent is the
parameter-type check: a function taking `HttpRequest`, `web::Json<T>` or
axum's `State<T>`/`Path<T>`/`Query<T>` is recognisably a handler by its
signature alone -- the same weak-hint role Go's HANDLER_PARAM_TYPES and
Java's HttpServletRequest-typed-parameter fallback play, useful for a
handler wired through a registration shape this module does not recognise
(warp's filter combinators, a hand-rolled routing table).
"""
from tree_sitter import Node

from scanner.callgraph.rust_syntax import _param_type_names, _short_name, _string_literal_value, _text

# Attribute-macro verbs actix-web and Rocket both use directly on a handler
# function. `route` is actix's generic form (`#[route("/x", method = "GET")]`)
# -- the specific method is not parsed out of its token tree, only the path,
# since the entry point is proven either way and a generic "ROUTE" label
# costs nothing a reader cannot see from the source line itself.
ATTRIBUTE_VERBS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})
GENERIC_ROUTE_ATTRIBUTE = "route"

# Route-registration builder calls. `.route(path, get(handler))` is axum's
# own shape; `.route(path, web::get().to(handler))` is actix's builder-style
# alternative to its own attribute macros above -- both are recognised by
# the same nested-verb-call search in rust_index.py.
ROUTE_METHOD_NAMES = frozenset({"route", "route_service"})
HTTP_ROUTE_VERBS = frozenset({"get", "post", "put", "delete", "patch", "head", "options", "any", "on"})

# Parameter types that mark a function as a request handler regardless of
# how (or whether) this module can see it being registered.
HANDLER_PARAM_TYPES = frozenset({
    "HttpRequest", "HttpResponse", "Request", "Response",
    "web::Json", "web::Query", "web::Path", "web::Form", "web::Data", "web::Bytes", "web::Payload",
    "Json", "Query", "Path", "Form", "State", "Extension", "Multipart",
})


def _attribute_name(attr: Node, src: bytes) -> str:
    first = attr.children[0] if attr.children else None
    return _short_name(first, src) if first is not None else ""


def _attribute_path_arg(attr: Node, src: bytes) -> str:
    token_tree = next((c for c in attr.children if c.type == "token_tree"), None)
    if token_tree is None:
        return "?"
    string_lit = next((c for c in token_tree.children if c.type == "string_literal"), None)
    return _string_literal_value(string_lit, src) if string_lit is not None else "?"


def route_attributes(func_node: Node, src: bytes) -> list[tuple[str, str]]:
    """`[(verb, path), ...]` from every `#[get("/x")]`-shaped attribute
    directly above `func_node`. Attributes are preceding siblings in this
    grammar (`#[cfg(test)]` and `#[get(...)]` both sit next to the function,
    not inside it), so this walks `prev_sibling` rather than `children`.
    """
    results = []
    sib = func_node.prev_sibling
    while sib is not None and sib.type == "attribute_item":
        attr = next((c for c in sib.children if c.type == "attribute"), None)
        if attr is not None:
            name = _attribute_name(attr, src)
            if name in ATTRIBUTE_VERBS:
                results.append((name.upper(), _attribute_path_arg(attr, src)))
            elif name == GENERIC_ROUTE_ATTRIBUTE:
                results.append(("ROUTE", _attribute_path_arg(attr, src)))
        sib = sib.prev_sibling
    return results


def _has_handler_param(params_node: Node, src: bytes) -> bool:
    return any(t in HANDLER_PARAM_TYPES for t in _param_type_names(params_node, src))


def entry_reason(func_node: Node, params_node: Node, src: bytes) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint.

    An attribute macro is proof -- it is never written on a plain helper.
    A handler-shaped parameter with no macro above it is only a hint, the
    same trade Go's own parameter-type fallback makes: a plain function can
    be handed an `HttpRequest` too.
    """
    routes = route_attributes(func_node, src)
    if routes:
        return ", ".join(f"{verb} {path}" for verb, path in routes), True
    if params_node is not None and _has_handler_param(params_node, src):
        return "handler-shaped parameter", False
    return "", False


def is_route_registration(call: Node, src: bytes) -> bool:
    """Whether a call_expression is `<something>.route(path, ..., handler)`.
    Requires at least two arguments, the same guard Go's and JS's own checks
    apply, ruling out a zero/one-argument call that merely shares the method
    name (`Router::route` vs. some unrelated `.route(x)`)."""
    func = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    if func is None or func.type != "field_expression" or args is None:
        return False
    field = func.child_by_field_name("field")
    if field is None or _text(field, src) not in ROUTE_METHOD_NAMES:
        return False
    return sum(1 for c in args.children if c.is_named) >= 2


def route_path(args: Node, src: bytes) -> str:
    first = args.named_children[0] if args.named_children else None
    return _string_literal_value(first, src) if first is not None and first.type == "string_literal" else "?"


def iter_route_handlers(node: Node, src: bytes):
    """`(verb, handler_node)` for every handler nested inside a `.route(...)`
    call's arguments, searched recursively so both supported shapes resolve
    in one pass: axum's `get(handler)` (the verb call's own argument) and
    actix's `web::get().to(handler)` (the handler sits under a chained
    `.to(...)` call instead, so the verb is one step up the receiver chain
    rather than in the same call's arguments).
    """
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        call_args = node.child_by_field_name("arguments")
        if func is not None and call_args is not None:
            name = _short_name(func, src)
            handler = call_args.named_children[0] if call_args.named_children else None
            if name in HTTP_ROUTE_VERBS and handler is not None:
                yield name.upper(), handler
            elif func.type == "field_expression":
                field = func.child_by_field_name("field")
                if field is not None and _text(field, src) == "to" and handler is not None:
                    yield "ROUTE", handler
    for child in node.children:
        yield from iter_route_handlers(child, src)
