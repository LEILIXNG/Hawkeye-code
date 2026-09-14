"""What makes a Go function or method something a request can enter through.

Go has no annotations and no decorators, so unlike Java's REQUEST_MAPPING_
ANNOTATIONS or Python's ROUTE_DECORATOR_NAMES there is nothing written on
the handler declaration itself to recognise. Route registration in every
common Go web framework -- the standard library, gorilla/mux, chi, gin,
echo -- is a plain function *call* naming the path and the handler, the
same shape JS/Express uses (see js_entrypoints.py) and for the same reason:
`router.GET(path, handler)` proves the handler by where it sits as an
argument, not by anything on the function.

The one fallback with no JS equivalent is the parameter-type check: a
function taking `http.ResponseWriter` (or a framework's own request-context
type) is recognisably a handler by its signature alone, the same weak-hint
role Java's HttpServletRequest-typed-parameter and Python's Django
`request`-named-first-parameter play -- useful for a handler wired into a
routing table or a third-party router this module does not recognise by
call shape.
"""
from tree_sitter import Node

from scanner.callgraph.go_syntax import _param_type_names, _text

# GET/POST/etc. in both spellings actually used: gin and echo write them
# upper-case (`router.GET(...)`), chi and fiber write them capitalised
# (`r.Get(...)`). Handle/HandleFunc are the standard library's and gorilla/
# mux's own registration calls (`http.HandleFunc(path, handler)`,
# `mux.Handle(path, handler)`), spelled only the one way. Any is gin's
# catch-all-methods registration. Matched by method name alone, regardless
# of receiver or package -- the same trade JS's HTTP_METHOD_NAMES makes: an
# unrelated `.Handle(...)` on some other type costs a few false-entry lines
# of prompt, and missing a real route costs the answer. The >= 2-argument
# requirement in is_route_registration() below is what keeps this from
# also matching `some.Getter()`-shaped calls with no handler argument at
# all.
_HTTP_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT", "TRACE")
HTTP_METHOD_NAMES = frozenset(_HTTP_VERBS) | frozenset(v.capitalize() for v in _HTTP_VERBS) | {
    "Any", "Handle", "HandleFunc",
}

# Parameter types that mark a function as a request handler regardless of
# how (or whether) this module can see it being registered: the standard
# library's own handler signature, and the three next-most-common routers'
# request-context types.
HANDLER_PARAM_TYPES = frozenset({
    "http.ResponseWriter", "http.Request", "gin.Context", "echo.Context", "fiber.Ctx",
})


def is_route_registration(call: Node, src: bytes) -> bool:
    """Whether a call_expression is `<something>.<verb-or-Handle>(path, ...,
    handler)`. Requires at least two arguments the same way JS's check
    does, ruling out any zero/one-argument call that merely shares a
    method name with a route registration.
    """
    func = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    if func is None or func.type != "selector_expression" or args is None:
        return False
    field = func.child_by_field_name("field")
    if field is None or _text(field, src) not in HTTP_METHOD_NAMES:
        return False
    return sum(1 for c in args.children if c.is_named) >= 2


def route_description(call: Node, src: bytes) -> str:
    """`"GET /users/:id"` from `router.GET("/users/:id", handler)`, for the
    synthetic entry point's name and its entry_reason."""
    func = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    field = func.child_by_field_name("field")
    method = _text(field, src).upper() if field is not None else "?"
    first_arg = args.named_children[0] if args and args.named_children else None
    path = (_text(first_arg, src).strip("`\"")
            if first_arg is not None and first_arg.type in ("interpreted_string_literal", "raw_string_literal")
            else "?")
    return f"{method} {path}"


def _has_handler_param(params_node: Node, src: bytes) -> bool:
    return any(t in HANDLER_PARAM_TYPES for t in _param_type_names(params_node, src))


def entry_reason(name: str, params_node: Node, src: bytes) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint.

    `ServeHTTP` is Go's one named-method convention with no decorator or
    supertype available to confirm it against (the http.Handler interface
    is satisfied structurally, never declared) -- treated as proof only
    combined with the signature, the same pairing Java's SERVLET_ENTRY_
    METHODS applies to a supertype instead. Any other handler-shaped
    parameter list is a hint only, since a plain helper can be handed a
    `*http.Request` too.
    """
    if params_node is None:
        return "", False
    if name == "ServeHTTP" and _has_handler_param(params_node, src):
        return "ServeHTTP(http.ResponseWriter, *http.Request)", True
    if _has_handler_param(params_node, src):
        return "handler-shaped parameter", False
    return "", False
