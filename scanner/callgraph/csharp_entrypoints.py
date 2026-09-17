"""What makes a C# method something a request can enter through.

Three tiers, the same shape Java's own vocabulary uses:

1. An HTTP-verb or generic route attribute directly on the method
   (`[HttpGet("{id}")]`, `[Route("api/x")]`) is proof -- never written on a
   plain helper. ASP.NET Core's attribute-routing style.

2. A `public` method with no such attribute, declared on a type whose
   base list includes `Controller`/`ControllerBase`, is proof too --
   ASP.NET (Core and classic) MVC's convention-routed style, where every
   public action method on a controller is reachable by name whether or
   not anything marks it. The same pairing Java's SERVLET_ENTRY_METHODS
   applies with a supertype check instead of an attribute.

3. A parameter typed `HttpContext`/`HttpRequest`/`HttpResponse` with
   neither of the above is a hint, not proof -- the same weak-signal role
   Go's HANDLER_PARAM_TYPES and Java's HttpServletRequest fallback play,
   useful for a handler wired through a routing shape this module does not
   recognise (a hand-rolled middleware pipeline, a third-party router).

Minimal-API registration (`app.MapGet("/x", handler)`, ASP.NET Core 6+) is
a fourth, call-shaped signal -- mirrors Go's and Rust's own route-
registration-call recognition, and is read in csharp_index.py rather than
here since it resolves a *handler reference*, not a method declaration.
"""
from tree_sitter import Node

from scanner.callgraph.csharp_syntax import _param_type_names, _short_name, _string_literal_value, _text

HTTP_VERB_ATTRIBUTES = frozenset({"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "HttpHead",
                                 "HttpOptions"})
GENERIC_ROUTE_ATTRIBUTE = "Route"

# ASP.NET Core's own base class, and classic ASP.NET MVC / Web API's --
# actions are convention-routed by public method name on any of these.
CONTROLLER_SUPERTYPES = frozenset({"Controller", "ControllerBase", "ApiController"})

# Minimal-API endpoint registration. Matched by method name alone, the same
# trade Go's HTTP_METHOD_NAMES and axum/actix's HTTP_ROUTE_VERBS make.
MAP_METHOD_NAMES = frozenset({"MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch", "MapMethods"})

HANDLER_PARAM_TYPES = frozenset({"HttpContext", "HttpRequest", "HttpResponse"})


def _attribute_path_arg(attribute: Node, src: bytes) -> str:
    arg_list = next((c for c in attribute.children if c.type == "attribute_argument_list"), None)
    if arg_list is None:
        return "?"
    for arg in arg_list.children:
        if arg.type != "attribute_argument":
            continue
        string_lit = next((c for c in arg.children if c.type == "string_literal"), None)
        if string_lit is not None:
            return _string_literal_value(string_lit, src)
    return "?"


def route_attributes(decl_node: Node, src: bytes) -> list[tuple[str, str]]:
    """`[(verb, path), ...]` from every HTTP-verb/Route attribute on
    `decl_node`. Unlike Rust's attributes (preceding siblings), this
    grammar attaches an `attribute_list` as a direct child of the
    declaration it decorates."""
    results = []
    for attr_list in decl_node.children:
        if attr_list.type != "attribute_list":
            continue
        for attr in attr_list.children:
            if attr.type != "attribute":
                continue
            name_node = attr.child_by_field_name("name")
            name = _short_name(name_node, src) if name_node is not None else ""
            if name in HTTP_VERB_ATTRIBUTES:
                results.append((name.removeprefix("Http").upper(), _attribute_path_arg(attr, src)))
            elif name == GENERIC_ROUTE_ATTRIBUTE:
                results.append(("ROUTE", _attribute_path_arg(attr, src)))
    return results


def _has_handler_param(params_node: Node, src: bytes) -> bool:
    return any(t in HANDLER_PARAM_TYPES for t in _param_type_names(params_node, src))


def entry_reason(decl_node: Node, params_node: Node, owner_supertypes: tuple[str, ...],
                 is_public: bool, src: bytes) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint."""
    routes = route_attributes(decl_node, src)
    if routes:
        return ", ".join(f"{verb} {path}" for verb, path in routes), True
    if is_public and any(t in CONTROLLER_SUPERTYPES for t in owner_supertypes):
        return "convention-routed controller action", True
    if params_node is not None and _has_handler_param(params_node, src):
        return "handler-shaped parameter", False
    return "", False


def is_route_registration(call: Node, src: bytes) -> bool:
    """Whether a call_expression is `<something>.MapGet(path, handler)`.
    Requires at least two arguments, the same guard every other
    language's own registration-call check applies."""
    func = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    if func is None or func.type != "member_access_expression" or args is None:
        return False
    name_node = func.child_by_field_name("name")
    if name_node is None or _text(name_node, src) not in MAP_METHOD_NAMES:
        return False
    return sum(1 for c in args.children if c.type == "argument") >= 2


def route_path(args: Node, src: bytes) -> str:
    first = next((c for c in args.children if c.type == "argument"), None)
    if first is None:
        return "?"
    literal = next((c for c in first.children if c.type == "string_literal"), None)
    return _string_literal_value(literal, src) if literal is not None else "?"


def route_handler(args: Node) -> Node | None:
    """The handler argument: the second `argument` node, unwrapped down to
    the expression it carries. Unlike axum's nested verb-call chaining,
    `MapGet`/`MapPost`/etc. take the handler directly as their own second
    argument, so no recursive search is needed."""
    arguments = [c for c in args.children if c.type == "argument"]
    if len(arguments) < 2:
        return None
    return next((c for c in arguments[1].children if c.is_named), None)
