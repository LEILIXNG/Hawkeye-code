"""What makes a JS/TS function something a request can enter through.

Two shapes, because Express/Koa and NestJS route a request two completely
different ways. Express and Koa register a plain function *call* --
`app.get(path, handler)` -- so the handler is proven by where it sits as an
argument, not by anything written on the function itself. NestJS is
TypeScript-idiomatic and routes by decorator, the same shape Java's
annotations and Python's route decorators use, just spelled with a leading
capital (`@Get()`, not `@get()`) because Nest's decorators are classes.

Not attempted here: Next.js's file-based routing (`pages/api/*.js`'s
default export, `app/**/route.ts`'s named `GET`/`POST` exports) has no
in-function signal to read at all -- the entry point is a fact about the
file path and the export shape, not the function body. Documented as a gap
rather than guessed at, the same way Django's urls.py resolution is.
"""
from tree_sitter import Node

from scanner.callgraph.js_syntax import _short_name, _text

# get/post/etc. register that one HTTP method; `all` registers every one.
# `use` is deliberately excluded -- it is Express's generic
# middleware-mounting call (`app.use(express.static(...))`,
# `app.use(bodyParser.json())`), and treating every argument to it as a
# route handler would manufacture far more false entry points than it
# would catch real ones.
HTTP_METHOD_NAMES = frozenset({"get", "post", "put", "delete", "patch", "options", "head", "all"})

# NestJS's own decorators for the same set, capitalised because they are
# classes (`@Get()` instantiates a class named Get), not functions.
NEST_DECORATOR_NAMES = frozenset(name.capitalize() for name in HTTP_METHOD_NAMES)


def is_route_registration(call: Node, src: bytes) -> bool:
    """Whether a call_expression is `<something>.<http-method>(path, ...,
    handler)` -- Express's and Koa's shape for wiring a route, identical in
    both frameworks. Requires at least two arguments (a path and a
    handler): `app.get("view engine")` -- reading a setting, not
    registering anything -- only ever has one, so the count alone rules
    out Express's other, unrelated overload of `.get()`.
    """
    func = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    if func is None or func.type != "member_expression" or args is None:
        return False
    prop = func.child_by_field_name("property")
    if prop is None or _text(prop, src) not in HTTP_METHOD_NAMES:
        return False
    return sum(1 for c in args.children if c.is_named) >= 2


def route_description(call: Node, src: bytes) -> str:
    """`"GET /users/:id"` from `router.get("/users/:id", handler)`, for the
    synthetic entry point's name and its entry_reason -- readable in a
    report and in the LLM's context without needing the handler to have
    had a name of its own."""
    func = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    method = _short_name(func.child_by_field_name("property"), src).upper()
    first_arg = args.named_children[0] if args and args.named_children else None
    path = _text(first_arg, src).strip("'\"`") if first_arg is not None and first_arg.type == "string" else "?"
    return f"{method} {path}"


def nest_decorator_entry(decorators: list[Node], src: bytes) -> tuple[str, bool] | None:
    """Whether any decorator collected on a method_definition is one of
    NestJS's route decorators."""
    for dec in decorators:
        inner = next((c for c in dec.children if c.type not in ("@",)), None)
        if inner is None:
            continue
        call = inner if inner.type == "call_expression" else None
        name_node = call.child_by_field_name("function") if call is not None else (
            inner if inner.type == "identifier" else None)
        if name_node is None or name_node.type != "identifier":
            continue
        name = _text(name_node, src)
        if name in NEST_DECORATOR_NAMES:
            return f"@{name}(...)", True
    return None
