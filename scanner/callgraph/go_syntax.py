"""Thin readers over a Go tree-sitter node: source text, type names, arity,
method receivers. The Go-grammar counterpart to syntax.py, python_syntax.py
and js_syntax.py.

Go has no `extends`/`implements`/decorator syntax at all -- interfaces are
satisfied structurally, so there is nothing in the source for an
`Owner.supertypes`-style check to read the way Java's SERVLET_SUPERTYPES or
Python's DJANGO_VIEW_SUPERTYPES do. go_entrypoints.py recognises a handler by
calling convention (a route-registration call, or a recognised
context/request parameter type) instead, the same shape JS/Express uses for
the same reason -- see go_index.py's module docstring.
"""
import tree_sitter_go as tsgo
from tree_sitter import Language, Node, Parser

from scanner.callgraph.model import ANY_ARITY


def _parser() -> Parser:
    return Parser(Language(tsgo.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _short_name(node: Node, src: bytes) -> str:
    """The bare name at the end of a selector expression: `pkg.Func` and
    `h.svc.Lookup` both read as `Func`/`Lookup`, the same trim every other
    language's syntax module applies to a qualified reference."""
    if node.type == "selector_expression":
        field = node.child_by_field_name("field")
        return _text(field, src) if field is not None else ""
    return _text(node, src)


def _type_name(node: Node, src: bytes) -> str:
    """A type node's name, package-qualified where the source is
    (`http.ResponseWriter`, not just `ResponseWriter`) since that
    qualification is exactly what tells a stdlib/gin/echo context parameter
    apart from an unrelated same-named local type. Pointers, generic type
    arguments and slice/map wrappers are stripped down to the base name they
    carry -- a handler parameter is declared `*http.Request`, never `http.
    Request` by value, so unwrapping the pointer is required just to reach
    the name at all.
    """
    if node.type == "pointer_type":
        named = [c for c in node.children if c.is_named]
        return _type_name(named[0], src) if named else ""
    if node.type == "qualified_type":
        pkg = node.child_by_field_name("package")
        name = node.child_by_field_name("name")
        if name is None:
            return _text(node, src)
        return f"{_text(pkg, src)}.{_text(name, src)}" if pkg is not None else _text(name, src)
    if node.type == "generic_type":
        base = node.child_by_field_name("type")
        return _type_name(base, src) if base is not None else _text(node, src)
    return _text(node, src)


def _param_type_names(params_node: Node, src: bytes) -> list[str]:
    """Every parameter's type name, in declaration order. `a, b int` is one
    `parameter_declaration` node sharing one type across two names -- this
    still yields "int" once, since only the type matters here, not which or
    how many names bind to it."""
    names = []
    for child in params_node.children:
        if child.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        type_node = child.children[-1] if child.children else None
        if type_node is not None:
            names.append(_type_name(type_node, src))
    return names


def _arity(params_node: Node, src: bytes) -> int:
    """Declared parameter count. `variadic_parameter_declaration`
    (`items ...string`) matches any call-site argument count, the same
    treatment Python's `*args` and JS's `...rest` get. A plain
    `parameter_declaration` can name more than one parameter off one shared
    type (`a, b int` is arity 2, not 1) or none at all (an unnamed parameter
    in an interface method signature, still arity 1) -- counted by its
    `identifier` children, floored at 1.
    """
    count = 0
    for child in params_node.children:
        if child.type == "variadic_parameter_declaration":
            return ANY_ARITY
        if child.type == "parameter_declaration":
            names = [c for c in child.children if c.type == "identifier"]
            count += max(1, len(names))
    return count


def _receiver(receiver_params: Node, src: bytes) -> tuple[str | None, str]:
    """`(var_name_or_None, bare_type_name)` for a method's receiver --
    `(h *UserHandler)` -> `("h", "UserHandler")`, `(*UserHandler)` (no name,
    legal Go for a method that never uses its receiver) -> `(None,
    "UserHandler")`. The variable name is what lets a call inside the method
    be recognised as calling back onto the same receiver (Call.
    receiver_is_self); Go has no `this`/`self` keyword, so this is read off
    the receiver clause itself rather than checked against a fixed name the
    way Java and Python can.
    """
    decl = next((c for c in receiver_params.children if c.type == "parameter_declaration"), None)
    if decl is None:
        return None, ""
    name_node = next((c for c in decl.children if c.type == "identifier"), None)
    type_node = decl.children[-1] if decl.children else None
    var_name = _text(name_node, src) if name_node is not None else None
    type_name = _type_name(type_node, src) if type_node is not None else ""
    return var_name, type_name


def _call_arity(args_node: Node) -> int:
    return sum(1 for c in args_node.children if c.is_named)
