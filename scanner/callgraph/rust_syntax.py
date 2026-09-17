"""Thin readers over a Rust tree-sitter node: source text, type names,
arity, string-literal attribute arguments. The Rust-grammar counterpart to
go_syntax.py, python_syntax.py and js_syntax.py.

Structurally closest to Go's: Rust has no `extends`/annotation syntax
either, but unlike Go it does have an explicit trait-implementation
relationship (`impl Trait for Type`) to read for Owner.supertypes, and its
receiver is always spelled the one fixed way (`self`/`&self`/`&mut self`),
so Call.receiver_is_self is a literal node-type check the way Java's `this`
is, not an author-chosen name read off a receiver clause the way Go's is.
"""
import tree_sitter_rust as tsrust
from tree_sitter import Language, Node, Parser


def _parser() -> Parser:
    return Parser(Language(tsrust.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _short_name(node: Node, src: bytes) -> str:
    """The bare name at the end of a scoped path or a field access:
    `actix_web::get` and `h.svc.lookup`'s field both read as `get`/`lookup`,
    the same trim every other language's syntax module applies to a
    qualified reference."""
    if node.type == "scoped_identifier":
        name = node.child_by_field_name("name")
        return _text(name, src) if name is not None else _text(node, src)
    if node.type == "field_expression":
        field = node.child_by_field_name("field")
        return _text(field, src) if field is not None else ""
    return _text(node, src)


def _type_name(node: Node, src: bytes) -> str:
    """A type node's name, module-qualified where the source is
    (`web::Json`, not just `Json`) since that qualification is exactly what
    tells an actix/axum extractor type apart from an unrelated same-named
    local type. References (`&T`, `&mut T`) and generic type arguments
    (`Json<CreateUser>`) are stripped down to the base name they carry --
    a handler parameter is declared `web::Json<T>` or `&HttpRequest`, never
    the bare generic or an owned value, so unwrapping both is required just
    to reach the name at all.
    """
    if node.type == "reference_type":
        inner = node.child_by_field_name("type")
        return _type_name(inner, src) if inner is not None else ""
    if node.type == "generic_type":
        base = node.child_by_field_name("type")
        return _type_name(base, src) if base is not None else _text(node, src)
    if node.type in ("scoped_type_identifier", "scoped_identifier"):
        path = node.child_by_field_name("path")
        name = node.child_by_field_name("name")
        if name is None:
            return _text(node, src)
        return f"{_type_name(path, src)}::{_text(name, src)}" if path is not None else _text(name, src)
    return _text(node, src)


def _param_type_names(params_node: Node, src: bytes) -> list[str]:
    """Every ordinary parameter's type name, in declaration order.
    `self_parameter` (`self`/`&self`/`&mut self`) is not a `parameter` node
    at all in this grammar, so it is excluded for free rather than needing
    the explicit skip Go's receiver clause does."""
    names = []
    for child in params_node.children:
        if child.type != "parameter":
            continue
        type_node = child.child_by_field_name("type")
        if type_node is not None:
            names.append(_type_name(type_node, src))
    return names


def _arity(params_node: Node, src: bytes) -> int:
    """Declared parameter count, `self` excluded. Unlike Go's `a, b int`
    (one node, two names), Rust gives every parameter -- even ones sharing a
    destructuring pattern like `Json(payload): Json<T>` -- its own
    `parameter` node, so a plain count needs no name-splitting."""
    return sum(1 for c in params_node.children if c.type == "parameter")


def _has_self(params_node: Node) -> bool:
    return any(c.type == "self_parameter" for c in params_node.children)


def _string_literal_value(node: Node, src: bytes) -> str:
    content = next((c for c in node.children if c.type == "string_content"), None)
    return _text(content, src) if content is not None else _text(node, src).strip('"')
