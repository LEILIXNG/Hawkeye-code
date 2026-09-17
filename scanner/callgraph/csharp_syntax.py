"""Thin readers over a C# tree-sitter node: source text, type names, arity,
string-literal attribute arguments. The C#-grammar counterpart to syntax.py
(Java), whose shape this module mirrors closely -- C# methods live inside
class/interface bodies the same way Java's do, `this` is a fixed keyword
the same way Java's is, and a class states every base type (class and
interfaces alike) in one place, unlike Rust's scattered `impl Trait for
Type` blocks.

The one thing this grammar does not give: separate `extends`/`implements`
fields. `class Foo : Base, IBar, IBaz` parses its whole `: ...` clause as
one flat `base_list`, with nothing marking which entry is the base class
and which are interfaces -- Owner.supertypes carries all of them
undistinguished, which every consumer (ancestor closure, self-call
resolution) already treats as one set regardless of language.
"""
import tree_sitter_c_sharp as tscs
from tree_sitter import Language, Node, Parser


def _parser() -> Parser:
    return Parser(Language(tscs.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _short_name(node: Node, src: bytes) -> str:
    """The bare name at the end of a qualified reference: `Foo.Bar` and a
    member access's own name field both read as `Bar`."""
    if node.type == "qualified_name":
        name = node.child_by_field_name("name")
        return _text(name, src) if name is not None else _text(node, src)
    if node.type == "member_access_expression":
        name = node.child_by_field_name("name")
        return _text(name, src) if name is not None else ""
    return _text(node, src)


def _type_name(node: Node, src: bytes) -> str:
    """A type node's bare name: generic arguments and namespace
    qualification stripped, so `Microsoft.AspNetCore.Http.HttpContext` and
    a `using`-shortened `HttpContext` both read as `HttpContext` -- the
    same bare-name convention Java's own _type_names() uses, since this
    project's handler-parameter-type hints are always written unqualified.
    """
    if node.type == "generic_name":
        # No field name on either child in this grammar -- the identifier
        # is always the first, the type_argument_list the second.
        name = next((c for c in node.children if c.type == "identifier"), None)
        return _text(name, src) if name is not None else _text(node, src).split("<")[0]
    if node.type == "qualified_name":
        # `name` can itself be a generic_name (`Foo.Bar<X>`), so this
        # recurses rather than reading the text straight off -- otherwise
        # the generic argument survives the qualifier strip.
        name = node.child_by_field_name("name")
        return _type_name(name, src) if name is not None else _text(node, src).split(".")[-1]
    if node.type == "nullable_type":
        inner = node.child_by_field_name("type")
        return _type_name(inner, src) if inner is not None else _text(node, src)
    return _text(node, src)


def _base_list_names(class_node: Node, src: bytes) -> tuple[str, ...]:
    base_list = next((c for c in class_node.children if c.type == "base_list"), None)
    if base_list is None:
        return ()
    return tuple(_type_name(c, src) for c in base_list.children if c.is_named)


def _modifiers(node: Node, src: bytes) -> set[str]:
    return {_text(c, src) for c in node.children if c.type == "modifier"}


def _param_type_names(params_node: Node, src: bytes) -> list[str]:
    """Every ordinary parameter's type name, in declaration order. A
    lambda's own `parameters` field is `implicit_parameter` for a single
    unparenthesized param (`id => ...`) rather than `parameter_list` --
    that shape has no type annotation to read at all, so it contributes
    nothing here rather than raising."""
    if params_node.type != "parameter_list":
        return []
    names = []
    for child in params_node.children:
        if child.type != "parameter":
            continue
        type_node = child.child_by_field_name("type")
        if type_node is not None:
            names.append(_type_name(type_node, src))
    return names


def _arity(params_node: Node | None, src: bytes) -> int:
    if params_node is None or params_node.type != "parameter_list":
        return 0
    return sum(1 for c in params_node.children if c.type == "parameter")


def _string_literal_value(node: Node, src: bytes) -> str:
    content = next((c for c in node.children if c.type == "string_literal_content"), None)
    return _text(content, src) if content is not None else _text(node, src).strip('"')
