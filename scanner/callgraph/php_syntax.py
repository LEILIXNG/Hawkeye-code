"""Thin readers over a PHP tree-sitter node: source text, type names, arity,
string-literal attribute arguments. The PHP-grammar counterpart to
csharp_syntax.py (Java's own `this`-keyword model applies here too) with one
structural difference worth noting: `$this` is not a fixed grammar
production the way C#'s `this` or Rust's `self` are -- it parses as an
ordinary `variable_name` whose text happens to be `this`, so receiver_is_self
in php_index.py compares text rather than checking a node type.

`language_php_only()` is used rather than the mixed PHP+HTML grammar
(`language_php()`): every workspace file this project indexes is a `.php`
source file parsed for its PHP content, never an HTML template with embedded
`<?php ?>` islands, so the plain grammar is the correct (and simpler) one.
"""
import tree_sitter_php as tsphp
from tree_sitter import Language, Node, Parser

PARAMETER_TYPES = ("simple_parameter", "variadic_parameter", "property_promotion_parameter")


def _parser() -> Parser:
    return Parser(Language(tsphp.language_php_only()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _short_name(node: Node, src: bytes) -> str:
    """The bare name at the end of a qualified reference: `App\\Helpers\\util`
    and a member/scoped call's own `name` field both read as `util`."""
    if node.type == "qualified_name":
        name = node.child_by_field_name("name")
        return _text(name, src) if name is not None else _text(node, src)
    return _text(node, src)


def _type_name(node: Node, src: bytes) -> str:
    """A type node's bare name. `named_type` wraps the identifier a class
    or interface hint carries (`UserService`, `Request`); `primitive_type`
    (`int`, `string`, ...) and an `optional_type`'s nullable marker (`?Foo`)
    are unwrapped down to the same bare name every other language's own
    _type_name() produces."""
    if node.type == "named_type":
        inner = node.child_by_field_name("name") or (node.children[0] if node.children else None)
        return _type_name(inner, src) if inner is not None else _text(node, src)
    if node.type == "optional_type":
        inner = next((c for c in node.children if c.type != "?"), None)
        return _type_name(inner, src) if inner is not None else _text(node, src)
    if node.type == "qualified_name":
        return _short_name(node, src)
    return _text(node, src)


def _param_type_names(params_node: Node, src: bytes) -> list[str]:
    """Every ordinary parameter's type name, in declaration order. Property
    promotion (`private UserService $svc` inside `__construct`) is a
    distinct node type from a plain typed parameter, so both are read the
    same way here rather than only recognising `simple_parameter`."""
    names = []
    for child in params_node.children:
        if child.type not in PARAMETER_TYPES:
            continue
        type_node = child.child_by_field_name("type")
        if type_node is not None:
            names.append(_type_name(type_node, src))
    return names


def _arity(params_node: Node | None, src: bytes) -> int:
    if params_node is None:
        return 0
    return sum(1 for c in params_node.children if c.type in PARAMETER_TYPES)


def _string_literal_value(node: Node, src: bytes) -> str:
    """Unwraps both single-quoted (`string`) and double-quoted
    (`encapsed_string`) literals by stripping the outer quote characters
    off the node's own text, rather than reading a single `string_content`
    child: an escaped character (`\\\\`, `\\'`) splits the content into
    *multiple* `string_content` siblings around its own `escape_sequence`
    node, so `'Auth\\\\LoginController'` parses as `string_content("Auth")`,
    `escape_sequence("\\\\")`, `string_content("LoginController")` -- taking
    only the first child silently truncated every literal with a
    backslash in it."""
    text = _text(node, src)
    return text[1:-1] if len(text) >= 2 and text[0] in ("'", '"') else text


def _base_clause_name(class_node: Node, src: bytes) -> str | None:
    """`base_clause`'s own `name` child carries no field name in this
    grammar (unlike `class_declaration`'s, which does) -- found by type
    instead, the same way `_interface_names()` already has to read
    `class_interface_clause`'s repeated, likewise unfielded `name`
    children."""
    base = next((c for c in class_node.children if c.type == "base_clause"), None)
    if base is None:
        return None
    name = next((c for c in base.children if c.type == "name"), None)
    return _text(name, src) if name is not None else None


def _interface_names(class_node: Node, src: bytes) -> tuple[str, ...]:
    clause = next((c for c in class_node.children if c.type == "class_interface_clause"), None)
    if clause is None:
        return ()
    return tuple(_text(c, src) for c in clause.children if c.type == "name")
