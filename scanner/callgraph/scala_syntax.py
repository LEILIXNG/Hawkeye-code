"""Thin readers over a Scala tree-sitter node: source text, type names,
arity. Structurally closest to Kotlin's own syntax.py (a method lives
inside a class/object/trait body, every field this module reads carries
its own name), with one shape neither Java nor Kotlin has: an
`extends_clause`'s base class and each `with`-mixed-in trait
(`class X extends Base with Greeter with Loggable`) all share the *same*
field name (`type`), so reading the full supertype list means filtering
by node type rather than taking the one node a field lookup would return.
"""
import tree_sitter_scala as tsscala
from tree_sitter import Language, Node, Parser


def _parser() -> Parser:
    return Parser(Language(tsscala.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _arity(params_node: Node | None) -> int:
    if params_node is None:
        return 0
    return sum(1 for c in params_node.children if c.type == "parameter")


def _supertype_names(decl_node: Node, src: bytes) -> tuple[str, ...]:
    """The base class and every `with`-mixed-in trait, all read off the
    same repeated `type` field on `extends_clause` -- see this module's
    own docstring."""
    clause = next((c for c in decl_node.children if c.type == "extends_clause"), None)
    if clause is None:
        return ()
    return tuple(_text(c, src) for c in clause.children if c.type in ("type_identifier", "generic_type"))
