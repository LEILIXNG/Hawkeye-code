"""Thin readers over an Elixir tree-sitter node: source text, arity,
function signatures, atom/string/keyword-list values.

Two things make this module read every node positionally, by type,
rather than by field name the way every earlier language's own syntax
module does: (1) there is no dedicated node type for a module
definition, a function definition, or an ordinary function call -- all
three are the *same* `call` node, distinguished only by what its first
child's text says (`defmodule`, `def`/`defp`, or anything else); (2)
`child_by_field_name()`/`field_name_for_child()` measured unreliable
against this grammar/binding combination (tree-sitter-elixir 0.3.x) --
the same `call` node shape reports its `target`/`arguments`/`do_block`
fields correctly in one parse and reports `None` for the identical shape
in another, depending on surrounding context that does not change the
resulting tree's own node types or child order at all. Every reader here
therefore finds what it needs by position (`call`'s first child is
always its target) or by node type (`arguments`, `do_block`, `keywords`
are all findable by type regardless of whether this parse happened to
carry their field names), never by field name.
"""
import tree_sitter_elixir as tsex
from tree_sitter import Language, Node, Parser


def _parser() -> Parser:
    return Parser(Language(tsex.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _call_target_name(call_node: Node, src: bytes) -> str | None:
    """The bare name a `call` node's target (always its first child)
    resolves against: a plain macro/function name (`get`, `def`,
    `defmodule`), or the right-hand side of a qualified `Module.function`
    reference (a `dot` node, whose own last child is always the field
    identifier, unlike every earlier language's field/member-access
    shape)."""
    if not call_node.children:
        return None
    target = call_node.children[0]
    if target.type == "identifier":
        return _text(target, src)
    if target.type == "dot":
        right = next((c for c in reversed(target.children) if c.type == "identifier"), None)
        return _text(right, src) if right is not None else None
    return None


def _call_arguments(call_node: Node) -> Node | None:
    return next((c for c in call_node.children if c.type == "arguments"), None)


def _call_do_block(call_node: Node) -> Node | None:
    return next((c for c in call_node.children if c.type == "do_block"), None)


def _call_arity(call_node: Node) -> int:
    args = _call_arguments(call_node)
    return sum(1 for c in args.children if c.is_named) if args is not None else 0


def _function_signature(def_call: Node, src: bytes) -> tuple[str | None, Node | None]:
    """`(name, params_node)` for a `def`/`defp` call's own signature --
    its first (and only meaningful) argument, which is itself one of
    three shapes: a plain `call` (`foo(x)`), a `when`-guarded
    `binary_operator` wrapping one (`foo(x) when x > 0`, one of
    potentially several clauses sharing this name and arity -- each
    clause still gets indexed as its own Method, deliberately not merged
    into one, so a caller resolves to whichever clause's span the sink
    actually sits in), or a bare `identifier` with no parameter list at
    all (`def noparen do ... end`, zero arity)."""
    args = _call_arguments(def_call)
    if args is None or not args.children:
        return None, None
    sig = args.children[0]
    if sig.type == "binary_operator" and len(sig.children) == 3:
        # `left when guard`: always exactly [left, `when`, guard] in this
        # grammar, so the left side is unambiguous by position.
        sig = sig.children[0]
    if sig.type == "call":
        return _call_target_name(sig, src), _call_arguments(sig)
    if sig.type == "identifier":
        return _text(sig, src), None
    return None, None


def _arity(params_node: Node | None) -> int:
    return sum(1 for c in params_node.children if c.is_named) if params_node is not None else 0


def _string_value(node: Node, src: bytes) -> str | None:
    if node.type != "string":
        return None
    content = next((c for c in node.children if c.type == "quoted_content"), None)
    return _text(content, src) if content is not None else ""


def _atom_value(node: Node, src: bytes) -> str | None:
    if node.type != "atom":
        return None
    return _text(node, src).removeprefix(":")


def _keyword_list_arg(call_args: Node, key: str, src: bytes) -> list[str] | None:
    """The atom list from a trailing `key: [...]` keyword argument
    (`only: [:index, :show]`) among a call's own arguments, or None if
    that keyword is absent. A `pair` node's `key`/`value` always sit at
    positions 0/1, the same fixed-arity shape `binary_operator`'s own
    `left when right` has."""
    keywords = next((c for c in call_args.children if c.type == "keywords"), None)
    if keywords is None:
        return None
    for pair in keywords.children:
        if pair.type != "pair" or len(pair.children) != 2:
            continue
        key_node, value_node = pair.children
        if _text(key_node, src).rstrip(": \t") != key:
            continue
        if value_node.type != "list":
            return None
        return [a for a in (_atom_value(c, src) for c in value_node.children if c.type == "atom") if a is not None]
    return None
