"""Thin readers over a Kotlin tree-sitter node: source text, type names,
arity, annotation entries, string-literal call arguments. Structurally
closest to Java's own syntax.py for class/method/annotation shape (a
method lives inside a class body, annotations are read off a `modifiers`
node), with one grammar quirk of its own: a call with a trailing lambda
block (`get("/x") { ... }`, Kotlin's idiomatic DSL-building shape) has no
`value_arguments` field carrying the lambda -- the lambda is a second,
separate child (`annotated_lambda`) beside whatever ordinary call the
receiver wrote, so reading a call's full argument list means checking two
different places depending on whether it ends in a block.
"""
import tree_sitter_kotlin as tsk
from tree_sitter import Language, Node, Parser


def _parser() -> Parser:
    return Parser(Language(tsk.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _type_name(user_type_node: Node, src: bytes) -> str:
    """A `user_type` node's bare name: `org.foo.Bar` and a simple `Bar`
    both read as `Bar`, the last `identifier` child either way."""
    identifiers = [c for c in user_type_node.children if c.type == "identifier"]
    return _text(identifiers[-1], src) if identifiers else _text(user_type_node, src)


def _string_literal_value(node: Node, src: bytes) -> str:
    content = next((c for c in node.children if c.type == "string_content"), None)
    return _text(content, src) if content is not None else _text(node, src).strip('"')


def _annotation_entries(modifiers_node: Node, src: bytes) -> list[tuple[str, Node | None]]:
    """`[(name, value_arguments_or_None), ...]` for every `annotation`
    under a `modifiers` node. A bare annotation (`@RestController`) wraps
    a `user_type` directly; one with arguments (`@GetMapping("/x")`)
    wraps a `constructor_invocation` instead, carrying its own nested
    `user_type` and `value_arguments`."""
    results = []
    for child in modifiers_node.children:
        if child.type != "annotation":
            continue
        target = next((c for c in child.children if c.type in ("user_type", "constructor_invocation")), None)
        if target is None:
            continue
        if target.type == "user_type":
            results.append((_type_name(target, src), None))
        else:
            type_node = next((c for c in target.children if c.type == "user_type"), None)
            args_node = next((c for c in target.children if c.type == "value_arguments"), None)
            if type_node is not None:
                results.append((_type_name(type_node, src), args_node))
    return results


def _first_string_arg(args_node: Node | None, src: bytes) -> str | None:
    if args_node is None:
        return None
    first = next((c for c in args_node.children if c.type == "value_argument"), None)
    if first is None:
        return None
    literal = next((c for c in first.children if c.type == "string_literal"), None)
    return _string_literal_value(literal, src) if literal is not None else None


def _arity(params_node: Node | None) -> int:
    if params_node is None:
        return 0
    return sum(1 for c in params_node.children if c.type == "parameter")


def _supertype_names(class_node: Node, src: bytes) -> tuple[str, ...]:
    """The base class and interfaces from a class's `: Base(), IFoo`
    delegation-specifier list -- Kotlin's one-clause-covers-both shape,
    the same trade C#'s flat `base_list` and Ruby's single superclass
    slot both make, extended here to cover more than one entry since a
    Kotlin class can implement several interfaces in the same clause."""
    clause = next((c for c in class_node.children if c.type == "delegation_specifiers"), None)
    if clause is None:
        return ()
    names = []
    for spec in clause.children:
        if spec.type != "delegation_specifier":
            continue
        inner = spec.children[0] if spec.children else None
        if inner is None:
            continue
        if inner.type == "user_type":
            names.append(_type_name(inner, src))
        elif inner.type == "constructor_invocation":
            type_node = next((c for c in inner.children if c.type == "user_type"), None)
            if type_node is not None:
                names.append(_type_name(type_node, src))
    return tuple(names)
