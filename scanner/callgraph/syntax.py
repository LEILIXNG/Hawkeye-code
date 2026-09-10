"""Thin readers over tree-sitter nodes: source text, annotation names, type
names, arity. Shared by the entry-point vocabulary and the indexing walk."""
import tree_sitter_java
from tree_sitter import Language, Node, Parser

from scanner.callgraph.model import Owner


def _parser() -> Parser:
    return Parser(Language(tree_sitter_java.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _annotation_names(node: Node, src: bytes) -> set[str]:
    names = set()
    for child in node.children:
        if child.type in ("annotation", "marker_annotation"):
            name = child.child_by_field_name("name")
            if name is not None:
                names.add(_text(name, src).split(".")[-1])
    return names


def _type_names(node: Node | None, src: bytes) -> tuple[str, ...]:
    """The bare type names under an `extends`/`implements` clause, generics and
    package qualifiers stripped, so `implements java.util.List<String>` and
    `implements List<String>` both read as `List`."""
    if node is None:
        return ()
    names = []
    for child in node.children:
        if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
            names.append(_text(child, src).split("<")[0].split(".")[-1].strip())
        elif child.type == "type_list":
            names.extend(_type_names(child, src))
    return tuple(names)


def _owner_of(node: Node, src: bytes) -> Owner:
    name_node = node.child_by_field_name("name")
    return Owner(
        name=_text(name_node, src) if name_node is not None else "",
        supertypes=(_type_names(node.child_by_field_name("superclass"), src)
                    + _type_names(node.child_by_field_name("interfaces"), src)),
    )


def _arity(node: Node, field_name: str) -> int:
    container = node.child_by_field_name(field_name)
    if container is None:
        return 0
    return sum(1 for c in container.children if c.is_named)
