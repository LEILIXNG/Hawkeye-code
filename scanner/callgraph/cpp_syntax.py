"""Small tree-sitter-cpp helpers used by the C++ call-graph indexer."""
from tree_sitter import Language, Node, Parser
import tree_sitter_cpp

from scanner.callgraph.model import ANY_ARITY


def _parser() -> Parser:
    return Parser(Language(tree_sitter_cpp.language()))


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _arity(node: Node | None) -> int:
    if node is None:
        return ANY_ARITY
    named = [child for child in node.named_children if child.type != "comment"]
    if not named or (len(named) == 1 and named[0].type == "variadic_parameter"):
        return 0
    return len(named)


def _declarator_name(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "field_identifier", "operator_name", "destructor_name"}:
        return _text(node, source).lstrip("~")
    if node.type in {"qualified_identifier", "scoped_identifier"}:
        return _declarator_name(node.child_by_field_name("name"), source)
    child = node.child_by_field_name("declarator")
    if child is not None:
        return _declarator_name(child, source)
    for child in node.named_children:
        found = _declarator_name(child, source)
        if found:
            return found
    return ""


def _call_name(node: Node | None, source: bytes) -> tuple[str, bool]:
    if node is None:
        return "", False
    if node.type in {"identifier", "field_identifier"}:
        return _text(node, source), False
    if node.type in {"qualified_identifier", "scoped_identifier"}:
        return _declarator_name(node.child_by_field_name("name"), source), False
    if node.type == "field_expression":
        field = node.child_by_field_name("field")
        if field is None and node.named_children:
            field = node.named_children[-1]
        return _declarator_name(field, source), _text(node, source).lstrip().startswith("this->")
    return "", False
