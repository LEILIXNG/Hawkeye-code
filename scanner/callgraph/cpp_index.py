"""Index C++ functions, methods and calls into the shared call graph."""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.cpp_syntax import _arity, _call_name, _declarator_name, _parser, _text
from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.languages import iter_cpp_files


def index_cpp_workspace(root: Path, index: Index) -> Index:
    parser = _parser()
    for path in iter_cpp_files(root):
        try:
            source = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(source).root_node, source, rel, index, None, Owner())
    return index


def _walk(node: Node, source: bytes, rel: str, index: Index,
          current: Method | None, owner: Owner) -> None:
    if node.type in {"class_specifier", "struct_specifier", "union_specifier"}:
        name = node.child_by_field_name("name")
        if name is not None:
            owner = Owner(name=_text(name, source))

    if node.type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        name = _declarator_name(declarator, source)
        params = _find_descendant(declarator, "parameter_list")
        if name:
            type_node = node.child_by_field_name("type")
            current = Method(
                file=rel,
                name=name,
                arity=_arity(params),
                return_type=_text(type_node, source) if type_node is not None else "",
                owner=owner,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
            )
            index.methods.append(current)
    elif node.type == "call_expression":
        name, member_call = _call_name(node.child_by_field_name("function"), source)
        if name:
            index.calls.append(Call(
                file=rel,
                callee=name,
                arity=_arity(node.child_by_field_name("arguments")),
                line=node.start_point[0] + 1,
                caller=current,
                receiver_is_self=member_call,
            ))

    for child in node.children:
        _walk(child, source, rel, index, current, owner)


def _find_descendant(node: Node | None, wanted: str) -> Node | None:
    if node is None:
        return None
    if node.type == wanted:
        return node
    for child in node.named_children:
        found = _find_descendant(child, wanted)
        if found is not None:
            return found
    return None
