"""Parsing Python sources into the same Method/Call/Owner shapes the Java
side produces, so index_workspace() can hand both to one shared traversal
with no language check anywhere in traverse.py.

The walk itself is the Python counterpart to index.py's `_walk`; owner and
entry-point recognition are delegated to python_entrypoints.py exactly the
way index.py delegates to entrypoints.py.
"""
from pathlib import Path

from tree_sitter import Node, Parser

from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.callgraph.python_entrypoints import _entry_reason
from scanner.callgraph.python_syntax import _arity, _base_names, _parser, _short_name, _text

DEFINITION_TYPES = ("function_definition", "class_definition")


def index_python_workspace(root: Path, index: Index, parser: Parser | None = None) -> None:
    """Parses every .py file under `root` into `index`'s methods and call
    sites -- additively, so a mixed Java+Python checkout (two services in
    one uploaded zip, say) ends up in one graph rather than two that cannot
    see each other. Ancestor closure and MyBatis linking are run once,
    after both languages have contributed, by index_workspace() itself.
    """
    parser = parser or _parser()
    for path in sorted(root.rglob("*.py")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner())


def _unwrap_decorated(node: Node) -> tuple[Node, Node | None]:
    """A `function_definition`/`class_definition` reached directly has no
    decorators; reached through a `decorated_definition`, the actual
    definition is one field access away and the wrapper itself is what
    entry-point recognition reads the decorators off of."""
    if node.type == "decorated_definition":
        inner = node.child_by_field_name("definition")
        return (inner, node) if inner is not None else (node, None)
    return node, None


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner) -> None:
    definition, decorated = _unwrap_decorated(node) if node.type == "decorated_definition" else (node, None)

    if definition.type == "class_definition":
        name_node = definition.child_by_field_name("name")
        new_owner = Owner(name=_text(name_node, src) if name_node is not None else "",
                          supertypes=_base_names(definition, src))
        if new_owner.name:
            index.supertypes[new_owner.name] = new_owner.supertypes
        for child in (definition.child_by_field_name("body") or definition).children:
            _walk(child, src, rel, index, current, new_owner)
        return

    if definition.type == "function_definition":
        name_node = definition.child_by_field_name("name")
        params_node = definition.child_by_field_name("parameters")
        if name_node is not None and params_node is not None:
            name = _text(name_node, src)
            reason, definitive = _entry_reason(name, decorated, params_node, src, owner)
            method = Method(
                file=rel,
                name=name,
                arity=_arity(params_node, src),
                owner=owner,
                start_line=(decorated or definition).start_point[0] + 1,
                end_line=definition.end_point[0] + 1,
                entry_reason=reason,
                entry_definitive=definitive,
            )
            index.methods.append(method)
            body = definition.child_by_field_name("body")
            if body is not None:
                for child in body.children:
                    _walk(child, src, rel, index, method, owner)
        return

    if node.type == "call":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is not None:
            callee, receiver_is_self = _callee_name(func, src)
            if callee is not None:
                index.calls.append(Call(
                    file=rel,
                    callee=callee,
                    arity=_call_arity(args) if args is not None else 0,
                    line=node.start_point[0] + 1,
                    caller=current,
                    receiver_is_self=receiver_is_self,
                ))

    for child in node.children:
        _walk(child, src, rel, index, current, owner)


def _callee_name(func: Node, src: bytes) -> tuple[str | None, bool]:
    """The name a call resolves against, and whether its receiver is
    `self`/`cls` -- Python's spelling of Java's `this`/`super`, and the
    same restriction applies: such a call can only land inside the
    caller's own class hierarchy."""
    if func.type == "identifier":
        return _text(func, src), False
    if func.type == "attribute":
        obj = func.child_by_field_name("object")
        attr = func.child_by_field_name("attribute")
        if attr is None:
            return None, False
        receiver_is_self = obj is not None and obj.type == "identifier" and _text(obj, src) in ("self", "cls")
        return _text(attr, src), receiver_is_self
    return None, False


def _call_arity(args_node: Node) -> int:
    return sum(1 for c in args_node.children if c.is_named)
