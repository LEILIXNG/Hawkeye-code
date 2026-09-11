"""Thin readers over a Python tree-sitter node: source text, decorator
calls, base-class names, arity. The Python-grammar counterpart to
syntax.py, which only ever speaks Java node types.
"""
import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

from scanner.callgraph.model import ANY_ARITY


def _parser() -> Parser:
    return Parser(Language(tspython.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _short_name(node: Node, src: bytes) -> str:
    """The bare name at the end of a dotted reference: `flask.views.MethodView`
    and `MethodView` both read as `MethodView`, the same trim Java's
    `_type_names` applies to `implements java.util.List`."""
    if node.type == "attribute":
        attr = node.child_by_field_name("attribute")
        return _text(attr, src) if attr is not None else ""
    return _text(node, src)


def _base_names(class_node: Node, src: bytes) -> tuple[str, ...]:
    """A class's direct base classes, bare-named. `class_definition`'s
    `superclasses` field is a plain `argument_list` -- the same node type a
    call's arguments use -- so `metaclass=ABCMeta`-style keyword arguments
    have to be skipped explicitly rather than assumed absent."""
    superclasses = class_node.child_by_field_name("superclasses")
    if superclasses is None:
        return ()
    names = []
    for child in superclasses.children:
        if child.type in ("identifier", "attribute"):
            names.append(_short_name(child, src))
    return tuple(names)


def _decorator_calls(decorated: Node, src: bytes) -> list[tuple[str, str]]:
    """`(object_name, attribute_name)` for every decorator on a
    `decorated_definition` that is itself a call, e.g. `@app.route(...)` ->
    `("app", "route")`. A bare decorator (`@staticmethod`, `@property`) has
    no call to unwrap and is not returned -- entry-point recognition only
    ever looks for the call-shaped kind."""
    calls = []
    for child in decorated.children:
        if child.type != "decorator":
            continue
        inner = next((c for c in child.children if c.type not in ("@",)), None)
        if inner is None or inner.type != "call":
            continue
        func = inner.child_by_field_name("function")
        if func is not None and func.type == "attribute":
            obj = func.child_by_field_name("object")
            attr = func.child_by_field_name("attribute")
            if obj is not None and attr is not None:
                calls.append((_short_name(obj, src), _text(attr, src)))
    return calls


# A parameter shaped like this can accept any number of positional or
# keyword arguments, so no fixed arity describes its call sites -- the same
# situation Java's mapper-XML linking hits when the interface cannot be
# resolved, and the same fix applies: match any argument count.
_VARARG_PARAMETER_TYPES = frozenset({"list_splat_pattern", "dictionary_splat_pattern"})


def _arity(params_node: Node, src: bytes) -> int:
    """Declared parameter count, with the bound receiver stripped so it
    matches how the method is actually called.

    Python spells the receiver out (`self`, `cls`) as an explicit first
    parameter, unlike Java where it is implicit -- counting it as declared
    would make `def run(self, cmd)` arity 2 while every call site
    `obj.run(x)` supplies 1, and nothing would ever match. Checked by name,
    not by "is this inside a class": a `@staticmethod` never names its
    first parameter `self`, so the same check does the right thing for
    those without having to notice the decorator at all.
    """
    named = [c for c in params_node.children if c.is_named]
    if any(c.type in _VARARG_PARAMETER_TYPES for c in named):
        return ANY_ARITY
    if named and named[0].type == "identifier" and _text(named[0], src) in ("self", "cls"):
        named = named[1:]
    return len(named)
