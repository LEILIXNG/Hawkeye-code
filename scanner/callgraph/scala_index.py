"""Parsing Scala sources into the same Method/Call/Owner shapes the Java,
Python, JS/TS, Go, C++, Rust, C#, PHP, Ruby and Kotlin sides produce, so
index_workspace() can hand all eleven to one shared traversal with no
language check anywhere in traverse.py.

Unlike every earlier language here, this module recognises no entry point
at all on its own: Play Framework, the one Scala web framework this
project targets, has no annotation, decorator or registration-call
convention of any kind on a controller action -- `def index() = Action
{ ... }` is an ordinary method that looks like any other. The entire
signal lives in `conf/routes`, which is not Scala syntax at all (a
`GET /path controllers.HomeController.index` line is a fixed-column text
format, not an expression this grammar parses) -- scala_routes.py reads
it with its own line-level parser and sets entry_reason/entry_definitive
directly on the Method nodes this module already built, the same
"external file names the method, Java/Scala source never proves it
itself" shape mybatis.py already uses for a MyBatis mapper statement,
except updating an existing Method in place rather than manufacturing a
new one (a mapper statement's XML span *is* the sink; a routes line never
contains one).
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.callgraph.scala_syntax import _arity, _parser, _supertype_names, _text

TYPE_DECLARATIONS = ("class_definition", "object_definition", "trait_definition")


def index_scala_workspace(root: Path, index: Index) -> None:
    """Parses every .scala file under `root` into `index`'s methods and
    call sites, additively -- the same contract every other
    index_*_workspace function already has. No test-file convention to
    skip: ScalaTest/specs2 suites live under a project-chosen
    `src/test/scala/` directory, which the bare `test`/`tests` names in
    ruleset.yml's exclude_paths already catch."""
    parser = _parser()
    for path in sorted(root.rglob("*.scala")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner())


def _owner_of(node: Node, src: bytes) -> Owner:
    name_node = node.child_by_field_name("name")
    name = _text(name_node, src) if name_node is not None else ""
    return Owner(name=name, supertypes=_supertype_names(node, src))


def _handle_function(node: Node, src: bytes, rel: str, index: Index, owner: Owner) -> None:
    name_node = node.child_by_field_name("name")
    body = node.child_by_field_name("body")
    if name_node is None or body is None:
        # A missing body means a trait's abstract signature
        # (`function_declaration`, not `function_definition` at all, but
        # kept as a defensive check here too) -- nothing to walk or index.
        return
    params_node = node.child_by_field_name("parameters")
    method = Method(
        file=rel, name=_text(name_node, src), arity=_arity(params_node), owner=owner,
        start_line=node.start_point[0] + 1, end_line=node.end_point[0] + 1,
    )
    index.methods.append(method)
    _walk(body, src, rel, index, method, owner)


def _callee_name(call_expr: Node, src: bytes) -> tuple[str | None, bool]:
    func = call_expr.child_by_field_name("function")
    if func is None:
        return None, False
    if func.type == "identifier":
        return _text(func, src), False
    if func.type == "field_expression":
        field = func.child_by_field_name("field")
        value = func.child_by_field_name("value")
        if field is None:
            return None, False
        # `this` has no dedicated node type in this grammar -- it parses
        # as a plain `identifier` whose text happens to be `this`, the
        # same trap PHP's `$this` and Ruby's bareword calls both are
        # their own version of (see php_index.py's own `_is_this()`).
        return _text(field, src), value is not None and value.type == "identifier" and _text(value, src) == "this"
    return None, False


def _call_arity(call_expr: Node) -> int:
    args = call_expr.child_by_field_name("arguments")
    if args is None or args.type != "arguments":
        return 0
    return sum(1 for c in args.children if c.is_named)


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner) -> None:
    if node.type in TYPE_DECLARATIONS:
        new_owner = _owner_of(node, src)
        if new_owner.name and new_owner.supertypes:
            existing = index.supertypes.get(new_owner.name, ())
            index.supertypes[new_owner.name] = existing + tuple(t for t in new_owner.supertypes if t not in existing)
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.children:
                _walk(child, src, rel, index, current, new_owner)
        return

    if node.type == "function_definition":
        _handle_function(node, src, rel, index, owner)
        return

    if node.type == "call_expression":
        callee, receiver_is_self = _callee_name(node, src)
        if callee is not None:
            index.calls.append(Call(
                file=rel, callee=callee, arity=_call_arity(node),
                line=node.start_point[0] + 1, caller=current, receiver_is_self=receiver_is_self,
            ))
        for child in node.children:
            _walk(child, src, rel, index, current, owner)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner)
