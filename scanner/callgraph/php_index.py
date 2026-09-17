"""Parsing PHP sources into the same Method/Call/Owner shapes the Java,
Python, JS/TS, Go, C++, Rust and C# sides produce, so index_workspace() can
hand all eight to one shared traversal with no language check anywhere in
traverse.py.

Structurally closest to C#'s: methods live inside class bodies, a class
states its base class and interface list in one place (`extends Base
implements IFoo, IBar`), and traits (`use SomeTrait;` -- not indexed here,
see the docstring on TYPE_DECLARATIONS below) are this language's own
mixin mechanism. The one thing every other class-based language's `this`/
`self` has that PHP's `$this` does not: a fixed grammar production of its
own. `$this` parses as an ordinary `variable_name`, so receiver_is_self is
decided by comparing its name field's text rather than a node-type check --
see php_syntax.py's and this module's own docstrings for the two other
consequences of that (superglobal detection has the same shape).

Laravel's `Route::get('/x', [Controller::class, 'method'])` is this
project's first *cross-file* handler reference: unlike every earlier
language's route-registration call, which always names a handler declared
in the same file (or resolves same-file per rust_index.py's and
csharp_index.py's own _resolve_named_references()), a Laravel routes file
and the controller it wires up are almost always two different files. So
_resolve_named_references() here matches globally, by owner class name and
method name across the whole index, not scoped to the registration call's
own file -- a controller class name colliding with an unrelated same-named
class elsewhere in the codebase is the one false-positive risk that trade
accepts, the same kind of bet Rust's and C#'s own bare-name matching makes
for a narrower (same-file) search space.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.callgraph.php_entrypoints import entry_reason, is_route_registration, route_handler, route_verb_and_path
from scanner.callgraph.php_syntax import (_arity, _base_clause_name, _interface_names, _parser, _short_name,
                                           _string_literal_value, _text)

# `interface_declaration` bodies carry no method with a `body` field to walk
# (an interface only ever declares a signature), so it is intentionally left
# out here -- including it would cost a traversal for zero methods, since
# _handle_function_like() already skips a body-less declaration on its own.
# `trait_declaration` is included: unlike an interface, a PHP trait's
# methods have real bodies and are mixed into whatever class `use`s the
# trait, so a sink inside one is exactly as real as a sink in a class body.
TYPE_DECLARATIONS = ("class_declaration", "trait_declaration")

CLOSURE_TYPES = ("anonymous_function", "arrow_function")


def index_php_workspace(root: Path, index: Index) -> None:
    """Parses every .php file under `root` into `index`'s methods and call
    sites, additively -- the same contract every other index_*_workspace
    function already has. No test-file convention to skip: PHPUnit tests
    live under a project-chosen `tests/` directory, which the bare `test`/
    `tests` names in ruleset.yml's exclude_paths already catch."""
    parser = _parser()
    pending_refs: list[tuple[str, str, str]] = []
    for path in sorted(root.rglob("*.php")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(), pending_refs=pending_refs)
    _resolve_named_references(index, pending_refs)


def _resolve_named_references(index: Index, pending_refs: list[tuple[str, str, str]]) -> None:
    """A Laravel route naming its handler as `[Controller::class, 'method']`
    or the older `'Controller@method'` string -- see this module's own
    docstring for why this search is global rather than same-file."""
    for class_name, method_name, description in pending_refs:
        for method in index.methods:
            if method.owner.name == class_name and method.name == method_name and not method.entry_definitive:
                method.entry_reason = description
                method.entry_definitive = True


def _owner_of(node: Node, src: bytes) -> Owner:
    name_node = node.child_by_field_name("name")
    name = _text(name_node, src) if name_node is not None else ""
    base = _base_clause_name(node, src)
    supertypes = ((base,) if base else ()) + _interface_names(node, src)
    return Owner(name=name, supertypes=supertypes)


def _call_arity(args: Node | None) -> int:
    return sum(1 for c in args.children if c.type == "argument") if args is not None else 0


def _create_method(decl_node: Node, name: str, src: bytes, rel: str, index: Index, owner: Owner,
                   pending_refs: list, reason: str = "", definitive: bool = False) -> Method:
    """Shared by a declared function/method and a closure handed straight to
    a `Route::` registration call -- `function_definition`, `method_
    declaration` and `anonymous_function` all name their parameter list
    `parameters`, so one reader covers every shape."""
    params = decl_node.child_by_field_name("parameters")
    method = Method(
        file=rel, name=name, arity=_arity(params, src), owner=owner,
        start_line=decl_node.start_point[0] + 1, end_line=decl_node.end_point[0] + 1,
        entry_reason=reason, entry_definitive=definitive,
    )
    index.methods.append(method)
    body = decl_node.child_by_field_name("body")
    if body is not None:
        _walk(body, src, rel, index, method, owner, pending_refs)
    return method


def _handle_function_like(node: Node, src: bytes, rel: str, index: Index, owner: Owner,
                          pending_refs: list) -> None:
    """`function_definition` (top-level) or `method_declaration` (class/
    trait body). A missing `body` field means an interface signature or an
    abstract method -- nothing to walk or index."""
    name_node = node.child_by_field_name("name")
    if name_node is None or node.child_by_field_name("body") is None:
        return
    reason, definitive = entry_reason(node, src)
    _create_method(node, _text(name_node, src), src, rel, index, owner, pending_refs, reason, definitive)


def _class_constant_class_name(node: Node, src: bytes) -> str | None:
    """The class name out of a `ClassName::class` constant-access
    expression -- the first `name`/`qualified_name` child, since this
    grammar gives neither operand of `::` a field name here (see
    php_syntax.py's own `_short_name` for the qualified-name case)."""
    if node.type != "class_constant_access_expression":
        return None
    first = next((c for c in node.children if c.type in ("name", "qualified_name")), None)
    return _short_name(first, src) if first is not None else None


def _handle_route_registration(call: Node, args: Node, src: bytes, rel: str, index: Index,
                               pending_refs: list) -> None:
    verb, path = route_verb_and_path(call, args, src)
    handler = route_handler(args)
    if handler is None:
        return
    description = f"{verb} {path}"
    if handler.type in CLOSURE_TYPES:
        _create_method(handler, description, src, rel, index, Owner(), pending_refs,
                       reason=description, definitive=True)
    elif handler.type == "array_creation_expression":
        elements = [c for c in handler.children if c.type == "array_element_initializer"]
        if len(elements) < 2:
            return
        class_expr = next((c for c in elements[0].children if c.is_named), None)
        method_expr = next((c for c in elements[1].children if c.is_named), None)
        if class_expr is None or method_expr is None or method_expr.type not in ("string", "encapsed_string"):
            return
        class_name = _class_constant_class_name(class_expr, src)
        if class_name:
            pending_refs.append((class_name, _string_literal_value(method_expr, src), description))
    elif handler.type in ("string", "encapsed_string"):
        value = _string_literal_value(handler, src)
        if "@" in value:
            class_part, method_part = value.rsplit("@", 1)
            pending_refs.append((class_part.rsplit("\\", 1)[-1], method_part, description))


def _is_this(node: Node, src: bytes) -> bool:
    # `variable_name`'s `name` child carries no field name in this
    # grammar (see php_entrypoints.py's own superglobal check for the same
    # trap), so `$this`'s bare text is compared directly instead.
    return node.type == "variable_name" and _text(node, src) == "$this"


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         pending_refs: list) -> None:
    if node.type in TYPE_DECLARATIONS:
        new_owner = _owner_of(node, src)
        if new_owner.name and new_owner.supertypes:
            existing = index.supertypes.get(new_owner.name, ())
            index.supertypes[new_owner.name] = existing + tuple(t for t in new_owner.supertypes if t not in existing)
        body = node.child_by_field_name("body")
        if body is not None:
            for child in body.children:
                _walk(child, src, rel, index, current, new_owner, pending_refs)
        return

    if node.type in ("function_definition", "method_declaration"):
        _handle_function_like(node, src, rel, index, owner, pending_refs)
        return

    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is not None:
            index.calls.append(Call(
                file=rel, callee=_short_name(func, src), arity=_call_arity(args),
                line=node.start_point[0] + 1, caller=current, receiver_is_self=False,
            ))
        for child in node.children:
            _walk(child, src, rel, index, current, owner, pending_refs)
        return

    if node.type == "member_call_expression":
        object_node = node.child_by_field_name("object")
        name_node = node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        if name_node is not None:
            index.calls.append(Call(
                file=rel, callee=_text(name_node, src), arity=_call_arity(args),
                line=node.start_point[0] + 1, caller=current,
                receiver_is_self=object_node is not None and _is_this(object_node, src),
            ))
        for child in node.children:
            _walk(child, src, rel, index, current, owner, pending_refs)
        return

    if node.type == "scoped_call_expression":
        scope = node.child_by_field_name("scope")
        name_node = node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        if name_node is not None:
            index.calls.append(Call(
                file=rel, callee=_text(name_node, src), arity=_call_arity(args),
                line=node.start_point[0] + 1, caller=current,
                # `self::`/`static::`/`parent::` all stay inside the type
                # hierarchy the same way Java's own `this`/`super` check
                # treats both as one thing (see java's syntax.py precedent).
                receiver_is_self=scope is not None and scope.type == "relative_scope",
            ))
        if args is not None and is_route_registration(node, src):
            # The arguments subtree is registration wiring (the path
            # literal, the handler) -- walking it again generically below
            # would re-discover an inline closure's body as belonging to
            # whatever function called Route::get(), not to the synthetic
            # handler Method just created for it above.
            _handle_route_registration(node, args, src, rel, index, pending_refs)
            # Compared by byte range, not `is`: this binding does not
            # guarantee a node fetched via child_by_field_name() and the
            # same node reached again through .children are one Python
            # object, so an identity check here would silently walk the
            # arguments subtree a second time and double-index a closure
            # handler already turned into its own synthetic Method above.
            args_range = (args.start_byte, args.end_byte)
            for child in node.children:
                if (child.start_byte, child.end_byte) != args_range:
                    _walk(child, src, rel, index, current, owner, pending_refs)
            return

        for child in node.children:
            _walk(child, src, rel, index, current, owner, pending_refs)
        return

    for child in node.children:
        _walk(child, src, rel, index, current, owner, pending_refs)
