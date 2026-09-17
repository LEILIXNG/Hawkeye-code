"""Parsing Elixir sources into the same Method/Call/Owner shapes the
Java, Python, JS/TS, Go, C++, Rust, C#, PHP, Ruby, Kotlin and Scala sides
produce, so index_workspace() can hand all twelve to one shared traversal
with no language check anywhere in traverse.py.

Structurally the most unusual language here: Elixir is not object-
oriented at all, so there is no owner hierarchy, no `this`/`self`
receiver, and -- unlike every earlier language's own dedicated syntax for
a class or a method -- no dedicated syntax for a module or a function
either. `defmodule`, `def`/`defp`, a Phoenix router macro (`get`,
`scope`, `resources`) and an ordinary application function call are all
the *same* `call` node, told apart only by what its `target` identifier's
text says -- see elixir_syntax.py's own docstring for that shape and why
it is read the way it is.

Phoenix's router recognises entry points inline, during this module's own
`_walk()`, unlike Scala's Play (see scala_routes.py): `get "/path",
PageController, :index` is ordinary Elixir syntax, parsed by the same
grammar as everything else, so there is no separate non-syntax file to
read. A `scope "/prefix", AliasModule do ... end` block nests a path
prefix through however many of them wrap the leaf verb call, the same
`route_prefix`-threading `_walk()` needs that Kotlin's Ktor recognition
already does for `route("/prefix") { ... }`.
"""
from pathlib import Path

from tree_sitter import Node

from scanner.callgraph.elixir_entrypoints import HTTP_VERBS, RESOURCES_ACTIONS, RESOURCES_CALL_NAME, SCOPE_CALL_NAME
from scanner.callgraph.elixir_syntax import (_arity, _atom_value, _call_arguments, _call_arity, _call_do_block,
                                             _call_target_name, _function_signature, _keyword_list_arg, _parser,
                                             _string_value, _text)
from scanner.callgraph.model import Call, Index, Method, Owner


def index_elixir_workspace(root: Path, index: Index) -> None:
    """Parses every .ex file under `root` into `index`'s methods and call
    sites, additively -- the same contract every other index_*_workspace
    function already has. `.exs` (Mix scripts, ExUnit test files) is
    deliberately excluded: it is never application source, and ExUnit
    tests already live under a project-chosen `test/` directory the bare
    `test`/`tests` names in ruleset.yml's exclude_paths would catch
    regardless."""
    parser = _parser()
    pending_refs: list[tuple[str, str, str]] = []
    for path in sorted(root.rglob("*.ex")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        _walk(parser.parse(src).root_node, src, rel, index, current=None, owner=Owner(),
             pending_refs=pending_refs, route_prefix="")
    _resolve_named_references(index, pending_refs)


def _resolve_named_references(index: Index, pending_refs: list[tuple[str, str, str]]) -> None:
    """A Phoenix router entry naming its target as a controller module
    and an action atom -- matched globally across the whole index by
    module name and function name, the same way PHP's Laravel facade
    resolution and Ruby's routes.rb resolution both work (see this
    module's own docstring for why the router and its controllers are
    almost always different files)."""
    for module_name, action_name, description in pending_refs:
        for method in index.methods:
            if method.owner.name == module_name and method.name == action_name and not method.entry_definitive:
                method.entry_reason = description
                method.entry_definitive = True


def _module_short_name(alias_node: Node, src: bytes) -> str:
    return _text(alias_node, src).rsplit(".", 1)[-1]


def _positional_args(args_node: Node | None) -> list[Node]:
    """Every named child of a call's `arguments` list except the trailing
    `keywords` pair list (`only: [...]`), in source order."""
    if args_node is None:
        return []
    return [c for c in args_node.children if c.is_named and c.type != "keywords"]


def _handle_defmodule(node: Node, src: bytes, rel: str, index: Index, current: Method | None,
                      pending_refs: list, route_prefix: str) -> None:
    args = _call_arguments(node)
    alias_node = args.children[0] if args is not None and args.children else None
    name = _module_short_name(alias_node, src) if alias_node is not None and alias_node.type == "alias" else ""
    new_owner = Owner(name=name)
    do_block = _call_do_block(node)
    if do_block is not None:
        for child in do_block.children:
            _walk(child, src, rel, index, current, new_owner, pending_refs, route_prefix)


def _handle_def(node: Node, src: bytes, rel: str, index: Index, owner: Owner, pending_refs: list,
                route_prefix: str) -> None:
    name, params = _function_signature(node, src)
    if name is None:
        return
    method = Method(
        file=rel, name=name, arity=_arity(params), owner=owner,
        start_line=node.start_point[0] + 1, end_line=node.end_point[0] + 1,
    )
    index.methods.append(method)
    do_block = _call_do_block(node)
    if do_block is not None:
        for child in do_block.children:
            _walk(child, src, rel, index, method, owner, pending_refs, route_prefix)


def _handle_route_verb_call(node: Node, src: bytes, verb: str, route_prefix: str, pending_refs: list) -> None:
    positional = _positional_args(_call_arguments(node))
    if len(positional) < 3:
        return
    path_segment = _string_value(positional[0], src)
    controller_node, action_node = positional[1], positional[2]
    if path_segment is None or controller_node.type != "alias" or action_node.type != "atom":
        return
    action = _atom_value(action_node, src)
    if action is None:
        return
    controller = _module_short_name(controller_node, src)
    pending_refs.append((controller, action, f"{verb.upper()} {route_prefix}{path_segment}"))


def _handle_resources_call(node: Node, src: bytes, route_prefix: str, pending_refs: list) -> None:
    args = _call_arguments(node)
    positional = _positional_args(args)
    if len(positional) < 2:
        return
    path_segment = _string_value(positional[0], src)
    controller_node = positional[1]
    if path_segment is None or controller_node.type != "alias":
        return
    controller = _module_short_name(controller_node, src)
    only = _keyword_list_arg(args, "only", src) if args is not None else None
    except_ = _keyword_list_arg(args, "except", src) if args is not None else None
    full_prefix = route_prefix + path_segment
    for action, verb, suffix in RESOURCES_ACTIONS:
        if only is not None and action not in only:
            continue
        if except_ is not None and action in except_:
            continue
        pending_refs.append((controller, action, f"{verb} {full_prefix}{suffix}"))


def _handle_scope(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
                  pending_refs: list, route_prefix: str) -> None:
    positional = _positional_args(_call_arguments(node))
    segment = _string_value(positional[0], src) if positional else None
    do_block = _call_do_block(node)
    if do_block is not None:
        for child in do_block.children:
            _walk(child, src, rel, index, current, owner, pending_refs, route_prefix + (segment or ""))


def _walk(node: Node, src: bytes, rel: str, index: Index, current: Method | None, owner: Owner,
         pending_refs: list, route_prefix: str) -> None:
    if node.type != "call":
        for child in node.children:
            _walk(child, src, rel, index, current, owner, pending_refs, route_prefix)
        return

    name = _call_target_name(node, src)

    if name == "defmodule":
        _handle_defmodule(node, src, rel, index, current, pending_refs, route_prefix)
        return

    if name in ("def", "defp"):
        _handle_def(node, src, rel, index, owner, pending_refs, route_prefix)
        return

    if name is not None:
        # `defmodule`/`def`/`defp` are declarations, not real calls, and
        # are already handled (and returned) above -- everything else,
        # including a Phoenix router macro, is recorded as an ordinary
        # call site too, the same way Rust's/PHP's/Ruby's own route-
        # registration calls still are.
        index.calls.append(Call(
            file=rel, callee=name, arity=_call_arity(node),
            line=node.start_point[0] + 1, caller=current, receiver_is_self=False,
        ))

    if name == SCOPE_CALL_NAME:
        _handle_scope(node, src, rel, index, current, owner, pending_refs, route_prefix)
        return

    if name in HTTP_VERBS:
        _handle_route_verb_call(node, src, name, route_prefix, pending_refs)
    elif name == RESOURCES_CALL_NAME:
        _handle_resources_call(node, src, route_prefix, pending_refs)

    for child in node.children:
        _walk(child, src, rel, index, current, owner, pending_refs, route_prefix)
