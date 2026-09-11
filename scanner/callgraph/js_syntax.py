"""Thin readers over a JavaScript/TypeScript tree-sitter node: source text,
member-expression names, base classes, arity. The JS/TS-grammar counterpart
to syntax.py and python_syntax.py.

One module for both languages: tree-sitter-typescript's grammar is built as
an extension of tree-sitter-javascript's, and every node type this file
reads (call_expression, member_expression, class_declaration/heritage,
arrow_function) is spelled identically in both. Only the parameter node the
two wrap arguments in differs (TypeScript wraps each in a
required_parameter/optional_parameter to carry its type annotation), and
`_arity` reads through that difference rather than needing two versions of
itself.
"""
from tree_sitter import Node, Parser


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def parser_for(suffix: str) -> Parser | None:
    """A parser for this extension, or None for one this module does not
    handle (.d.ts declaration files carry no runtime code to index)."""
    if suffix == ".d.ts":
        return None
    if suffix in (".ts",):
        import tree_sitter_typescript as tsts
        from tree_sitter import Language
        return Parser(Language(tsts.language_typescript()))
    if suffix in (".tsx",):
        import tree_sitter_typescript as tsts
        from tree_sitter import Language
        return Parser(Language(tsts.language_tsx()))
    if suffix in (".js", ".jsx", ".mjs", ".cjs"):
        import tree_sitter_javascript as tsjs
        from tree_sitter import Language
        return Parser(Language(tsjs.language()))
    return None


# Every shape a function value can take at an expression position: an
# `app.get(path, <here>)` handler argument, or the right side of
# `const handler = <here>` / `exports.handler = <here>`. Generators are
# deliberately included -- an async generator route handler is unusual but
# not invalid, and excluding the type would just mean silently dropping it.
FUNCTION_SHAPED_TYPES = frozenset({
    "function_expression", "arrow_function", "function_declaration",
    "generator_function", "generator_function_declaration",
})


def _short_name(node: Node, src: bytes) -> str:
    """The bare name at the end of a member expression: `express.Router`
    and `Router` both read as `Router`, the same trim every other
    language's syntax module applies to a qualified reference."""
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        return _text(prop, src) if prop is not None else ""
    return _text(node, src)


def _callee(call: Node, src: bytes) -> tuple[str | None, str, bool]:
    """`(object_name_or_None, method_name, receiver_is_this)` for a
    call_expression's callee: a bare `helper(x)` has no object, a
    `router.get(...)` has `router`, and `this.run()` is JS's spelling of
    Python's `self.run()` / Java's `this.run()` -- the same restriction
    applies, so it is flagged here rather than re-detected downstream."""
    func = call.child_by_field_name("function")
    if func is None:
        return None, "", False
    if func.type == "identifier":
        return None, _text(func, src), False
    if func.type == "member_expression":
        obj = func.child_by_field_name("object")
        prop = func.child_by_field_name("property")
        if prop is None:
            return None, "", False
        obj_name = _text(obj, src) if obj is not None else None
        receiver_is_this = obj is not None and obj.type == "this"
        return obj_name, _text(prop, src), receiver_is_this
    return None, "", False


def _base_name(class_node: Node, src: bytes) -> tuple[str, ...]:
    """A class's `extends` target, bare-named. `class_heritage` wraps
    exactly one expression (`extends Base` or `extends ns.Base`); there is
    no multiple inheritance in JS/TS to enumerate the way Python's
    `argument_list` superclasses list does."""
    heritage = next((c for c in class_node.children if c.type == "class_heritage"), None)
    if heritage is None:
        return ()
    target = next((c for c in heritage.children if c.is_named), None)
    return (_short_name(target, src),) if target is not None else ()


def _arity(params_node: Node, src: bytes) -> int:
    """Declared parameter count. A rest parameter (`...args`) matches any
    call-site argument count, read by whether the parameter's own text
    starts with `...` rather than by its wrapper node type -- plain JS
    spells it `rest_pattern`, TypeScript wraps the same thing in a
    `required_parameter` carrying a type annotation, and checking the text
    once covers both without needing to track every grammar's parameter
    node names.
    """
    from scanner.callgraph.model import ANY_ARITY

    named = [c for c in params_node.children if c.is_named]
    if any(_text(c, src).startswith("...") for c in named):
        return ANY_ARITY
    return len(named)


def _call_arity(args_node: Node) -> int:
    return sum(1 for c in args_node.children if c.is_named)
