"""Thin readers over a Ruby tree-sitter node: source text, type names,
arity, string/symbol literal values. The Ruby-grammar counterpart to
php_syntax.py, with no type-annotation reading at all -- Ruby is
dynamically typed, so unlike every earlier language's own _param_type_names(),
there is no handler-shaped-parameter-type signal this module could produce;
scanner/callgraph/ruby_entrypoints.py's own signals are arity- and
call-shaped instead (see its docstring).

`self` is a fixed grammar production here (`self` as its own node type, the
same as Rust's), not an author-chosen name the way Go's receiver is or plain
text comparison the way PHP's `$this` needs -- see ruby_index.py's own
`_callee_name()`.
"""
import tree_sitter_ruby as tsrb
from tree_sitter import Language, Node, Parser

# Every parameter shape method_parameters can hold. A required parameter is
# a bare `identifier` (no wrapper node of its own), unlike every other kind.
PARAMETER_TYPES = ("identifier", "optional_parameter", "splat_parameter",
                   "keyword_parameter", "hash_splat_parameter", "block_parameter")

VISIBILITY_KEYWORDS = frozenset({"private", "protected", "public"})


def _parser() -> Parser:
    return Parser(Language(tsrb.language()))


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _short_name(node: Node, src: bytes) -> str:
    """The bare name at the end of a scoped constant: `ActionController::Base`
    reads as `Base`, the same trim every other language's own _short_name()
    applies to a qualified reference."""
    if node.type == "scope_resolution":
        name = node.child_by_field_name("name")
        return _text(name, src) if name is not None else _text(node, src)
    return _text(node, src)


def _arity(params_node: Node | None) -> int:
    if params_node is None:
        return 0
    return sum(1 for c in params_node.children if c.type in PARAMETER_TYPES)


def _string_or_symbol_value(node: Node, src: bytes) -> str:
    """A plain/simple string's text with its quotes stripped, or a symbol
    (`:users`) with its leading `:` stripped -- both are how a route's path,
    `to:` target and `resources` collection name are always written."""
    if node.type == "simple_symbol":
        return _text(node, src).removeprefix(":")
    if node.type == "string":
        content = next((c for c in node.children if c.type == "string_content"), None)
        return _text(content, src) if content is not None else _text(node, src).strip("'\"")
    return _text(node, src)


def _camelize(name: str) -> str:
    """Rails' own controller-name convention: `users` -> `Users`,
    `blog_posts` -> `BlogPosts`. Namespaced controllers (`admin/users` ->
    `Admin::UsersController`) are not resolved -- a known gap, the same
    kind of scope trim PHP's bare-class-name Laravel resolution and Rust's
    builder-pattern indirection gap both document rather than chase."""
    return "".join(word.capitalize() for word in name.split("_"))
