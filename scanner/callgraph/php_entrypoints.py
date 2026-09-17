"""What makes a PHP function or method something a request can enter through.

Three tiers, covering Laravel and Symfony -- the two frameworks that between
them account for almost every server-side PHP app this tool would see:

1. A `#[Route(...)]` PHP attribute directly on the function/method is proof.
   Both frameworks share the same attribute syntax (PHP 8's `#[...]` is a
   language feature, not a framework one), so one recognizer covers Symfony's
   modern routing *and* the third-party attribute-routing packages Laravel
   projects sometimes add -- the same "one shape, two frameworks" trade
   route_attributes() already made for actix-web/Rocket in rust_entrypoints.py.

2. A `@Route(...)` PHPDoc annotation is Symfony's older, pre-attribute style:
   not a syntax node at all, just a docblock comment sitting as the
   preceding sibling the same position an attribute would occupy, so it is
   read by regex over the comment's own text rather than by walking a
   parsed argument list.

3. Laravel's routes-file registration -- `Route::get('/x', [Controller::class,
   'method'])`, a closure, or the older `'Controller@method'` string form --
   is a call-shaped signal read in php_index.py, the same split
   rust_index.py and csharp_index.py make between "what proves a handler"
   (here) and "what resolves a handler reference" (there).

The one weak hint, mirroring every other language's own parameter-type
fallback: a function body reading a superglobal (`$_GET`/`$_POST`/
`$_REQUEST`) is recognisably handling a request, even with no attribute,
annotation or registration call in sight -- but PHP has no request-object
*parameter* to check the way Java's HttpServletRequest or C#'s HttpContext
are, since a plain PHP script or controller action reads request data out of
these globals directly rather than receiving it as an argument. That means
the check happens over the function *body*, not its parameter list, unlike
every other language's own signature-based fallback.
"""
import re

from tree_sitter import Node

from scanner.callgraph.php_syntax import _string_literal_value, _text

ROUTE_ATTRIBUTE_NAME = "Route"
HTTP_VERBS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

# Laravel's `Route::get(...)`/`Route::post(...)`/etc. static calls.
# `any`/`match` register more than one verb at once and are read the same
# way `route`/`any`/`on` are for Rust/Go -- a generic "ROUTE" label, since
# the specific verb set is not what reachability tracing needs.
ROUTE_FACADE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "any"})

SUPERGLOBALS = frozenset({"_GET", "_POST", "_REQUEST"})

PHPDOC_ROUTE = re.compile(r'@Route\(\s*"([^"]+)"')
PHPDOC_VERB = re.compile(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"')


def _decl_attributes(decl_node: Node, src: bytes) -> list[Node]:
    """Every `attribute` node under `decl_node`'s own `attributes` field --
    a direct child field in this grammar (`function_definition` and
    `method_declaration` both carry it), unlike Rust's preceding-sibling
    attachment."""
    attr_list = decl_node.child_by_field_name("attributes")
    if attr_list is None:
        return []
    results = []
    for group in attr_list.children:
        if group.type != "attribute_group":
            continue
        results.extend(c for c in group.children if c.type == "attribute")
    return results


def _argument_value(arg: Node) -> Node | None:
    """The value expression an `argument` node carries -- its only named
    child for a positional argument, or the child after the `name:` field
    for a named one (`methods: [...]`). Compared by byte range rather than
    `is`: this binding does not guarantee two separate node accesses for
    the same underlying child are the same Python object."""
    name_node = arg.child_by_field_name("name")
    name_range = (name_node.start_byte, name_node.end_byte) if name_node is not None else None
    for child in arg.children:
        if child.is_named and (name_range is None or (child.start_byte, child.end_byte) != name_range):
            return child
    return None


def _route_attribute_path_and_verbs(attr: Node, src: bytes) -> tuple[str, list[str]]:
    args_node = attr.child_by_field_name("parameters")
    if args_node is None:
        return "?", []
    path = "?"
    verbs: list[str] = []
    positional_consumed = False
    for arg in args_node.children:
        if arg.type != "argument":
            continue
        name_node = arg.child_by_field_name("name")
        value = _argument_value(arg)
        if name_node is None:
            if not positional_consumed and value is not None and value.type in ("string", "encapsed_string"):
                path = _string_literal_value(value, src)
                positional_consumed = True
            continue
        arg_name = _text(name_node, src)
        if arg_name == "path" and value is not None and value.type in ("string", "encapsed_string"):
            path = _string_literal_value(value, src)
        elif arg_name == "methods" and value is not None and value.type == "array_creation_expression":
            for element in value.children:
                if element.type != "array_element_initializer":
                    continue
                inner = next((c for c in element.children if c.is_named), None)
                if inner is not None and inner.type in ("string", "encapsed_string"):
                    verbs.append(_string_literal_value(inner, src).upper())
    return path, verbs


def route_attributes(decl_node: Node, src: bytes) -> list[tuple[str, str]]:
    """`[(verb, path), ...]` from every `#[Route(...)]` attribute directly
    on `decl_node`."""
    results = []
    for attr in _decl_attributes(decl_node, src):
        # `attribute`'s own name child carries no field name in this
        # grammar (unlike the `parameters:` argument list beside it) --
        # found by type, the same trick _base_clause_name() needs.
        name_node = next((c for c in attr.children if c.type == "name"), None)
        if name_node is None or _text(name_node, src) != ROUTE_ATTRIBUTE_NAME:
            continue
        path, verbs = _route_attribute_path_and_verbs(attr, src)
        if verbs:
            results.extend((v, path) for v in verbs)
        else:
            results.append(("ROUTE", path))
    return results


def phpdoc_route(decl_node: Node, src: bytes) -> tuple[str, str] | None:
    """Symfony's pre-attribute `@Route(...)` annotation, read off the
    PHPDoc `comment` node immediately preceding `decl_node` -- text, not a
    parsed argument list, since a docblock is not part of this grammar's
    expression syntax at all."""
    sib = decl_node.prev_sibling
    if sib is None or sib.type != "comment":
        return None
    text = _text(sib, src)
    found = PHPDOC_ROUTE.search(text)
    if found is None:
        return None
    path = found.group(1)
    verbs = PHPDOC_VERB.findall(text)
    if verbs:
        return ", ".join(f"{v} {path}" for v in verbs), path
    return f"ROUTE {path}", path


def _uses_superglobal(body: Node | None, src: bytes) -> bool:
    if body is None:
        return False

    def walk(node: Node) -> bool:
        # `variable_name`'s `name` child carries no field name in this
        # grammar, so the bare `$var` text (with its leading `$` stripped)
        # is read directly rather than via child_by_field_name().
        if node.type == "variable_name" and _text(node, src).removeprefix("$") in SUPERGLOBALS:
            return True
        return any(walk(c) for c in node.children)

    return walk(body)


def entry_reason(decl_node: Node, src: bytes) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint."""
    routes = route_attributes(decl_node, src)
    if routes:
        return ", ".join(f"{verb} {path}" for verb, path in routes), True
    phpdoc = phpdoc_route(decl_node, src)
    if phpdoc is not None:
        return phpdoc[0], True
    body = decl_node.child_by_field_name("body")
    if _uses_superglobal(body, src):
        return "reads a request superglobal", False
    return "", False


def is_route_registration(call: Node, src: bytes) -> bool:
    """Whether a `scoped_call_expression` is `Route::get('/x', $handler)` (or
    post/put/patch/delete/options/any). Requires at least two arguments, the
    same guard every other language's own registration-call check applies."""
    scope = call.child_by_field_name("scope")
    name_node = call.child_by_field_name("name")
    args = call.child_by_field_name("arguments")
    if scope is None or scope.type != "name" or _text(scope, src) != "Route":
        return False
    if name_node is None or _text(name_node, src) not in ROUTE_FACADE_METHODS or args is None:
        return False
    return sum(1 for c in args.children if c.type == "argument") >= 2


def route_verb_and_path(call: Node, args: Node, src: bytes) -> tuple[str, str]:
    name_node = call.child_by_field_name("name")
    verb = _text(name_node, src).upper() if name_node is not None else "ROUTE"
    first = next((c for c in args.children if c.type == "argument"), None)
    value = _argument_value(first) if first is not None else None
    path = _string_literal_value(value, src) if value is not None and value.type in ("string", "encapsed_string") \
        else "?"
    return verb, path


def route_handler(args: Node) -> Node | None:
    """The handler argument: the second `argument` node's own value,
    unwrapped the same way `_argument_value()` unwraps any other."""
    arguments = [c for c in args.children if c.type == "argument"]
    if len(arguments) < 2:
        return None
    return _argument_value(arguments[1])
