"""What makes a Kotlin function something a request can enter through.

Two frameworks, two unrelated shapes. Spring Boot on Kotlin is structurally
identical to Spring Boot on Java: `@GetMapping("/x")` (or `@PostMapping`,
`@RequestMapping`, ...) directly on a function is proof, read off the
function's own `modifiers` node the same way Java's REQUEST_MAPPING_
ANNOTATIONS is -- kotlin_syntax.py's `_annotation_entries()` is this
grammar's counterpart to Java's `_annotation_names()`, extended to also
carry each annotation's arguments, since (unlike Java's own entry_reason(),
which reports just "@GetMapping") this module reports the actual verb and
path.

Ktor has no annotations at all: a route is a *call* whose own trailing
lambda block is the handler -- `get("/x") { ... }` -- recognised in
kotlin_index.py rather than here, since resolving it needs the enclosing
`route("/prefix") { ... }` chain a call-shape check alone cannot see (see
kotlin_index.py's own docstring). This module only supplies the constant
tables that recognition reads against.
"""
from tree_sitter import Node

from scanner.callgraph.kotlin_syntax import _first_string_arg

MAPPING_VERBS = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH",
}
GENERIC_MAPPING_ANNOTATION = "RequestMapping"

# Ktor's own route-building DSL calls, both always trailing-lambda-shaped.
# `route` only narrows the path prefix for whatever verb calls its lambda
# block nests; the HTTP_VERBS themselves are the actual handlers.
HTTP_VERBS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})
ROUTE_CALL_NAME = "route"


def entry_reason(annotations: list[tuple[str, Node | None]], src: bytes) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint
    -- the Spring-annotation tier only; Ktor's route/verb-call tier is
    resolved in kotlin_index.py."""
    for name, args_node in annotations:
        if name in MAPPING_VERBS:
            path = _first_string_arg(args_node, src) or "?"
            return f"{MAPPING_VERBS[name]} {path}", True
        if name == GENERIC_MAPPING_ANNOTATION:
            path = _first_string_arg(args_node, src) or "?"
            return f"ROUTE {path}", True
    return "", False
