"""What makes a method something a request can enter through.

The annotation and supertype vocabularies, and the one function that reads a
method declaration against them. Kept apart from the indexing walk because
this is the half that grows when a new framework turns up in a corpus, and
it grows by editing a frozenset rather than the tree walking.
"""
from tree_sitter import Node

from scanner.callgraph.model import Owner
from scanner.callgraph.syntax import _annotation_names, _text


# Annotations that put a method (or one of its parameters) directly on the
# request path. VulnerableAppRequestMapping is this corpus's own wrapper
# around Spring's mapping annotations.
REQUEST_MAPPING_ANNOTATIONS = frozenset({
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
    "DeleteMapping", "PatchMapping", "VulnerableAppRequestMapping",
})
REQUEST_PARAM_ANNOTATIONS = frozenset({
    "RequestParam", "RequestBody", "PathVariable", "RequestHeader",
    "CookieValue", "ModelAttribute", "RequestPart",
})
REQUEST_PARAM_TYPES = frozenset({"HttpServletRequest", "MultipartFile", "HttpEntity"})

# Framework callbacks that carry externally supplied data the same way an HTTP
# handler does: the payload is written by whoever put it on the queue or the
# socket. @Scheduled, @PostConstruct and @Bean are deliberately absent -- the
# framework invokes those too, but with nothing a user chose.
MESSAGE_ENTRY_ANNOTATIONS = frozenset({
    "KafkaListener", "RabbitListener", "RabbitHandler", "JmsListener",
    "SqsListener", "RocketMQMessageListener", "StreamListener",
    "MessageMapping", "SubscribeMapping", "ExceptionHandler",
})

# The servlet/filter entry points, recognised by supertype rather than by name
# alone: `service` and `doFilter` are ordinary words, and treating every method
# called `service` as a request handler would invent entry points all over a
# Spring codebase. rules/ruleset.yml mounts java/servlets/security, so the
# ruleset can already produce candidates in code shaped like this.
SERVLET_SUPERTYPES = frozenset({
    "HttpServlet", "GenericServlet", "Servlet", "Filter", "HttpFilter",
    "OncePerRequestFilter", "HandlerInterceptor", "HandlerInterceptorAdapter",
})


SERVLET_ENTRY_METHODS = frozenset({
    "doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace",
    "service", "doFilter", "preHandle", "postHandle",
})


def _entry_reason(method_node: Node, src: bytes, owner: Owner) -> tuple[str, bool]:
    """Why a request could enter here, and whether that is proof or a hint.

    Returns ("", False) when nothing suggests a request can enter.
    """
    if method_node.child_by_field_name("name") is not None and owner.supertypes:
        name = _text(method_node.child_by_field_name("name"), src)
        if name in SERVLET_ENTRY_METHODS and set(owner.supertypes) & SERVLET_SUPERTYPES:
            return f"{name}() of a {sorted(set(owner.supertypes) & SERVLET_SUPERTYPES)[0]}", True

    modifiers = next((c for c in method_node.children if c.type == "modifiers"), None)
    if modifiers is not None:
        mapped = _annotation_names(modifiers, src) & (REQUEST_MAPPING_ANNOTATIONS | MESSAGE_ENTRY_ANNOTATIONS)
        if mapped:
            return f"@{sorted(mapped)[0]}", True

    params = method_node.child_by_field_name("parameters")
    if params is None:
        return "", False
    weak = ""
    for param in params.children:
        if param.type != "formal_parameter":
            continue
        param_modifiers = next((c for c in param.children if c.type == "modifiers"), None)
        if param_modifiers is not None:
            annotated = _annotation_names(param_modifiers, src) & REQUEST_PARAM_ANNOTATIONS
            if annotated:
                return f"@{sorted(annotated)[0]} parameter", True
        type_node = param.child_by_field_name("type")
        if not weak and type_node is not None and _text(type_node, src).split("<")[0] in REQUEST_PARAM_TYPES:
            weak = f"{_text(type_node, src)} parameter"
    # Keep looking for an annotated parameter before settling for a type:
    # a handler often has both, and the annotation is the stronger claim.
    return weak, False
