"""What makes a Python function something a request can enter through.

The Python counterpart to entrypoints.py. Flask and FastAPI share one
recognizer because they share one shape -- a decorator that is a call whose
attribute name is an HTTP method (or `route`), on whatever object the
application or router happens to be bound to. Django gets two, because
Django itself has two ways to write a view: a function Django's URL
resolver calls directly with the request as its first argument, and a
class-based view whose `get`/`post`/... methods play the same role
`doGet`/`doPost` play for a Java servlet.
"""
from tree_sitter import Node

from scanner.callgraph.model import Owner
from scanner.callgraph.python_syntax import _decorator_calls, _text

# The attribute name on a Flask/FastAPI route decorator. `route` covers
# Flask's `@app.route(..., methods=[...])` form; the rest cover both
# Flask's HTTP-method shortcuts (`@app.get(...)`, Flask 2.0+) and FastAPI's
# own decorators, which are spelled identically. Matched by attribute name
# alone, not by the object it is called on (`app`, a blueprint, an
# `APIRouter` instance all vary) -- the same trade Java's annotation sets
# make: a decorator this shape on an unrelated object is a false entry
# point that costs a few lines of prompt, and missing a real one costs the
# answer.
ROUTE_DECORATOR_NAMES = frozenset({
    "route", "get", "post", "put", "delete", "patch", "options", "head",
})

# Django class-based views: recognised by supertype, the same reasoning as
# Java's SERVLET_SUPERTYPES -- `get`/`post`/... is too ordinary a method
# name to treat as an entry point on any class that happens to define one.
DJANGO_VIEW_SUPERTYPES = frozenset({
    "View", "APIView", "GenericAPIView", "ViewSet", "ModelViewSet",
    "ListView", "DetailView", "CreateView", "UpdateView", "DeleteView",
    "TemplateView", "RedirectView", "FormView",
})

# Method names Django (and DRF) dispatch to on a recognised view class.
# list/create/retrieve/update/destroy are DRF's ViewSet actions, which do
# not share HTTP verbs' names.
DJANGO_VIEW_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options",
    "list", "create", "retrieve", "update", "partial_update", "destroy",
})


def _route_decorator_entry(decorated: Node, src: bytes) -> tuple[str, bool] | None:
    for obj, attr in _decorator_calls(decorated, src):
        if attr in ROUTE_DECORATOR_NAMES:
            return f"@{obj}.{attr}(...)", True
    return None


def _django_view_method_entry(name: str, owner: Owner) -> tuple[str, bool] | None:
    if name in DJANGO_VIEW_METHODS and set(owner.supertypes) & DJANGO_VIEW_SUPERTYPES:
        return f"{name}() of a {sorted(set(owner.supertypes) & DJANGO_VIEW_SUPERTYPES)[0]}", True
    return None


def _django_function_view_hint(params_node: Node, src: bytes, owner: Owner) -> tuple[str, bool] | None:
    """Django's URL resolver calls a view function directly with the
    request as its first positional argument -- there is no decorator or
    supertype to check, only the calling convention itself. Weak, like
    Java's HttpServletRequest-typed-parameter fallback: a `request` first
    parameter is what a real Django view looks like, but the name alone
    cannot prove the function is wired into urls.py rather than being an
    ordinary helper that happens to be called `request` too. Only offered
    for a module-level function (empty owner) -- a method's first
    parameter after `self` being named `request` is a much weaker signal,
    and Django class-based views are already covered on supertype.
    """
    if owner.name:
        return None
    named = [c for c in params_node.children if c.is_named]
    if named and named[0].type == "identifier" and _text(named[0], src) == "request":
        return "request parameter (Django view)", False
    return None


def _entry_reason(name: str, decorated: Node | None, params_node: Node, src: bytes,
                  owner: Owner) -> tuple[str, bool]:
    """Why a request could enter this function, and whether that is proof
    (a route decorator, a recognised Django view method) or a hint (the
    Django function-view naming convention). Returns ("", False) when
    nothing suggests a request can enter -- mirrors entrypoints.py's
    `_entry_reason` exactly, parameters aside.
    """
    if decorated is not None:
        found = _route_decorator_entry(decorated, src)
        if found:
            return found
    found = _django_view_method_entry(name, owner)
    if found:
        return found
    found = _django_function_view_hint(params_node, src, owner)
    if found:
        return found
    return "", False
