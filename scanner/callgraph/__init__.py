"""D: a reverse call graph over the Java and Python sources in a workspace.

Semgrep OSS taint analysis is intraprocedural, so a candidate's reported
"source" is only ever the nearest tainted expression inside the same method.
On the corpus that means AuthLoginService.java:44 -> :51, where line 44 is a
local `sql` string -- true, and useless for deciding exploitability, because
the thing that decides it is that `username` came from an @RequestParam in
AuthenticationVulnerability.java, a different file entirely. The verify stage
was being handed one method and asked a question only its callers can answer.

This walks the other way: given a sink location, find the method containing
it, then the methods that call that method, and so on, until it reaches
something a request can enter through. It is a name-and-arity call graph, not
a resolved one -- there is no type resolution here, so two same-named methods
with the same parameter count are indistinguishable. That is deliberate: the
chains it produces are handed to the LLM as context, and an extra plausible
caller costs a few lines of prompt, while a missing one costs the answer.
docs/framework.md section D calls for exactly this, minus the Java sidecar
that CLAUDE.md replaced with Python.

Split out of a single 538-line module. The names re-exported below are the
package's public API, importable from `scanner.callgraph` exactly as they
were before the split; the module boundaries inside are an internal detail.

Python support (2026-09-11) added python_syntax.py / python_entrypoints.py /
python_index.py alongside their Java counterparts, feeding the same Method /
Call / Owner / Index model.py already defined language-agnostically -- so
traverse.py, callers_of() and trace_to_entry_points() needed no changes at
all to gain a second language. Flask and FastAPI share one recognizer (a
route decorator, matched by attribute name); Django gets its own two, for
its two ways of writing a view. Nothing here resolves urls.py, so a Django
function view is recognised by its calling convention (a `request` first
parameter) rather than proven the way a route decorator or a class-based
view's supertype is -- a hint, like Java's HttpServletRequest-typed-parameter
fallback, not a certainty.
"""
from scanner.callgraph.entrypoints import (MESSAGE_ENTRY_ANNOTATIONS, REQUEST_MAPPING_ANNOTATIONS,
                                           REQUEST_PARAM_ANNOTATIONS, REQUEST_PARAM_TYPES,
                                           SERVLET_ENTRY_METHODS, SERVLET_SUPERTYPES)
from scanner.callgraph.index import IDENTIFIER_LITERAL, index_workspace
from scanner.callgraph.model import ANY_ARITY, MAX_DEPTH, Call, Index, Method, Owner
from scanner.callgraph.mybatis import MYBATIS_STATEMENT_TAGS, index_mybatis_mappers
from scanner.callgraph.python_entrypoints import DJANGO_VIEW_SUPERTYPES, ROUTE_DECORATOR_NAMES
from scanner.callgraph.python_index import index_python_workspace
from scanner.callgraph.traverse import callers_of, enclosing_method, trace_to_entry_points

__all__ = [
    "ANY_ARITY", "DJANGO_VIEW_SUPERTYPES", "IDENTIFIER_LITERAL", "MAX_DEPTH",
    "MESSAGE_ENTRY_ANNOTATIONS", "MYBATIS_STATEMENT_TAGS", "REQUEST_MAPPING_ANNOTATIONS",
    "REQUEST_PARAM_ANNOTATIONS", "REQUEST_PARAM_TYPES", "ROUTE_DECORATOR_NAMES",
    "SERVLET_ENTRY_METHODS", "SERVLET_SUPERTYPES",
    "Call", "Index", "Method", "Owner", "callers_of", "enclosing_method",
    "index_mybatis_mappers", "index_python_workspace", "index_workspace", "trace_to_entry_points",
]
