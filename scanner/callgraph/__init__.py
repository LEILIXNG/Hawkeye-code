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

JavaScript/TypeScript support (2026-09-11), js_syntax.py / js_entrypoints.py
/ js_index.py, same model reuse again. The one structural difference from
Java and Python: Express/Koa route handlers are very often anonymous --
`app.get(path, (req, res) => {...})` -- so js_index.py creates a Method for
one at the call site itself rather than only ever reading a name off a
declaration, and resolves a *named* handler reference in a same-file
second pass once the whole file's declarations are known. NestJS routes by
decorator instead, the same shape Java's annotations and Python's
decorators use. Next.js's file-based routing is not attempted -- there is
no in-function signal to read for it at all, the entry point is a fact
about the file path and export shape, not the function body.

Go support (2026-09-14), go_syntax.py / go_entrypoints.py / go_index.py,
same model reuse a third time. Structurally closest to JS/TS: Go has no
annotations or decorators either, so net/http, gorilla/mux, chi, gin and
echo are all recognised the same way Express is, by a route-registration
*call* (`router.GET(path, handler)`) rather than anything written on the
handler -- go_index.py reuses JS's inline-literal-at-the-call-site plus
same-file-second-pass-for-a-named-reference approach, extended to also
resolve a *method value* (`router.GET(path, h.GetUser)`), a handler shape
JS's own two forms do not have. The other structural difference: Go has no
`this`/`self` keyword, so Call.receiver_is_self is decided by comparing a
call's receiver against the enclosing method's own author-chosen receiver
variable name (read off the receiver clause itself) rather than against a
fixed keyword.

C++ support adds cpp_syntax.py / cpp_index.py. It indexes functions,
methods and calls into the same graph, but deliberately declares no generic
request entry point: C++ server frameworks do not share a reliable source
annotation or registration shape. Framework adapters can add those signals
later without changing the shared traversal.

Rust support (2026-09-17), rust_syntax.py / rust_entrypoints.py /
rust_index.py, same model reuse a fourth time. Ownership is read
differently than in every class-based language above: a method is never
declared inside the type it belongs to (`struct User {}` and
`impl User { fn find(&self) {} }` are separate top-level items), so Owner
comes fresh from the nearest enclosing `impl` block rather than from a type
declaration that states every supertype once -- and because one type can
gain trait impls from any number of separate `impl Trait for Type` blocks,
index.supertypes accumulates per type here instead of being overwritten by
the latest Owner computed, the one thing every earlier language's single
type-declaration site let it skip. Entry points mirror Java/Python's
attribute-macro recognition for actix-web and Rocket (`#[get("/x")]`) and
Go/JS's registration-call recognition for axum and actix's builder style
(`.route(path, get(handler))`, `.route(path, web::get().to(handler))`).
Self-calls are simpler than Go's: `self` is a fixed grammar production here,
not an author-named receiver variable that has to be compared by text.

C# support (2026-09-17), csharp_syntax.py / csharp_entrypoints.py /
csharp_index.py, same model reuse a fifth time. Structurally closest to
Java's: methods live inside class/interface bodies, `this` is a fixed
keyword, and (unlike Rust's scattered `impl Trait for Type` blocks)
Owner.supertypes still accumulates per type rather than being overwritten,
here because a `partial class` can state different slices of its base list
across several files. Entry points are three-tiered like Java's: an
HTTP-verb/Route attribute on the method is proof (ASP.NET Core attribute
routing); a public method with no such attribute on a type whose base list
includes Controller/ControllerBase is proof too (MVC's convention routing,
where every public action is reachable by name alone); an
HttpContext/HttpRequest/HttpResponse-typed parameter with neither is a
hint. Minimal-API registration (`app.MapGet("/x", handler)`) is a fourth,
call-shaped signal read the same way Go/Rust resolve a named handler
reference or index an inline lambda at the call site.

PHP support (2026-09-17), php_syntax.py / php_entrypoints.py / php_index.py,
same model reuse a sixth time. Structurally closest to C#'s: methods live in
class bodies, a class states its base class and interface list in one
place. `$this` is the one departure from every earlier class-based
language's own fixed keyword: it parses as an ordinary `variable_name`
whose text happens to be `this`, so receiver_is_self compares text instead
of a node type. Entry points cover Laravel and Symfony, the two frameworks
that share PHP 8's `#[Route(...)]` attribute syntax, plus Symfony's older
`@Route(...)` PHPDoc annotation (read by regex over a comment's text, since
a docblock carries no parsed argument list at all) and Laravel's
`Route::get('/x', $handler)` facade calls -- the first route-registration
call in this project where the handler almost always lives in a different
file than the registration itself (`[Controller::class, 'method']` naming a
class the routes file never declares), so its named-reference resolution
pass matches globally across the whole index by owner class name and method
name rather than the same-file search every earlier language's own version
of that pass uses. The one hint with no parameter-type equivalent: a
function body reading `$_GET`/`$_POST`/`$_REQUEST` directly, since PHP has
no request-object parameter to check in the first place.

Ruby support (2026-09-17), ruby_syntax.py / ruby_entrypoints.py /
ruby_index.py, same model reuse a seventh time. Rails routing is entirely
external to the controller -- there is no annotation/attribute/decorator
tier at all here, unlike every earlier language -- so entry points come
from two places: routes.rb's own per-verb calls (`get '/x', to:
'users#show'`) and its `resources :users` RESTful macro, both resolved
globally across the whole index the same way PHP's Laravel facade
resolution is, since routes.rb and the controller it wires up are almost
always different files; and a public method on an ApplicationController/
ActionController::Base subclass, treated as proof the same way C#'s own
convention-routing tier is, though Rails (unlike ASP.NET MVC) does not
actually expose every public controller method without a routes.rb entry
-- a deliberate over-approximation, not a claim the two frameworks work
alike. `private`/`protected`/`public` are ordinary method calls that flip
a class body's default visibility for every `def` after them, not
modifiers on the declaration itself, so ruby_index.py's own class-body
walk tracks that state sequentially rather than delegating to the
generic per-child dispatch every earlier language's `_walk()` uses
unconditionally. The one call shape invisible to this module: a bare,
zero-argument, no-parens call (`helper`) is syntactically indistinguishable
from a local-variable read in this grammar, so it produces no Call edge --
a known gap, not attempted here.

Kotlin support (2026-09-17), kotlin_syntax.py / kotlin_entrypoints.py /
kotlin_index.py, same model reuse an eighth time. Two frameworks, two
unrelated entry-point shapes: Spring Boot on Kotlin is structurally
identical to Spring Boot on Java (`@GetMapping("/x")` on a function is
proof, read off a `modifiers` node the same way Java's annotations are).
Ktor has no annotations at all -- a route is a *call* ending in a
trailing lambda block (`get("/x") { ... }`), and unlike every earlier
language's route-registration-call recognition, the real path is only
ever half visible at the call site itself: `route("/api") { get("/users")
{ ... } }` nests a path prefix through however many `route(...)` blocks
wrap the leaf verb call, so kotlin_index.py's own `_walk()` threads a
`route_prefix` string through the recursion, extended on entering a
`route(...)` call's lambda body -- the one piece of state no earlier
language's own version of `_walk()` needed to carry. The other
Kotlin-specific grammar trap: a call ending in a trailing lambda block
carries that lambda as a second, separate child rather than inside its
`value_arguments`, so recognising `get("/x") { ... }` means checking two
different places depending on whether the call ends in a block.

Scala support (2026-09-17), scala_syntax.py / scala_index.py / (for
routing) scala_routes.py, same model reuse a ninth time. The most
structurally unusual language here: Play Framework, the one Scala web
framework this project targets, has no annotation, decorator or
registration-call convention on a controller action at all -- `def
index() = Action { ... }` is an ordinary method indistinguishable from
any other by source alone, so scala_index.py recognises no entry point on
its own. The entire signal lives in `conf/routes`, a fixed-column text
format that is not Scala syntax -- `GET /users/:id
controllers.UserController.show(id: String)` -- read by scala_routes.py's
own line-level parser rather than tree-sitter, the same "external file
names the method, source never proves it" shape mybatis.py already uses
for a MyBatis mapper statement. The one real difference from mybatis.py:
a mapper's XML span *is* the sink and gets a brand new synthetic Method,
while a routes line only ever *points at* an existing one, so
scala_routes.py updates a Method already built by scala_index.py in
place, matching globally by controller class name and action method name
the same way PHP's Laravel facade resolution and Ruby's routes.rb
resolution both do. The other Scala-specific grammar trap: an
`extends_clause`'s base class and every `with`-mixed-in trait
(`class X extends Base with Greeter with Loggable`) all share the *same*
field name, so reading the full supertype list means filtering by node
type rather than a single field lookup.
"""
from scanner.callgraph.entrypoints import (MESSAGE_ENTRY_ANNOTATIONS, REQUEST_MAPPING_ANNOTATIONS,
                                           REQUEST_PARAM_ANNOTATIONS, REQUEST_PARAM_TYPES,
                                           SERVLET_ENTRY_METHODS, SERVLET_SUPERTYPES)
from scanner.callgraph.go_entrypoints import HANDLER_PARAM_TYPES
from scanner.callgraph.go_entrypoints import HTTP_METHOD_NAMES as GO_HTTP_METHOD_NAMES
from scanner.callgraph.go_index import index_go_workspace
from scanner.callgraph.index import IDENTIFIER_LITERAL, index_workspace
from scanner.callgraph.cpp_index import index_cpp_workspace
from scanner.callgraph.js_entrypoints import HTTP_METHOD_NAMES, NEST_DECORATOR_NAMES
from scanner.callgraph.js_index import index_js_workspace
from scanner.callgraph.kotlin_entrypoints import HTTP_VERBS as KOTLIN_HTTP_VERBS
from scanner.callgraph.kotlin_entrypoints import MAPPING_VERBS as KOTLIN_MAPPING_VERBS
from scanner.callgraph.kotlin_index import index_kotlin_workspace
from scanner.callgraph.model import ANY_ARITY, MAX_DEPTH, Call, Index, Method, Owner
from scanner.callgraph.mybatis import MYBATIS_STATEMENT_TAGS, index_mybatis_mappers
from scanner.callgraph.csharp_entrypoints import CONTROLLER_SUPERTYPES as CSHARP_CONTROLLER_SUPERTYPES
from scanner.callgraph.csharp_entrypoints import HANDLER_PARAM_TYPES as CSHARP_HANDLER_PARAM_TYPES
from scanner.callgraph.csharp_index import index_csharp_workspace
from scanner.callgraph.php_entrypoints import ROUTE_FACADE_METHODS as PHP_ROUTE_FACADE_METHODS
from scanner.callgraph.php_index import index_php_workspace
from scanner.callgraph.python_entrypoints import DJANGO_VIEW_SUPERTYPES, ROUTE_DECORATOR_NAMES
from scanner.callgraph.python_index import index_python_workspace
from scanner.callgraph.ruby_entrypoints import CONTROLLER_SUPERTYPES as RUBY_CONTROLLER_SUPERTYPES
from scanner.callgraph.ruby_entrypoints import HTTP_VERBS as RUBY_HTTP_VERBS
from scanner.callgraph.ruby_index import index_ruby_workspace
from scanner.callgraph.rust_entrypoints import HANDLER_PARAM_TYPES as RUST_HANDLER_PARAM_TYPES
from scanner.callgraph.rust_entrypoints import HTTP_ROUTE_VERBS as RUST_HTTP_ROUTE_VERBS
from scanner.callgraph.rust_index import index_rust_workspace
from scanner.callgraph.scala_index import index_scala_workspace
from scanner.callgraph.scala_routes import HTTP_VERBS as SCALA_HTTP_VERBS
from scanner.callgraph.scala_routes import index_play_routes
from scanner.callgraph.traverse import callers_of, enclosing_method, trace_to_entry_points

__all__ = [
    "ANY_ARITY", "CSHARP_CONTROLLER_SUPERTYPES", "CSHARP_HANDLER_PARAM_TYPES",
    "DJANGO_VIEW_SUPERTYPES", "GO_HTTP_METHOD_NAMES", "HANDLER_PARAM_TYPES",
    "HTTP_METHOD_NAMES", "IDENTIFIER_LITERAL", "KOTLIN_HTTP_VERBS", "KOTLIN_MAPPING_VERBS", "MAX_DEPTH",
    "MESSAGE_ENTRY_ANNOTATIONS", "MYBATIS_STATEMENT_TAGS", "NEST_DECORATOR_NAMES",
    "PHP_ROUTE_FACADE_METHODS",
    "REQUEST_MAPPING_ANNOTATIONS", "REQUEST_PARAM_ANNOTATIONS", "REQUEST_PARAM_TYPES",
    "ROUTE_DECORATOR_NAMES", "RUBY_CONTROLLER_SUPERTYPES", "RUBY_HTTP_VERBS",
    "RUST_HANDLER_PARAM_TYPES", "RUST_HTTP_ROUTE_VERBS", "SCALA_HTTP_VERBS",
    "SERVLET_ENTRY_METHODS", "SERVLET_SUPERTYPES",
    "Call", "Index", "Method", "Owner", "callers_of", "enclosing_method",
    "index_cpp_workspace", "index_csharp_workspace", "index_go_workspace", "index_js_workspace",
    "index_kotlin_workspace", "index_mybatis_mappers", "index_php_workspace", "index_play_routes",
    "index_python_workspace", "index_ruby_workspace", "index_rust_workspace", "index_scala_workspace",
    "index_workspace", "trace_to_entry_points",
]
