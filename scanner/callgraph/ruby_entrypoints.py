"""What makes a Ruby method something a request can enter through.

Rails routing is entirely external to the controller: unlike every earlier
language's own annotation/attribute/decorator tier, there is nothing
written on a controller action itself that proves it is one -- the whole
signal lives in `config/routes.rb`, a DSL that is nonetheless ordinary
Ruby syntax (a series of method calls), unlike Scala's Play `conf/routes`
file, which is not Scala syntax at all (see scala_index.py's own routes
file parser for that contrast).

Two shapes cover it. A per-verb call -- `get '/users/:id', to:
'users#show'` -- names its target directly, resolved in ruby_index.py the
same way php_index.py resolves a Laravel `Route::get(...)` facade call:
globally by controller class name and action method name, since
`routes.rb` and the controller it wires up are almost always different
files. `resources :users` is Rails' RESTful macro: one call expands into
up to seven routes (index/show/new/create/edit/update/destroy) against a
controller named by camelizing the symbol, narrowed by an `only:`/`except:`
option list when present -- the one macro-expansion shape in this
project's route-registration recognizers, described briefly by the task
brief that asked for it by name.

The one hint, matching C#'s own convention-routing tier rather than any
parameter-type fallback (Ruby has no type annotations to read at all, see
ruby_syntax.py's own docstring): a public method on a class descending
from ApplicationController/ActionController::Base is *plausibly* a
controller action, the same bet C#'s MVC convention-routing tier makes for
Controller/ControllerBase -- without parsing routes.rb's full DSL (nested
`member`/`collection`/`namespace` blocks, custom `:as`/`:constraints`
options), there is no way to prove which of a controller's public methods
are actually routed, so this is deliberately a hint, not proof, the same
simplification the task's own Ruby notes call for explicitly.
"""
from tree_sitter import Node

from scanner.callgraph.ruby_syntax import _string_or_symbol_value, _text

HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete"})

CONTROLLER_SUPERTYPES = frozenset({"ApplicationController", "ActionController::Base", "Base"})

# action_name -> (verb, path suffix appended to "/#{resource}"). Rails'
# own seven RESTful actions, in the order `resources` documents them.
RESOURCES_ACTIONS: tuple[tuple[str, str, str], ...] = (
    ("index", "GET", ""),
    ("create", "POST", ""),
    ("new", "GET", "/new"),
    ("edit", "GET", "/:id/edit"),
    ("show", "GET", "/:id"),
    ("update", "PATCH", "/:id"),
    ("destroy", "DELETE", "/:id"),
)


def _argument_list(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if c.is_named]


def _pair_value(args: list[Node], key: str, src: bytes) -> Node | None:
    for arg in args:
        if arg.type != "pair":
            continue
        key_node = arg.child_by_field_name("key")
        if key_node is not None and _text(key_node, src).rstrip(":") == key:
            return arg.child_by_field_name("value")
    return None


def route_verb_call(call: Node, src: bytes) -> tuple[str, str, str] | None:
    """`(verb, path, "controller#action")` from a `get '/x', to:
    'ctrl#action'` -shaped call, or None if `call` is not one."""
    method_node = call.child_by_field_name("method")
    if method_node is None or _text(method_node, src) not in HTTP_VERBS:
        return None
    args = _argument_list(call)
    if not args:
        return None
    path = _string_or_symbol_value(args[0], src) if args[0].type in ("string", "simple_symbol") else "?"
    target = _pair_value(args, "to", src)
    if target is None or target.type != "string":
        return None
    target_text = _string_or_symbol_value(target, src)
    if "#" not in target_text:
        return None
    return _text(method_node, src).upper(), path, target_text


def resources_call(call: Node, src: bytes) -> tuple[str, list[str] | None, list[str] | None] | None:
    """`(resource_name, only_list_or_None, except_list_or_None)` from a
    `resources :name[, only: [...]][, except: [...]]`-shaped call, or None
    if `call` is not one."""
    method_node = call.child_by_field_name("method")
    if method_node is None or _text(method_node, src) != "resources":
        return None
    args = _argument_list(call)
    if not args or args[0].type != "simple_symbol":
        return None
    name = _string_or_symbol_value(args[0], src)

    def symbol_list(key: str) -> list[str] | None:
        value = _pair_value(args, key, src)
        if value is None or value.type != "array":
            return None
        return [_string_or_symbol_value(c, src) for c in value.children if c.type == "simple_symbol"]

    return name, symbol_list("only"), symbol_list("except")


def entry_reason(is_public: bool, owner_supertypes: tuple[str, ...]) -> tuple[str, bool]:
    """Why a request could enter here -- the convention-routing tier only;
    route-registration resolution (both verb calls and `resources`)
    happens in ruby_index.py since it needs the whole-index name search
    every other language's own route-registration-call handling already
    does.

    A hint, not proof -- the one place this tier's own trade differs from
    C#'s. ASP.NET MVC's convention routing really does dispatch *every*
    public action on a Controller-derived type without a per-route
    declaration; Rails requires routes.rb (or `resources`) to expose any
    action at all, so a public method with no such declaration is not
    reachable, whatever its class inherits from. Marking it proof was
    tried first and measured to be actively harmful: `resources`'s own
    `only:`/`except:` narrowing (real routes.rb signal, precise) would
    have nothing to narrow, since every public method would already read
    as a definitive entry on its own, and a route-registration match would
    never get the chance to overwrite this generic label with the actual
    verb and path (_resolve_named_references() only updates a method that
    is not yet entry_definitive). A hint costs nothing a real
    route-registration match cannot already override for free."""
    if is_public and owner_supertypes and set(owner_supertypes) & CONTROLLER_SUPERTYPES:
        return "convention-routed controller action", False
    return "", False
