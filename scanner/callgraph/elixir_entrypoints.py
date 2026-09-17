"""What makes an Elixir function something a request can enter through.

Phoenix's router is ordinary Elixir syntax, unlike Play's `conf/routes`
(see scala_routes.py's own docstring for that contrast) -- `get "/path",
PageController, :index` is a macro *call*, parsed by the same grammar as
everything else, so recognition happens inline during elixir_index.py's
own walk rather than needing a second, non-syntax parser. Two shapes:

  - a per-verb call (`get`/`post`/`put`/`patch`/`delete`) names its
    target directly: a controller module (an `alias` node) and an action
    atom (`:index`). Resolved globally across the whole index by
    controller module name and action function name, the same way PHP's
    Laravel facade calls and Ruby's routes.rb entries both are, since a
    Phoenix router module and the controllers it dispatches to almost
    always live in different files.
  - `resources "/path", ControllerModule` is Phoenix's own RESTful macro,
    expanding to up to seven of its own seven conventional actions --
    named differently from Rails' otherwise-identical macro (`delete`,
    not `destroy`), narrowed the same way by an `only:`/`except:` keyword
    list.

A `scope "/prefix", AliasModule do ... end` block nests a path prefix the
same way Kotlin's Ktor `route("/prefix") { ... }` does -- resolved in
elixir_index.py's own `_walk()`, which threads the accumulated prefix
through the recursion, since knowing the full path needs however many
scope blocks enclose the leaf verb call.
"""
HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
RESOURCES_CALL_NAME = "resources"
SCOPE_CALL_NAME = "scope"

# action -> (verb, path suffix appended to "/#{resource}"). Phoenix's own
# seven RESTful actions, in the order its own router documentation lists
# them -- `delete`, unlike Rails' `destroy`, is the one name that differs
# between the two otherwise-parallel macros.
RESOURCES_ACTIONS: tuple[tuple[str, str, str], ...] = (
    ("index", "GET", ""),
    ("new", "GET", "/new"),
    ("create", "POST", ""),
    ("show", "GET", "/:id"),
    ("edit", "GET", "/:id/edit"),
    ("update", "PATCH", "/:id"),
    ("delete", "DELETE", "/:id"),
)
