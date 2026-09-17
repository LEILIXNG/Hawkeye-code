"""Play Framework's `conf/routes`, linked onto the Scala controller
methods it names -- the routing-table half of this project's Scala
support, and the one entry-point signal Scala has at all (see
scala_index.py's own docstring for why nothing in scala_index.py itself
recognises a controller action).

A routes file is a fixed-column text format, not Scala:

    GET     /users/:id          controllers.UserController.show(id: String)

-- method, path, and a controller reference that is *not* an expression
this grammar parses, just a dotted name followed by an optional
parameter-type signature this module never needs to read (the target
method's own real parameter list is already indexed by scala_index.py).
Reused from mybatis.py's own precedent for exactly this shape: an
external, non-source config file that names a method by string rather
than the source itself proving it -- except mybatis.py's XML statement
*is* the sink and gets a brand new Method, while a routes line only ever
*points at* one, so this module updates an existing Method's
entry_reason/entry_definitive in place, matching globally by controller
class name and action method name the same way php_index.py's Laravel
facade resolution and ruby_index.py's routes.rb resolution both do --
`conf/routes` and `app/controllers/` are always separate directories.
"""
import re
from pathlib import Path

from scanner.callgraph.model import Index

HTTP_VERBS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# method, path, dotted controller reference (package(s) + class + action,
# e.g. `controllers.HomeController.index`) -- the optional `(id: String)`
# parameter-type signature some lines carry is left for whatever follows
# the captured method name to fall off unmatched, since scala_index.py's
# own Method already carries the action's real parameters.
ROUTE_LINE = re.compile(
    r"^(?P<verb>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?P<path>\S+)\s+(?P<target>[\w.]+)"
)


def _parse_route_lines(text: str) -> list[tuple[str, str, str, str]]:
    """`[(verb, path, controller_class, action_name), ...]` for every
    routable line. Comments (`# ...`), blank lines and `->` include
    directives (routing to another routes file's own prefix, not a
    controller) are silently skipped -- not a claim this reads the whole
    Play routing DSL (string interpolators in the path, `+nocsrf`
    modifiers, `assets:Assets.at`), just the ordinary `VERB path
    controller.Action` shape a real project's routes file is mostly made
    of."""
    results = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("->"):
            continue
        match = ROUTE_LINE.match(line)
        if match is None:
            continue
        target = match.group("target")
        if "." not in target:
            continue
        controller, action = target.rsplit(".", 1)
        class_name = controller.rsplit(".", 1)[-1]
        results.append((match.group("verb"), match.group("path"), class_name, action))
    return results


def index_play_routes(root: Path, index: Index) -> None:
    """Sets entry_reason/entry_definitive on every Scala Method a
    `conf/routes`-shaped file's lines name, across the whole index (see
    this module's own docstring for why the search is global). A file
    just named `routes`, or ending in `.routes` (Play's own convention for
    an included secondary routes file, e.g. `admin.routes`), either way
    with no extension collision against a real source language this tool
    also scans."""
    route_files = [p for p in root.rglob("*") if p.is_file() and (p.name == "routes" or p.name.endswith(".routes"))]
    for path in sorted(route_files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for verb, path_pattern, class_name, action in _parse_route_lines(text):
            description = f"{verb} {path_pattern}"
            for method in index.methods:
                if method.owner.name == class_name and method.name == action and not method.entry_definitive:
                    method.entry_reason = description
                    method.entry_definitive = True
