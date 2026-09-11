"""Unit tests for the Python half of scanner/callgraph/ (python_syntax.py,
python_entrypoints.py, python_index.py).

Same discipline as tests/test_callgraph.py: every case is real Python
source parsed for real, no hand-built Index fixtures -- the tree-sitter
node walking is the thing most likely to break, and a fixture would skip
exactly that. index_workspace() is the shared entry point for both
languages, so these tests call the same function the Java tests do.
"""
from pathlib import Path

from scanner.callgraph import ANY_ARITY, callers_of, enclosing_method, index_workspace, trace_to_entry_points


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


class TestFlaskEntryPoints:
    def test_a_route_decorator_is_a_definitive_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"app.py": """
            from flask import Flask
            app = Flask(__name__)

            @app.route("/ping", methods=["POST"])
            def ping():
                pass
        """})
        idx = index_workspace(root)
        ping = next(m for m in idx.methods if m.name == "ping")

        assert ping.is_entry_point and ping.entry_definitive
        assert "route" in ping.entry_reason

    def test_a_get_shortcut_decorator_is_also_recognised(self, tmp_path):
        """Flask 2.0's @app.get(...)/@app.post(...) shorthand -- the same
        shape FastAPI uses natively, which is why one recognizer covers
        both frameworks."""
        root = workspace(tmp_path, {"app.py": """
            @app.get("/x")
            def read():
                pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "read").entry_definitive

    def test_a_blueprint_route_is_recognised_regardless_of_the_object_name(self, tmp_path):
        root = workspace(tmp_path, {"routes.py": """
            @admin_bp.route("/admin")
            def admin_panel():
                pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "admin_panel").entry_definitive

    def test_an_unrelated_decorator_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"app.py": """
            @staticmethod
            def helper():
                pass

            @cache.memoize()
            def cached_thing():
                pass
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestFastApiEntryPoints:
    def test_a_router_get_decorator_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"main.py": """
            from fastapi import APIRouter
            router = APIRouter()

            @router.get("/items")
            def list_items():
                pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "list_items").entry_definitive


class TestDjangoEntryPoints:
    def test_a_request_first_parameter_is_a_weak_hint_not_proof(self, tmp_path):
        """Django's URL resolver calls a view function directly with the
        request as its first argument -- there is no decorator to read, only
        the calling convention. Unlike a route decorator this cannot be
        proven from the function alone, so it is a hint, not definitive --
        the same status Java gives an HttpServletRequest-typed parameter."""
        root = workspace(tmp_path, {"views.py": """
            def show_profile(request, user_id):
                pass
        """})
        idx = index_workspace(root)
        view = next(m for m in idx.methods if m.name == "show_profile")

        assert view.is_entry_point and not view.entry_definitive

    def test_a_method_whose_first_parameter_is_request_is_not_a_false_hint(self, tmp_path):
        """The Django heuristic is for module-level functions specifically --
        a method's first parameter after `self` happens to be named `request`
        far more easily by coincidence, and class-based views are already
        covered on supertype."""
        root = workspace(tmp_path, {"helpers.py": """
            class Logger:
                def log(self, request, message):
                    pass
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "log").is_entry_point

    def test_a_class_based_view_method_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"views.py": """
            from django.views import View

            class ExportView(View):
                def get(self, request):
                    pass
        """})
        idx = index_workspace(root)
        get = next(m for m in idx.methods if m.name == "get")

        assert get.is_entry_point and get.entry_definitive
        assert "View" in get.entry_reason

    def test_a_drf_viewset_action_is_recognised_by_its_own_name(self, tmp_path):
        """list/retrieve/create/... are DRF's action names, not HTTP verbs --
        a separate vocabulary from the class-based-view methods above."""
        root = workspace(tmp_path, {"views.py": """
            from rest_framework.viewsets import ModelViewSet

            class UserViewSet(ModelViewSet):
                def list(self, request):
                    pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "list").entry_definitive

    def test_a_get_method_on_an_unrelated_class_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"cache.py": """
            class Cache:
                def get(self, key):
                    pass
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "get").is_entry_point


class TestArity:
    def test_self_is_stripped_so_arity_matches_how_the_method_is_called(self, tmp_path):
        """def run(self, cmd) is arity 1, not 2 -- a bound call site
        obj.run(x) only ever supplies the one argument Python does not
        make you spell out the receiver for."""
        root = workspace(tmp_path, {"a.py": """
            class Runner:
                def run(self, cmd):
                    pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "run").arity == 1

    def test_a_module_level_function_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.py": """
            def add(a, b):
                pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_a_classmethods_cls_is_stripped_too(self, tmp_path):
        root = workspace(tmp_path, {"a.py": """
            class Factory:
                @classmethod
                def create(cls, name):
                    pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "create").arity == 1

    def test_a_staticmethod_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.py": """
            class Util:
                @staticmethod
                def add(a, b):
                    pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_a_splat_parameter_matches_any_arity(self, tmp_path):
        root = workspace(tmp_path, {"a.py": """
            def run(*args, **kwargs):
                pass
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "run").arity == ANY_ARITY


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_class_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "app.py": """
                from flask import Flask, request
                from runner import CommandRunner
                app = Flask(__name__)

                @app.route("/ping")
                def ping():
                    CommandRunner().run(request.args.get("ip"))
            """,
            "runner.py": """
                import subprocess

                class CommandRunner:
                    def run(self, cmd):
                        subprocess.call(cmd, shell=True)
            """,
        })
        idx = index_workspace(root)
        chains = trace_to_entry_points(idx, "runner.py", 5)

        assert chains
        assert chains[0][-1].caller.name == "ping"

    def test_a_function_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"app.py": """
            def orphan(x):
                pass
        """})
        idx = index_workspace(root)

        assert trace_to_entry_points(idx, "app.py", 2) == []

    def test_a_bare_function_call_resolves_by_name(self, tmp_path):
        root = workspace(tmp_path, {"app.py": """
            @app.route("/x")
            def handler():
                helper()

            def helper():
                pass
        """})
        idx = index_workspace(root)
        helper = next(m for m in idx.methods if m.name == "helper")

        assert [c.caller.name for c in callers_of(idx, helper)] == ["handler"]


class TestSelfCalls:
    def test_self_dot_call_stays_inside_the_hierarchy(self, tmp_path):
        """this.x() / super.x()'s Python spelling: `self.run()` cannot
        resolve outside the caller's own class hierarchy -- the same
        restriction that keeps two unrelated same-named `run` methods
        elsewhere in a corpus from being bridged into one chain."""
        root = workspace(tmp_path, {"a.py": """
            class Consumer:
                def start(self):
                    self.run()

                def run(self):
                    pass

            class UnrelatedThing:
                def run(self):
                    pass
        """})
        idx = index_workspace(root)
        start = next(m for m in idx.methods if m.name == "start")
        run_calls = [c for c in idx.calls if c.callee == "run"]

        assert len(run_calls) == 1 and run_calls[0].caller is start
        matched = callers_of(idx, next(m for m in idx.methods
                                       if m.name == "run" and m.owner.name == "Consumer"))
        assert [c.caller.name for c in matched] == ["start"]

    def test_self_dot_call_reaches_a_base_class_method(self, tmp_path):
        """The template-method direction: `self.x()` in a subclass landing
        on a method only the base class defines."""
        root = workspace(tmp_path, {"a.py": """
            class Base:
                def run(self):
                    pass

            class Sub(Base):
                def start(self):
                    self.run()
        """})
        idx = index_workspace(root)
        run = next(m for m in idx.methods if m.name == "run")

        assert [c.caller.name for c in callers_of(idx, run)] == ["start"]


class TestMixedLanguageWorkspace:
    """The corpus this is actually for: one uploaded zip is not always one
    language, and the two graphs have to share a traversal without
    bridging into each other by accident."""

    def test_java_and_python_index_into_one_shared_graph(self, tmp_path):
        root = workspace(tmp_path, {
            "Service.java": """
                class Service {
                    @org.springframework.web.bind.annotation.GetMapping("/x")
                    public String handle() { return "ok"; }
                }
            """,
            "app.py": """
                @app.route("/y")
                def handle_py():
                    pass
            """,
        })
        idx = index_workspace(root)
        names = {m.name for m in idx.methods}

        assert {"handle", "handle_py"} <= names
        assert next(m for m in idx.methods if m.name == "handle").entry_definitive
        assert next(m for m in idx.methods if m.name == "handle_py").entry_definitive

    def test_an_empty_python_glob_costs_nothing_on_a_java_only_repo(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
