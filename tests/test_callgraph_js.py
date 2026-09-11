"""Unit tests for the JS/TS half of scanner/callgraph/ (js_syntax.py,
js_entrypoints.py, js_index.py).

Same discipline as tests/test_callgraph.py and test_callgraph_python.py:
every case is real JavaScript/TypeScript source parsed for real, no
hand-built Index fixtures. index_workspace() is the shared entry point for
all three languages, so these tests call the same function the Java and
Python tests do.
"""
from pathlib import Path

from scanner.callgraph import ANY_ARITY, callers_of, index_workspace, trace_to_entry_points


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


class TestExpressEntryPoints:
    def test_an_inline_arrow_handler_becomes_a_synthetic_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"app.js": """
            app.get("/ping", (req, res) => {
                res.send("ok");
            });
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_definitive
        assert handler.entry_reason == "GET /ping"

    def test_an_inline_function_expression_handler_is_recognised_too(self, tmp_path):
        root = workspace(tmp_path, {"app.js": """
            router.post("/x", function (req, res) {
                res.send("ok");
            });
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.entry_reason).entry_reason == "POST /x"

    def test_a_named_handler_reference_is_resolved_in_the_second_pass(self, tmp_path):
        """The common `const listUsers = (req, res) => {...}; app.get(path,
        listUsers);` shape -- the handler's declaration and its
        registration are two separate statements, so recognising it needs
        both to have been seen."""
        root = workspace(tmp_path, {"app.js": """
            const listUsers = (req, res) => {
                res.send("ok");
            };

            app.get("/users", listUsers);
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "listUsers")

        assert handler.entry_definitive and handler.entry_reason == "GET /users"

    def test_a_handler_declared_after_its_registration_still_resolves(self, tmp_path):
        """Source order must not matter -- the second pass runs only once
        the whole file's declarations are known."""
        root = workspace(tmp_path, {"app.js": """
            app.get("/users", listUsers);

            function listUsers(req, res) {
                res.send("ok");
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "listUsers").entry_definitive

    def test_koa_router_is_recognised_the_same_way(self, tmp_path):
        root = workspace(tmp_path, {"routes.js": """
            router.get("/x", async (ctx) => {
                ctx.body = "ok";
            });
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.entry_reason).entry_reason == "GET /x"

    def test_app_use_is_not_a_route_registration(self, tmp_path):
        """Express's generic middleware-mounting call -- treating every
        argument to it as a handler would manufacture entry points out of
        static-file serving and body-parser setup."""
        root = workspace(tmp_path, {"app.js": """
            app.use(express.static("public"));
            app.use((req, res, next) => { next(); });
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)

    def test_a_single_argument_get_call_is_not_a_route_registration(self, tmp_path):
        """Express overloads .get() as a settings getter --
        `app.get("view engine")` reads a value, and only ever has one
        argument; requiring two is what tells the two apart."""
        root = workspace(tmp_path, {"app.js": """
            const engine = app.get("view engine");
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)

    def test_a_middleware_chain_recognises_the_last_argument_as_the_handler(self, tmp_path):
        root = workspace(tmp_path, {"app.js": """
            app.get("/admin", authMiddleware, (req, res) => {
                res.send("ok");
            });
        """})
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 1 and entries[0].entry_reason == "GET /admin"


class TestNestJsEntryPoints:
    def test_a_get_decorator_on_a_controller_method_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"user.controller.ts": """
            import { Controller, Get } from "@nestjs/common";

            @Controller("users")
            class UserController {
                @Get(":id")
                getUser(id: string) {
                    return db.find(id);
                }
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "getUser")

        assert method.entry_definitive and "Get" in method.entry_reason

    def test_a_method_without_a_route_decorator_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"user.controller.ts": """
            @Controller("users")
            class UserController {
                @Get()
                list() { return []; }

                helper(x: string) { return x; }
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "helper").is_entry_point

    def test_a_parameter_decorator_does_not_get_mistaken_for_a_route_one(self, tmp_path):
        """@Param()/@Body()/@Query() decorate a parameter, not the method --
        they must not satisfy the same check that @Get()/@Post() do."""
        root = workspace(tmp_path, {"c.ts": """
            @Controller()
            class C {
                lookup(@Param("id") id: string) {
                    return id;
                }
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "lookup").is_entry_point


class TestArity:
    def test_a_plain_function_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.js": """
            function add(a, b) { return a + b; }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_a_rest_parameter_matches_any_arity(self, tmp_path):
        root = workspace(tmp_path, {"a.js": """
            function run(...args) {}
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "run").arity == ANY_ARITY

    def test_a_bare_single_param_arrow_function_has_arity_one(self, tmp_path):
        root = workspace(tmp_path, {"a.js": """
            const double = x => x * 2;
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "double").arity == 1

    def test_typescript_type_annotations_do_not_change_the_count(self, tmp_path):
        root = workspace(tmp_path, {"a.ts": """
            function add(a: number, b: number): number { return a + b; }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "app.js": """
                const { runPing } = require("./ping");

                app.get("/ping", (req, res) => {
                    runPing(req.query.host);
                    res.send("ok");
                });
            """,
            "ping.js": """
                const { execSync } = require("child_process");

                function runPing(host) {
                    execSync("ping -c 1 " + host, { shell: true });
                }

                module.exports = { runPing };
            """,
        })
        idx = index_workspace(root)
        chains = trace_to_entry_points(idx, "ping.js", 5)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET /ping"

    def test_a_function_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.js": """
            function orphan(x) {}
        """})
        idx = index_workspace(root)

        assert trace_to_entry_points(idx, "a.js", 2) == []

    def test_a_commonjs_exports_assignment_is_indexed_by_its_property_name(self, tmp_path):
        root = workspace(tmp_path, {"a.js": """
            exports.handler = function (event) {
                helper(event);
            };

            function helper(x) {}
        """})
        idx = index_workspace(root)

        assert {"handler", "helper"} <= {m.name for m in idx.methods}
        helper = next(m for m in idx.methods if m.name == "helper")
        assert [c.caller.name for c in callers_of(idx, helper)] == ["handler"]


class TestSelfCalls:
    def test_this_dot_call_stays_inside_the_hierarchy(self, tmp_path):
        root = workspace(tmp_path, {"a.js": """
            class Consumer {
                start() {
                    this.run();
                }
                run() {}
            }

            class UnrelatedThing {
                run() {}
            }
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["start"]

    def test_this_dot_property_dot_call_is_not_treated_as_a_self_call(self, tmp_path):
        """`this.helper.build()` calls a method on a *different* object --
        the receiver is `this.helper`, not `this` -- so it is ordinary
        name+arity matching, not hierarchy-restricted the way `this.x()`
        is."""
        root = workspace(tmp_path, {"a.js": """
            class QueryHelper {
                build(id) { return id; }
            }

            class Controller {
                constructor() { this.helper = new QueryHelper(); }
                getUser(id) {
                    return this.helper.build(id);
                }
            }
        """})
        idx = index_workspace(root)
        build_call = next(c for c in idx.calls if c.callee == "build")

        assert build_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_java_python_and_js_index_into_one_shared_graph(self, tmp_path):
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
            "app.js": """
                app.get("/z", (req, res) => { res.send("ok"); });
            """,
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 3

    def test_a_java_python_only_repo_pays_nothing_for_the_empty_js_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
