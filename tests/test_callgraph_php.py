"""Unit tests for the PHP half of scanner/callgraph/ (php_syntax.py,
php_entrypoints.py, php_index.py).

Same discipline as tests/test_callgraph_rust.py and its siblings: every
case is real PHP source parsed for real, no hand-built Index fixtures.
index_workspace() is the shared entry point for every language, so these
tests call the same function the others do.
"""
from pathlib import Path

from scanner.callgraph import callers_of, index_workspace, trace_to_entry_points


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


class TestAttributeRoutingEntryPoints:
    def test_a_route_attribute_with_methods_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"C.php": """<?php
            class UserController {
                #[Route("/users/{id}", methods: ["GET"])]
                public function show($id) { return $id; }
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "show")

        assert method.entry_definitive
        assert method.entry_reason == "GET /users/{id}"

    def test_a_route_attribute_with_no_methods_is_a_generic_route(self, tmp_path):
        root = workspace(tmp_path, {"C.php": """<?php
            class C {
                #[Route("/x")]
                public function m() {}
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "m").entry_reason == "ROUTE /x"

    def test_multiple_methods_each_yield_their_own_verb(self, tmp_path):
        root = workspace(tmp_path, {"C.php": """<?php
            class C {
                #[Route("/x", methods: ["GET", "POST"])]
                public function m() {}
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "m").entry_reason == "GET /x, POST /x"

    def test_an_unrelated_attribute_is_not_mistaken_for_a_route(self, tmp_path):
        root = workspace(tmp_path, {"C.php": """<?php
            class C {
                #[Deprecated]
                public function helper() {}
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "helper").is_entry_point


class TestPhpDocRouteEntryPoints:
    def test_a_phpdoc_route_annotation_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"C.php": """<?php
            class C {
                /**
                 * @Route("/legacy", methods={"POST"})
                 */
                public function legacy() {}
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "legacy")

        assert method.entry_definitive
        assert method.entry_reason == "POST /legacy"

    def test_an_ordinary_docblock_is_not_mistaken_for_a_route(self, tmp_path):
        root = workspace(tmp_path, {"C.php": """<?php
            class C {
                /**
                 * Does some unrelated thing.
                 */
                public function helper() {}
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "helper").is_entry_point


class TestLaravelRouteFacadeEntryPoints:
    def test_an_inline_closure_handler_becomes_a_synthetic_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"web.php": """<?php
            Route::get('/ping', function () {
                return 'pong';
            });
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_definitive
        assert handler.entry_reason == "GET /ping"

    def test_an_array_callable_handler_resolves_across_files(self, tmp_path):
        root = workspace(tmp_path, {
            "web.php": """<?php
                Route::get('/users', [UserController::class, 'index']);
            """,
            "UserController.php": """<?php
                class UserController {
                    public function index() { return []; }
                }
            """,
        })
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "index")

        assert handler.entry_definitive and handler.entry_reason == "GET /users"

    def test_a_string_callable_handler_resolves_across_files(self, tmp_path):
        root = workspace(tmp_path, {
            "web.php": """<?php
                Route::post('/login', 'Auth\\\\LoginController@store');
            """,
            "LoginController.php": """<?php
                namespace Auth;
                class LoginController {
                    public function store() { return true; }
                }
            """,
        })
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "store")

        assert handler.entry_definitive and handler.entry_reason == "POST /login"

    def test_a_single_argument_call_is_not_a_route_registration(self, tmp_path):
        root = workspace(tmp_path, {"web.php": """<?php
            Route::get('/x');
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)

    def test_a_call_on_an_unrelated_class_is_not_a_route_registration(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            class Cache {
                public static function get($key, $default) { return $default; }
            }
            Cache::get('x', 'y');
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestSuperglobalHint:
    def test_a_function_reading_get_is_a_weak_hint_not_proof(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            function standaloneHandler() {
                return $_GET['id'];
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "standaloneHandler")

        assert method.is_entry_point and not method.entry_definitive

    def test_a_plain_helper_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            function add($a, $b) { return $a + $b; }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "add").is_entry_point


class TestArityAndOwnership:
    def test_a_plain_function_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.php": "<?php function add($a, $b) { return $a + $b; }"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_promoted_constructor_parameters_are_counted(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            class Service {
                public function __construct(private Db $db, int $count = 0) {}
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "__construct").arity == 2

    def test_a_method_is_owned_by_its_class(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            class UserService {
                public function find($id) { return $id; }
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_an_interface_method_signature_is_not_indexed(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            interface Greeter {
                public function greet();
            }
        """})
        idx = index_workspace(root)

        assert idx.methods == []

    def test_extends_and_implements_are_both_recorded_as_supertypes(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            class Base {}
            interface IFoo {}
            class Derived extends Base implements IFoo {
                public function m() {}
            }
        """})
        idx = index_workspace(root)

        assert set(idx.supertypes["Derived"]) == {"Base", "IFoo"}


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "UserController.php": """<?php
                class UserController {
                    #[Route("/users/{id}", methods: ["GET"])]
                    public function show($id) {
                        return findUser($id);
                    }
                }
            """,
            "db.php": """<?php
                function findUser($username) {
                    return "SELECT * FROM users WHERE username = '" . $username . "'";
                }
            """,
        })
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "findUser")
        chains = trace_to_entry_points(idx, "db.php", find_user.start_line)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET /users/{id}"

    def test_a_function_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.php": "<?php function orphan($x) {}"})
        idx = index_workspace(root)
        orphan = next(m for m in idx.methods if m.name == "orphan")

        assert trace_to_entry_points(idx, "a.php", orphan.start_line) == []


class TestSelfCalls:
    def test_calling_through_this_stays_inside_the_type(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            class Consumer {
                public function start() { $this->run(); }
                public function run() {}
            }
            class Unrelated {
                public function run() {}
            }
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["start"]

    def test_a_call_through_a_field_is_not_treated_as_a_self_call(self, tmp_path):
        root = workspace(tmp_path, {"a.php": """<?php
            class Handler {
                public function getUser($id) {
                    return $this->svc->lookup($id);
                }
            }
        """})
        idx = index_workspace(root)
        lookup_call = next(c for c in idx.calls if c.callee == "lookup")

        assert lookup_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_java_python_js_go_rust_csharp_and_php_index_into_one_shared_graph(self, tmp_path):
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
            "main.go": """
                package main

                func setup() {
                    http.HandleFunc("/w", func(w http.ResponseWriter, r *http.Request) {})
                }
            """,
            "main.rs": """
                #[get("/v")]
                async fn handle_rs() {}
            """,
            "C.cs": """
                public class C : ControllerBase {
                    [HttpGet("/u")]
                    public string Handle() { return "ok"; }
                }
            """,
            "web.php": """<?php
                class C {
                    #[Route("/t")]
                    public function handle() { return "ok"; }
                }
            """,
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 7

    def test_a_java_only_repo_pays_nothing_for_the_empty_php_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
