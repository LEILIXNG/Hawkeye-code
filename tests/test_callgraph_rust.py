"""Unit tests for the Rust half of scanner/callgraph/ (rust_syntax.py,
rust_entrypoints.py, rust_index.py).

Same discipline as tests/test_callgraph_go.py and its siblings: every case
is real Rust source parsed for real, no hand-built Index fixtures.
index_workspace() is the shared entry point for every language, so these
tests call the same function the others do.
"""
from pathlib import Path

from scanner.callgraph import ANY_ARITY, callers_of, index_workspace, trace_to_entry_points


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


class TestAttributeMacroEntryPoints:
    def test_an_actix_get_attribute_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            #[get("/users/{id}")]
            async fn get_user(path: web::Path<String>) -> HttpResponse {
                HttpResponse::Ok().finish()
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "get_user")

        assert method.entry_definitive
        assert method.entry_reason == "GET /users/{id}"

    def test_a_fully_qualified_attribute_path_is_recognised(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            #[actix_web::post("/login")]
            async fn login() {}
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "login").entry_reason == "POST /login"

    def test_an_unrelated_attribute_is_not_mistaken_for_a_route(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            #[cfg(test)]
            #[allow(dead_code)]
            fn helper() {}
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "helper").is_entry_point

    def test_a_generic_route_attribute_is_recognised(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            #[route("/multi", method = "GET", method = "POST")]
            async fn multi() {}
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "multi")

        assert method.entry_definitive and method.entry_reason == "ROUTE /multi"


class TestRouteRegistrationEntryPoints:
    def test_an_axum_inline_closure_handler_becomes_a_synthetic_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            fn setup() {
                let app = axum::Router::new().route("/ping", get(|req: HttpRequest| async move { req }));
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_definitive
        assert handler.entry_reason == "GET /ping"

    def test_an_axum_named_handler_reference_is_resolved(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            async fn list_users() -> Json<Vec<User>> { Json(vec![]) }

            fn setup() {
                let app = Router::new().route("/users", get(list_users));
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "list_users")

        assert handler.entry_definitive and handler.entry_reason == "GET /users"

    def test_a_handler_declared_after_its_registration_still_resolves(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            fn setup() {
                let app = Router::new().route("/users", get(list_users));
            }

            async fn list_users() -> Json<Vec<User>> { Json(vec![]) }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "list_users").entry_definitive

    def test_chained_verbs_on_one_route_each_resolve_their_own_handler(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            async fn list_users() {}
            async fn create_user() {}

            fn setup() {
                let app = Router::new().route("/users", get(list_users).post(create_user));
            }
        """})
        idx = index_workspace(root)
        list_h = next(m for m in idx.methods if m.name == "list_users")
        create_h = next(m for m in idx.methods if m.name == "create_user")

        assert list_h.entry_reason == "GET /users"
        assert create_h.entry_reason == "POST /users"

    def test_actix_builder_style_to_resolves_a_named_handler(self, tmp_path):
        """actix's alternative to its own attribute macros: a verb builder
        chained with `.to(handler)` rather than the handler being the verb
        call's own argument the way axum's is."""
        root = workspace(tmp_path, {"main.rs": """
            fn legacy_handler(req: HttpRequest) -> HttpResponse { HttpResponse::Ok().finish() }

            fn setup() {
                let app = App::new().route("/legacy", web::get().to(legacy_handler));
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "legacy_handler")

        assert handler.entry_definitive and handler.entry_reason == "ROUTE /legacy"

    def test_a_single_argument_call_is_not_a_route_registration(self, tmp_path):
        """A one-argument `.route(...)` call on some unrelated builder must
        not be mistaken for route registration -- the same guard Go's and
        JS's own is_route_registration() apply for the same reason."""
        root = workspace(tmp_path, {"main.rs": """
            fn setup() {
                let value = cache.route(key);
            }
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestSignatureBasedEntryPoints:
    def test_a_handler_shaped_parameter_is_a_weak_hint_not_proof(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            fn standalone_handler(req: HttpRequest) -> HttpResponse {
                HttpResponse::Ok().finish()
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "standalone_handler")

        assert method.is_entry_point and not method.entry_definitive

    def test_a_plain_helper_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"main.rs": """
            fn add(a: i32, b: i32) -> i32 { a + b }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "add").is_entry_point


class TestArityAndOwnership:
    def test_a_plain_function_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.rs": "fn add(a: i32, b: i32) -> i32 { a + b }"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_self_is_not_counted_as_a_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.rs": """
            struct Service;
            impl Service {
                fn lookup(&self, id: &str) -> &str { id }
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "lookup").arity == 1

    def test_a_method_is_owned_by_its_impl_blocks_type(self, tmp_path):
        root = workspace(tmp_path, {"a.rs": """
            struct UserService;
            impl UserService {
                fn find(&self, id: &str) -> String { id.to_string() }
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_a_trait_impl_registers_the_supertype(self, tmp_path):
        root = workspace(tmp_path, {"a.rs": """
            trait Greeter {
                fn greet(&self) -> String;
            }
            struct UserService;
            impl Greeter for UserService {
                fn greet(&self) -> String { "hi".to_string() }
            }
        """})
        idx = index_workspace(root)

        assert idx.supertypes["UserService"] == ("Greeter",)

    def test_trait_impls_from_separate_blocks_all_accumulate(self, tmp_path):
        """Unlike a Java class, which states every supertype in one
        declaration, a Rust type gains each trait from its own separate
        `impl Trait for Type` block -- the second block must not overwrite
        the first."""
        root = workspace(tmp_path, {"a.rs": """
            struct UserService;
            impl Greeter for UserService {
                fn greet(&self) -> String { "hi".to_string() }
            }
            impl Debuggable for UserService {
                fn describe(&self) -> String { "user".to_string() }
            }
        """})
        idx = index_workspace(root)

        assert set(idx.supertypes["UserService"]) == {"Greeter", "Debuggable"}


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "main.rs": """
                #[get("/users/{id}")]
                async fn get_user(path: web::Path<String>) -> HttpResponse {
                    let id = path.into_inner();
                    let result = find_user(&id);
                    HttpResponse::Ok().body(result)
                }
            """,
            "db.rs": """
                fn find_user(username: &str) -> String {
                    format!("SELECT * FROM users WHERE username = '{}'", username)
                }
            """,
        })
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "find_user")
        chains = trace_to_entry_points(idx, "db.rs", find_user.start_line)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET /users/{id}"

    def test_a_function_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.rs": "fn orphan(x: i32) {}"})
        idx = index_workspace(root)
        orphan = next(m for m in idx.methods if m.name == "orphan")

        assert trace_to_entry_points(idx, "a.rs", orphan.start_line) == []


class TestSelfCalls:
    def test_calling_through_self_stays_inside_the_type(self, tmp_path):
        root = workspace(tmp_path, {"a.rs": """
            struct Consumer;
            impl Consumer {
                fn start(&self) {
                    self.run();
                }
                fn run(&self) {}
            }
            struct Unrelated;
            impl Unrelated {
                fn run(&self) {}
            }
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["start"]

    def test_a_call_through_a_field_is_not_treated_as_a_self_call(self, tmp_path):
        root = workspace(tmp_path, {"a.rs": """
            struct Handler {
                svc: Service,
            }
            impl Handler {
                fn get_user(&self, id: &str) -> String {
                    self.svc.lookup(id)
                }
            }
        """})
        idx = index_workspace(root)
        lookup_call = next(c for c in idx.calls if c.callee == "lookup")

        assert lookup_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_java_python_js_go_cpp_and_rust_index_into_one_shared_graph(self, tmp_path):
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
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 5

    def test_a_java_only_repo_pays_nothing_for_the_empty_rust_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
