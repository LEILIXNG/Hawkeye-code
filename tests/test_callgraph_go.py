"""Unit tests for the Go half of scanner/callgraph/ (go_syntax.py,
go_entrypoints.py, go_index.py).

Same discipline as tests/test_callgraph.py, test_callgraph_python.py and
test_callgraph_js.py: every case is real Go source parsed for real, no
hand-built Index fixtures. index_workspace() is the shared entry point for
all four languages, so these tests call the same function the others do.
"""
from pathlib import Path

from scanner.callgraph import ANY_ARITY, callers_of, index_workspace, trace_to_entry_points


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


class TestRouteRegistrationEntryPoints:
    def test_an_inline_func_literal_handler_becomes_a_synthetic_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func setup() {
                http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
                    w.Write([]byte("ok"))
                })
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_definitive
        assert handler.entry_reason == "HANDLEFUNC /ping"

    def test_gin_style_uppercase_verb_is_recognised(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func setup() {
                router.GET("/ping", func(c *gin.Context) {
                    c.JSON(200, nil)
                })
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.entry_reason).entry_reason == "GET /ping"

    def test_chi_style_capitalised_verb_is_recognised(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func setup() {
                r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {})
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.entry_reason).entry_reason == "GET /ping"

    def test_a_named_handler_reference_is_resolved_in_the_second_pass(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func listUsers(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte("ok"))
            }

            func setup() {
                http.HandleFunc("/users", listUsers)
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "listUsers")

        assert handler.entry_definitive and handler.entry_reason == "HANDLEFUNC /users"

    def test_a_handler_declared_after_its_registration_still_resolves(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func setup() {
                http.HandleFunc("/users", listUsers)
            }

            func listUsers(w http.ResponseWriter, r *http.Request) {}
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "listUsers").entry_definitive

    def test_a_method_value_handler_is_resolved_by_bare_name(self, tmp_path):
        """`router.GET(path, h.GetUser)` -- a receiver instance's method
        passed by value, the one handler shape JS's own two forms
        (arrow/function-expression, named function reference) do not have.
        """
        root = workspace(tmp_path, {"main.go": """
            package main

            type UserHandler struct{}

            func (h *UserHandler) GetUser(c *gin.Context) {
                c.JSON(200, nil)
            }

            func setup() {
                h := &UserHandler{}
                router.GET("/users/:id", h.GetUser)
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "GetUser")

        assert handler.entry_definitive and handler.entry_reason == "GET /users/:id"

    def test_a_local_func_literal_variable_used_as_a_handler_resolves(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func setup() {
                handler := func(w http.ResponseWriter, r *http.Request) {
                    w.Write([]byte("ok"))
                }
                http.HandleFunc("/x", handler)
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "handler").entry_definitive

    def test_a_single_argument_call_is_not_a_route_registration(self, tmp_path):
        """A one-argument `.Handle(...)`/`.Get(...)` call on some unrelated
        type must not be mistaken for route registration -- the same guard
        JS's is_route_registration() applies for the same reason."""
        root = workspace(tmp_path, {"main.go": """
            package main

            func setup() {
                value := cache.Get("key")
            }
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)

    def test_a_middleware_chain_recognises_the_last_argument_as_the_handler(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func setup() {
                router.GET("/admin", authMiddleware, func(c *gin.Context) {
                    c.JSON(200, nil)
                })
            }
        """})
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 1 and entries[0].entry_reason == "GET /admin"


class TestSignatureBasedEntryPoints:
    def test_serve_http_with_the_handler_signature_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            type App struct{}

            func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte("ok"))
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "ServeHTTP")

        assert method.entry_definitive

    def test_serve_http_with_an_unrelated_signature_is_not_definitive(self, tmp_path):
        """The method name alone is not proof -- ServeHTTP is only
        meaningful paired with the http.Handler signature, the same
        name+signature pairing Java's SERVLET_ENTRY_METHODS applies with a
        supertype check instead (Go has no supertype to check)."""
        root = workspace(tmp_path, {"main.go": """
            package main

            type Thing struct{}

            func (t *Thing) ServeHTTP(x int, y int) int {
                return x + y
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "ServeHTTP")

        assert not method.is_entry_point

    def test_a_handler_shaped_parameter_is_a_weak_hint_not_proof(self, tmp_path):
        """Wired into a routing table this module does not recognise by
        call shape (a map literal, a third-party router) -- still worth
        surfacing, but as a hint, the same role Java's HttpServletRequest
        fallback and Python's Django `request`-parameter fallback play."""
        root = workspace(tmp_path, {"main.go": """
            package main

            func standaloneHandler(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte("ok"))
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "standaloneHandler")

        assert method.is_entry_point and not method.entry_definitive

    def test_a_plain_helper_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"main.go": """
            package main

            func add(a int, b int) int {
                return a + b
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "add").is_entry_point


class TestArity:
    def test_a_plain_function_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.go": """
            package main

            func add(a int, b int) int { return a + b }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_parameters_sharing_one_type_are_each_counted(self, tmp_path):
        """`a, b int` is one parameter_declaration node binding two names to
        one type -- arity 2, not 1."""
        root = workspace(tmp_path, {"a.go": """
            package main

            func add(a, b int) int { return a + b }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_a_variadic_parameter_matches_any_arity(self, tmp_path):
        root = workspace(tmp_path, {"a.go": """
            package main

            func run(items ...string) {}
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "run").arity == ANY_ARITY

    def test_a_method_receiver_is_not_counted_as_a_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.go": """
            package main

            func (s *Service) Lookup(id string) string { return id }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "Lookup").arity == 1


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "main.go": """
                package main

                func setup() {
                    http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
                        host := r.URL.Query().Get("host")
                        runPing(host)
                    })
                }
            """,
            "ping.go": """
                package main

                func runPing(host string) {
                    exec.Command("sh", "-c", "ping -c 1 "+host).Run()
                }
            """,
        })
        idx = index_workspace(root)
        chains = trace_to_entry_points(idx, "ping.go", 5)

        assert chains
        assert chains[0][-1].caller.entry_reason == "HANDLEFUNC /ping"

    def test_a_function_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.go": """
            package main

            func orphan(x int) {}
        """})
        idx = index_workspace(root)

        assert trace_to_entry_points(idx, "a.go", 2) == []

    def test_test_go_files_are_not_indexed(self, tmp_path):
        root = workspace(tmp_path, {"a_test.go": """
            package main

            func TestSomething(t *testing.T) {}
        """})
        idx = index_workspace(root)

        assert idx.methods == []


class TestSelfCalls:
    def test_calling_through_the_receivers_own_variable_stays_inside_the_type(self, tmp_path):
        """Go has no `this`/`self` keyword -- the receiver variable is
        author-named, here `h` -- so recognising `h.run()` as a self-call
        has to read that name off the receiver clause rather than check a
        fixed keyword."""
        root = workspace(tmp_path, {"a.go": """
            package main

            type Consumer struct{}

            func (h *Consumer) start() {
                h.run()
            }

            func (h *Consumer) run() {}

            type Unrelated struct{}

            func (u *Unrelated) run() {}
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["start"]

    def test_a_call_through_a_field_is_not_treated_as_a_self_call(self, tmp_path):
        """`h.svc.Lookup()` calls a method on a *different* value -- the
        receiver is `h.svc`, not `h` -- so it is ordinary name+arity
        matching, not hierarchy-restricted the way `h.x()` is."""
        root = workspace(tmp_path, {"a.go": """
            package main

            type Handler struct {
                svc *Service
            }

            func (h *Handler) GetUser(id string) string {
                return h.svc.Lookup(id)
            }
        """})
        idx = index_workspace(root)
        lookup_call = next(c for c in idx.calls if c.callee == "Lookup")

        assert lookup_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_java_python_js_and_go_index_into_one_shared_graph(self, tmp_path):
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
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 4

    def test_a_java_only_repo_pays_nothing_for_the_empty_go_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
