"""Unit tests for the C# half of scanner/callgraph/ (csharp_syntax.py,
csharp_entrypoints.py, csharp_index.py).

Same discipline as tests/test_callgraph_rust.py and its siblings: every
case is real C# source parsed for real, no hand-built Index fixtures.
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
    def test_an_httpget_attribute_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class UsersController : ControllerBase {
                [HttpGet("{id}")]
                public string GetUser(string id) { return id; }
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "GetUser")

        assert method.entry_definitive
        assert method.entry_reason == "GET {id}"

    def test_a_generic_route_attribute_is_recognised(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class C {
                [Route("api/x")]
                public void M() {}
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "M").entry_reason == "ROUTE api/x"

    def test_a_named_attribute_argument_still_yields_the_path(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class C {
                [Route(template: "api/y")]
                public void M() {}
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "M").entry_reason == "ROUTE api/y"

    def test_an_unrelated_attribute_is_not_mistaken_for_a_route(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class C {
                [Obsolete]
                public void Helper() {}
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "Helper").is_entry_point


class TestConventionRoutedControllerActions:
    def test_a_public_method_on_controllerbase_is_definitive_with_no_attribute(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class UsersController : ControllerBase {
                public string Index() { return "ok"; }
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "Index")

        assert method.entry_definitive
        assert method.entry_reason == "convention-routed controller action"

    def test_a_private_method_on_a_controller_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class UsersController : ControllerBase {
                private string Helper() { return "x"; }
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "Helper").is_entry_point

    def test_a_public_method_on_an_unrelated_base_type_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class Repository : BaseRepository {
                public string Find(string id) { return id; }
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "Find").is_entry_point


class TestMinimalApiRegistration:
    def test_an_inline_lambda_handler_becomes_a_synthetic_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class Program {
                public static void Main() {
                    var app = WebApplication.Create();
                    app.MapGet("/ping", () => "ok");
                }
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_definitive
        assert handler.entry_reason == "GET /ping"

    def test_a_named_handler_reference_is_resolved(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class Program {
                public static void Main() {
                    var app = WebApplication.Create();
                    app.MapPost("/users", CreateUser);
                }
                static string CreateUser(string body) { return body; }
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "CreateUser")

        assert handler.entry_definitive and handler.entry_reason == "POST /users"

    def test_a_handler_declared_after_its_registration_still_resolves(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class Program {
                public static void Main() {
                    var app = WebApplication.Create();
                    app.MapPost("/users", CreateUser);
                }
                static string CreateUser(string body) { return body; }
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "CreateUser").entry_definitive

    def test_a_single_argument_call_is_not_a_route_registration(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class C {
                public void M() {
                    var value = cache.MapGet(key);
                }
            }
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestSignatureBasedEntryPoints:
    def test_an_httpcontext_parameter_is_a_weak_hint_not_proof(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class C {
                public void Middleware(HttpContext context) {}
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "Middleware")

        assert method.is_entry_point and not method.entry_definitive

    def test_a_plain_helper_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class C {
                public int Add(int a, int b) { return a + b; }
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "Add").is_entry_point


class TestArityAndOwnership:
    def test_a_plain_method_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": "public class C { public int Add(int a, int b) { return a + b; } }"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "Add").arity == 2

    def test_an_interface_method_signature_is_not_indexed(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public interface IGreeter {
                string Greet();
            }
        """})
        idx = index_workspace(root)

        assert idx.methods == []

    def test_a_base_list_mixing_a_class_and_interfaces_is_all_one_supertypes_tuple(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class Base {}
            public interface IFoo {}
            public class Derived : Base, IFoo {
                public void M() {}
            }
        """})
        idx = index_workspace(root)

        assert set(idx.supertypes["Derived"]) == {"Base", "IFoo"}

    def test_partial_class_declarations_accumulate_supertypes(self, tmp_path):
        """Unlike Java, where one class declaration states every supertype
        at once, a `partial class` can list different interfaces in each of
        its declared parts -- the second file's declaration must not
        overwrite the first's."""
        root = workspace(tmp_path, {
            "A.cs": "public partial class Widget : IFoo {}",
            "B.cs": "public partial class Widget : IBar {}",
        })
        idx = index_workspace(root)

        assert set(idx.supertypes["Widget"]) == {"IFoo", "IBar"}


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "C.cs": """
                public class UsersController : ControllerBase {
                    [HttpGet("{id}")]
                    public string GetUser(string id) { return Db.FindUser(id); }
                }
            """,
            "Db.cs": """
                public static class Db {
                    public static string FindUser(string username) {
                        return "SELECT * FROM Users WHERE username = '" + username + "'";
                    }
                }
            """,
        })
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "FindUser")
        chains = trace_to_entry_points(idx, "Db.cs", find_user.start_line)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET {id}"

    def test_a_method_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": "public class C { public void Orphan() {} }"})
        idx = index_workspace(root)
        orphan = next(m for m in idx.methods if m.name == "Orphan")

        assert trace_to_entry_points(idx, "C.cs", orphan.start_line) == []


class TestSelfCalls:
    def test_calling_through_this_stays_inside_the_type(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class Consumer {
                public void Start() { this.Run(); }
                public void Run() {}
            }
            public class Unrelated {
                public void Run() {}
            }
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "Run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["Start"]

    def test_a_call_through_a_field_is_not_treated_as_a_self_call(self, tmp_path):
        root = workspace(tmp_path, {"C.cs": """
            public class Handler {
                public string GetUser(string id) { return this.svc.Lookup(id); }
            }
        """})
        idx = index_workspace(root)
        lookup_call = next(c for c in idx.calls if c.callee == "Lookup")

        assert lookup_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_java_python_js_go_rust_and_csharp_index_into_one_shared_graph(self, tmp_path):
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
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 6

    def test_a_java_only_repo_pays_nothing_for_the_empty_csharp_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
