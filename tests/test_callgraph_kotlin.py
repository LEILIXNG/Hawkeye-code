"""Unit tests for the Kotlin half of scanner/callgraph/ (kotlin_syntax.py,
kotlin_entrypoints.py, kotlin_index.py).

Same discipline as tests/test_callgraph_ruby.py and its siblings: every
case is real Kotlin source parsed for real, no hand-built Index fixtures.
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


class TestSpringAnnotationEntryPoints:
    def test_a_get_mapping_with_a_path_is_definitive(self, tmp_path):
        root = workspace(tmp_path, {"C.kt": """
            class UserController {
                @GetMapping("/users/{id}")
                fun show(id: String): String {
                    return id
                }
            }
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "show")

        assert method.entry_definitive
        assert method.entry_reason == "GET /users/{id}"

    def test_a_generic_request_mapping_is_recognised(self, tmp_path):
        root = workspace(tmp_path, {"C.kt": """
            class C {
                @RequestMapping("/x")
                fun m() {}
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "m").entry_reason == "ROUTE /x"

    def test_an_unrelated_annotation_is_not_mistaken_for_a_route(self, tmp_path):
        root = workspace(tmp_path, {"C.kt": """
            class C {
                @Deprecated("old")
                fun helper() {}
            }
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "helper").is_entry_point

    def test_every_http_verb_mapping_is_recognised(self, tmp_path):
        root = workspace(tmp_path, {"C.kt": """
            class C {
                @PostMapping("/a")
                fun a() {}
                @PutMapping("/b")
                fun b() {}
                @DeleteMapping("/c")
                fun c() {}
                @PatchMapping("/d")
                fun d() {}
            }
        """})
        idx = index_workspace(root)
        by_name = {m.name: m.entry_reason for m in idx.methods}

        assert by_name["a"] == "POST /a"
        assert by_name["b"] == "PUT /b"
        assert by_name["c"] == "DELETE /c"
        assert by_name["d"] == "PATCH /d"


class TestKtorRouteEntryPoints:
    def test_a_plain_get_call_is_a_synthetic_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            fun main() {
                routing {
                    get("/ping") {
                        call.respondText("pong")
                    }
                }
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_definitive
        assert handler.entry_reason == "GET /ping"

    def test_a_route_block_prefixes_its_nested_verb_calls(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            fun main() {
                routing {
                    route("/api") {
                        get("/users") {
                            call.respondText("ok")
                        }
                    }
                }
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_reason == "GET /api/users"

    def test_nested_route_blocks_accumulate_the_whole_prefix_chain(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            fun main() {
                routing {
                    route("/api") {
                        route("/v1") {
                            get("/users") {
                                call.respondText("ok")
                            }
                        }
                    }
                }
            }
        """})
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.entry_reason)

        assert handler.entry_reason == "GET /api/v1/users"

    def test_sibling_verb_calls_in_one_route_block_each_get_their_own_entry(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            fun main() {
                routing {
                    route("/users") {
                        get("/") {
                            call.respondText("list")
                        }
                        post("/") {
                            call.respondText("create")
                        }
                    }
                }
            }
        """})
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.entry_reason]

        assert {m.entry_reason for m in entries} == {"GET /users/", "POST /users/"}

    def test_a_call_that_is_not_a_verb_is_not_mistaken_for_a_route(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            fun main() {
                routing {
                    logStartup("/not/a/route") {
                        println("noop")
                    }
                }
            }
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestArityAndOwnership:
    def test_a_plain_function_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": "fun add(a: Int, b: Int): Int { return a + b }"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_a_method_is_owned_by_its_class(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            class UserService {
                fun find(id: String): String {
                    return id
                }
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_the_delegation_specifier_list_carries_both_base_class_and_interfaces(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            open class Base
            interface IFoo
            class Derived : Base(), IFoo {
                fun m() {}
            }
        """})
        idx = index_workspace(root)

        assert set(idx.supertypes["Derived"]) == {"Base", "IFoo"}


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "UserController.kt": """
                class UserController {
                    @GetMapping("/users/{id}")
                    fun show(id: String): String {
                        return findUser(id)
                    }
                }
            """,
            "Db.kt": """
                fun findUser(username: String): String {
                    return "SELECT * FROM users WHERE username = '" + username + "'"
                }
            """,
        })
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "findUser")
        chains = trace_to_entry_points(idx, "Db.kt", find_user.start_line)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET /users/{id}"

    def test_a_function_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": "fun orphan(x: Int) {}"})
        idx = index_workspace(root)
        orphan = next(m for m in idx.methods if m.name == "orphan")

        assert trace_to_entry_points(idx, "a.kt", orphan.start_line) == []


class TestSelfCalls:
    def test_calling_through_this_stays_inside_the_type(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            class Consumer {
                fun start() {
                    this.run()
                }
                fun run() {}
            }
            class Unrelated {
                fun run() {}
            }
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["start"]

    def test_a_call_through_a_field_is_not_treated_as_a_self_call(self, tmp_path):
        root = workspace(tmp_path, {"a.kt": """
            class Handler {
                fun getUser(id: String): String {
                    return svc.lookup(id)
                }
            }
        """})
        idx = index_workspace(root)
        lookup_call = next(c for c in idx.calls if c.callee == "lookup")

        assert lookup_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_all_ten_languages_index_into_one_shared_graph(self, tmp_path):
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
            "a.rb": """
                class C < ApplicationController
                  def handle
                    'ok'
                  end
                end
            """,
            "a.kt": """
                class C {
                    @GetMapping("/s")
                    fun handle(): String { return "ok" }
                }
            """,
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 9

    def test_a_java_only_repo_pays_nothing_for_the_empty_kotlin_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
