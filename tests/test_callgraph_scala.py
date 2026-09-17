"""Unit tests for the Scala half of scanner/callgraph/ (scala_syntax.py,
scala_index.py, scala_routes.py).

Same discipline as tests/test_callgraph_kotlin.py and its siblings: every
case is real Scala source (and, for routing, a real Play `conf/routes`-
shaped text file) parsed for real, no hand-built Index fixtures.
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


class TestPlayRoutesEntryPoints:
    def test_a_route_resolves_across_files(self, tmp_path):
        root = workspace(tmp_path, {
            "conf/routes": "GET     /users/:id          controllers.UserController.show(id: String)\n",
            "app/controllers/UserController.scala": """
                package controllers
                class UserController {
                  def show(id: String): String = id
                }
            """,
        })
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "show")

        assert handler.entry_definitive and handler.entry_reason == "GET /users/:id"

    def test_a_comment_only_line_is_ignored(self, tmp_path):
        root = workspace(tmp_path, {"conf/routes": "# GET  /x  controllers.X.y\n"})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)

    def test_an_include_directive_is_not_mistaken_for_a_route(self, tmp_path):
        root = workspace(tmp_path, {
            "conf/routes": "->  /admin  admin.Routes\n",
            "admin/Routes.scala": "class Routes { def index(): String = \"x\" }",
        })
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)

    def test_a_secondary_routes_file_is_also_read(self, tmp_path):
        root = workspace(tmp_path, {
            "conf/admin.routes": "GET  /admin  controllers.AdminController.index()\n",
            "app/controllers/AdminController.scala": """
                package controllers
                class AdminController {
                  def index(): String = "ok"
                }
            """,
        })
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "index").entry_definitive

    def test_a_route_to_an_unresolved_controller_creates_no_entry(self, tmp_path):
        root = workspace(tmp_path, {"conf/routes": "GET  /x  controllers.Missing.action()\n"})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestArityAndOwnership:
    def test_a_plain_method_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": "def add(a: Int, b: Int): Int = a + b"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_a_method_is_owned_by_its_class(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": """
            class UserService {
              def find(id: String): String = id
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_a_method_can_be_owned_by_an_object_too(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": """
            object UserService {
              def find(id: String): String = id
            }
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_a_trait_abstract_method_signature_is_not_indexed(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": """
            trait Greeter {
              def greet(): String
            }
        """})
        idx = index_workspace(root)

        assert idx.methods == []

    def test_extends_and_with_mixins_are_all_recorded_as_supertypes(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": """
            class Base
            trait Greeter
            trait Loggable
            class Derived extends Base with Greeter with Loggable {
              def m(): Unit = {}
            }
        """})
        idx = index_workspace(root)

        assert set(idx.supertypes["Derived"]) == {"Base", "Greeter", "Loggable"}


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "conf/routes": "GET  /users/:id  controllers.UserController.show(id: String)\n",
            "app/controllers/UserController.scala": """
                package controllers
                class UserController {
                  def show(id: String): String = {
                    findUser(id)
                  }
                }
            """,
            "app/db/Db.scala": """
                package db
                object Db {
                  def findUser(username: String): String = {
                    "SELECT * FROM users WHERE username = '" + username + "'"
                  }
                }
            """,
        })
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "findUser")
        chains = trace_to_entry_points(idx, "app/db/Db.scala", find_user.start_line)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET /users/:id"

    def test_a_method_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": "def orphan(x: Int): Unit = {}"})
        idx = index_workspace(root)
        orphan = next(m for m in idx.methods if m.name == "orphan")

        assert trace_to_entry_points(idx, "a.scala", orphan.start_line) == []


class TestSelfCalls:
    def test_calling_through_this_stays_inside_the_type(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": """
            class Consumer {
              def start(): Unit = {
                this.run()
              }
              def run(): Unit = {}
            }
            class Unrelated {
              def run(): Unit = {}
            }
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["start"]

    def test_a_call_through_a_field_is_not_treated_as_a_self_call(self, tmp_path):
        root = workspace(tmp_path, {"a.scala": """
            class Handler {
              def getUser(id: String): String = {
                svc.lookup(id)
              }
            }
        """})
        idx = index_workspace(root)
        lookup_call = next(c for c in idx.calls if c.callee == "lookup")

        assert lookup_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_all_eleven_languages_index_into_one_shared_graph(self, tmp_path):
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
            "conf/routes": "GET  /r  controllers.C.handle()\n",
            "controllers/C.scala": """
                package controllers
                class C {
                  def handle(): String = "ok"
                }
            """,
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 10

    def test_a_java_only_repo_pays_nothing_for_the_empty_scala_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
