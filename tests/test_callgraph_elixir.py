"""Unit tests for the Elixir half of scanner/callgraph/ (elixir_syntax.py,
elixir_entrypoints.py, elixir_index.py).

Same discipline as tests/test_callgraph_scala.py and its siblings: every
case is real Elixir source parsed for real, no hand-built Index fixtures.
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


class TestPhoenixVerbCallEntryPoints:
    def test_a_get_call_resolves_across_files(self, tmp_path):
        root = workspace(tmp_path, {
            "router.ex": """
                defmodule MyAppWeb.Router do
                  get "/users/:id", UserController, :show
                end
            """,
            "user_controller.ex": """
                defmodule UserController do
                  def show(conn, params) do
                    conn
                  end
                end
            """,
        })
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "show")

        assert handler.entry_definitive and handler.entry_reason == "GET /users/:id"

    def test_a_scope_block_prefixes_its_nested_verb_calls(self, tmp_path):
        root = workspace(tmp_path, {
            "router.ex": """
                defmodule MyAppWeb.Router do
                  scope "/api", MyAppWeb do
                    get "/ping", PingController, :index
                  end
                end
            """,
            "ping_controller.ex": """
                defmodule PingController do
                  def index(conn, _params) do
                    conn
                  end
                end
            """,
        })
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "index").entry_reason == "GET /api/ping"

    def test_nested_scope_blocks_accumulate_the_whole_prefix_chain(self, tmp_path):
        root = workspace(tmp_path, {
            "router.ex": """
                defmodule MyAppWeb.Router do
                  scope "/api" do
                    scope "/v1" do
                      get "/ping", PingController, :index
                    end
                  end
                end
            """,
            "ping_controller.ex": "defmodule PingController do\n  def index(conn, _p) do\n    conn\n  end\nend",
        })
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "index").entry_reason == "GET /api/v1/ping"

    def test_a_route_to_an_unresolved_controller_creates_no_entry(self, tmp_path):
        root = workspace(tmp_path, {"router.ex": """
            defmodule R do
              get "/x", Missing, :action
            end
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestPhoenixResourcesEntryPoints:
    def test_resources_expands_to_the_seven_restful_actions(self, tmp_path):
        root = workspace(tmp_path, {
            "router.ex": """
                defmodule R do
                  resources "/posts", PostController
                end
            """,
            "post_controller.ex": """
                defmodule PostController do
                  def index(conn, _p), do: conn
                  def new(conn, _p), do: conn
                  def create(conn, _p), do: conn
                  def show(conn, _p), do: conn
                  def edit(conn, _p), do: conn
                  def update(conn, _p), do: conn
                  def delete(conn, _p), do: conn
                end
            """,
        })
        idx = index_workspace(root)
        by_name = {m.name: m for m in idx.methods}

        assert by_name["index"].entry_reason == "GET /posts"
        assert by_name["new"].entry_reason == "GET /posts/new"
        assert by_name["create"].entry_reason == "POST /posts"
        assert by_name["show"].entry_reason == "GET /posts/:id"
        assert by_name["edit"].entry_reason == "GET /posts/:id/edit"
        assert by_name["update"].entry_reason == "PATCH /posts/:id"
        assert by_name["delete"].entry_reason == "DELETE /posts/:id"
        assert all(m.entry_definitive for m in by_name.values())

    def test_only_option_narrows_the_expanded_actions(self, tmp_path):
        root = workspace(tmp_path, {
            "router.ex": """
                defmodule R do
                  resources "/posts", PostController, only: [:index, :show]
                end
            """,
            "post_controller.ex": """
                defmodule PostController do
                  def index(conn, _p), do: conn
                  def show(conn, _p), do: conn
                  def delete(conn, _p), do: conn
                end
            """,
        })
        idx = index_workspace(root)
        by_name = {m.name: m for m in idx.methods}

        assert by_name["index"].is_entry_point
        assert by_name["show"].is_entry_point
        assert not by_name["delete"].is_entry_point

    def test_except_option_removes_actions(self, tmp_path):
        root = workspace(tmp_path, {
            "router.ex": """
                defmodule R do
                  resources "/posts", PostController, except: [:delete]
                end
            """,
            "post_controller.ex": """
                defmodule PostController do
                  def index(conn, _p), do: conn
                  def delete(conn, _p), do: conn
                end
            """,
        })
        idx = index_workspace(root)
        by_name = {m.name: m for m in idx.methods}

        assert by_name["index"].is_entry_point
        assert not by_name["delete"].is_entry_point


class TestArityAndOwnership:
    def test_a_plain_function_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.ex": "defmodule M do\n  def add(a, b), do: a + b\nend"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_a_zero_arity_function_with_no_parens_is_arity_zero(self, tmp_path):
        root = workspace(tmp_path, {"a.ex": "defmodule M do\n  def run do\n    :ok\n  end\nend"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "run").arity == 0

    def test_a_method_is_owned_by_its_module(self, tmp_path):
        root = workspace(tmp_path, {"a.ex": """
            defmodule UserService do
              def find(id) do
                id
              end
            end
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_a_qualified_module_name_is_shortened(self, tmp_path):
        root = workspace(tmp_path, {"a.ex": """
            defmodule MyApp.Services.UserService do
              def find(id) do
                id
              end
            end
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_each_guard_clause_is_indexed_as_its_own_method(self, tmp_path):
        root = workspace(tmp_path, {"a.ex": """
            defmodule Guarded do
              def classify(x) when x > 0 do
                :positive
              end

              def classify(x) when x <= 0 do
                :nonpositive
              end
            end
        """})
        idx = index_workspace(root)
        clauses = [m for m in idx.methods if m.name == "classify"]

        assert len(clauses) == 2
        assert all(m.arity == 1 for m in clauses)


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "router.ex": """
                defmodule R do
                  get "/users/:id", UserController, :show
                end
            """,
            "user_controller.ex": """
                defmodule UserController do
                  def show(conn, params) do
                    find_user(params["id"])
                  end
                end
            """,
            "db.ex": """
                defmodule Db do
                  def find_user(username) do
                    "SELECT * FROM users WHERE username = '" <> username <> "'"
                  end
                end
            """,
        })
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "find_user")
        chains = trace_to_entry_points(idx, "db.ex", find_user.start_line)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET /users/:id"

    def test_a_function_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.ex": "defmodule M do\n  def orphan(x) do\n    x\n  end\nend"})
        idx = index_workspace(root)
        orphan = next(m for m in idx.methods if m.name == "orphan")

        assert trace_to_entry_points(idx, "a.ex", orphan.start_line) == []

    def test_a_qualified_module_call_still_resolves_by_bare_name(self, tmp_path):
        """`Db.find_user(id)` reads its callee off the `dot` node's own
        `right` field (see elixir_syntax.py's own `_call_target_name()`),
        so it resolves by name+arity exactly like a bare call would."""
        root = workspace(tmp_path, {"a.ex": """
            defmodule Caller do
              def go(id) do
                Db.find_user(id)
              end
            end

            defmodule Db do
              def find_user(id) do
                id
              end
            end
        """})
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "find_user")

        assert [c.caller.name for c in callers_of(idx, find_user)] == ["go"]


class TestMixedLanguageWorkspace:
    def test_all_twelve_languages_index_into_one_shared_graph(self, tmp_path):
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
            "router.ex": """
                defmodule R do
                  get "/q", C, :handle
                end
            """,
            "c.ex": "defmodule C do\n  def handle(conn, _p) do\n    conn\n  end\nend",
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 11

    def test_a_java_only_repo_pays_nothing_for_the_empty_elixir_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
