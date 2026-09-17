"""Unit tests for the Ruby half of scanner/callgraph/ (ruby_syntax.py,
ruby_entrypoints.py, ruby_index.py).

Same discipline as tests/test_callgraph_php.py and its siblings: every
case is real Ruby source parsed for real, no hand-built Index fixtures.
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


class TestRouteVerbCallEntryPoints:
    def test_a_get_route_resolves_across_files(self, tmp_path):
        root = workspace(tmp_path, {
            "routes.rb": """
                get '/users/:id', to: 'users#show'
            """,
            "users_controller.rb": """
                class UsersController < ApplicationController
                  def show
                    'ok'
                  end
                end
            """,
        })
        idx = index_workspace(root)
        handler = next(m for m in idx.methods if m.name == "show")

        assert handler.entry_definitive and handler.entry_reason == "GET /users/:id"

    def test_a_route_with_no_hash_target_is_not_a_registration(self, tmp_path):
        root = workspace(tmp_path, {"routes.rb": """
            get '/health'
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)

    def test_a_route_to_an_unresolved_controller_creates_no_entry(self, tmp_path):
        root = workspace(tmp_path, {"routes.rb": """
            get '/x', to: 'missing#action'
        """})
        idx = index_workspace(root)

        assert not any(m.is_entry_point for m in idx.methods)


class TestResourcesMacroEntryPoints:
    def test_resources_expands_to_the_seven_restful_actions(self, tmp_path):
        root = workspace(tmp_path, {
            "routes.rb": "resources :posts",
            "posts_controller.rb": """
                class PostsController < ApplicationController
                  def index; end
                  def show; end
                  def new; end
                  def create; end
                  def edit; end
                  def update; end
                  def destroy; end
                end
            """,
        })
        idx = index_workspace(root)
        by_name = {m.name: m for m in idx.methods if m.file == "posts_controller.rb"}

        assert by_name["index"].entry_reason == "GET /posts"
        assert by_name["show"].entry_reason == "GET /posts/:id"
        assert by_name["new"].entry_reason == "GET /posts/new"
        assert by_name["create"].entry_reason == "POST /posts"
        assert by_name["edit"].entry_reason == "GET /posts/:id/edit"
        assert by_name["update"].entry_reason == "PATCH /posts/:id"
        assert by_name["destroy"].entry_reason == "DELETE /posts/:id"
        assert all(m.entry_definitive for m in by_name.values())

    def test_only_option_narrows_which_actions_are_proven(self, tmp_path):
        """`destroy` is left with only the convention-routing hint here
        (still is_entry_point, since any public controller method gets
        that fallback) -- `only:` narrows which actions resources() can
        *prove*, not this tool's overall entry-point guess for an
        unrelated public method. See ruby_entrypoints.py's own
        entry_reason() docstring for why that hint is never definitive."""
        root = workspace(tmp_path, {
            "routes.rb": "resources :posts, only: [:index, :show]",
            "posts_controller.rb": """
                class PostsController < ApplicationController
                  def index; end
                  def show; end
                  def destroy; end
                end
            """,
        })
        idx = index_workspace(root)
        by_name = {m.name: m for m in idx.methods if m.file == "posts_controller.rb"}

        assert by_name["index"].entry_definitive
        assert by_name["show"].entry_definitive
        assert not by_name["destroy"].entry_definitive

    def test_except_option_removes_actions_from_being_proven(self, tmp_path):
        root = workspace(tmp_path, {
            "routes.rb": "resources :posts, except: [:destroy]",
            "posts_controller.rb": """
                class PostsController < ApplicationController
                  def index; end
                  def destroy; end
                end
            """,
        })
        idx = index_workspace(root)
        by_name = {m.name: m for m in idx.methods if m.file == "posts_controller.rb"}

        assert by_name["index"].entry_definitive
        assert not by_name["destroy"].entry_definitive

    def test_camelization_matches_the_controller_class_name(self, tmp_path):
        root = workspace(tmp_path, {
            "routes.rb": "resources :blog_posts, only: [:index]",
            "blog_posts_controller.rb": """
                class BlogPostsController < ApplicationController
                  def index; end
                end
            """,
        })
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "index").entry_definitive


class TestConventionRoutedControllerActions:
    def test_a_public_method_on_application_controller_is_a_hint_not_proof(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class UsersController < ApplicationController
              def index
                'ok'
              end
            end
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "index")

        assert method.is_entry_point and not method.entry_definitive
        assert method.entry_reason == "convention-routed controller action"

    def test_a_private_method_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class UsersController < ApplicationController
              def index
                helper
              end

              private

              def helper
                'x'
              end
            end
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "helper").is_entry_point

    def test_a_method_after_a_later_public_call_is_public_again(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class UsersController < ApplicationController
              def index; end

              private

              def helper; end

              public

              def show; end
            end
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "show").is_entry_point
        assert not next(m for m in idx.methods if m.name == "helper").is_entry_point

    def test_a_public_method_on_an_unrelated_base_is_not_an_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class Repository < BaseRepository
              def find
                'x'
              end
            end
        """})
        idx = index_workspace(root)

        assert not next(m for m in idx.methods if m.name == "find").is_entry_point

    def test_action_controller_base_is_also_recognised(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class ApiController < ActionController::Base
              def index
                'ok'
              end
            end
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "index").is_entry_point


class TestArityAndOwnership:
    def test_a_plain_method_keeps_every_parameter(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": "def add(a, b) a + b end"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "add").arity == 2

    def test_keyword_and_splat_parameters_are_all_counted(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": "def f(a, b = 1, *rest, key:, opt: 2, **kw, &blk) end"})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "f").arity == 7

    def test_a_method_is_owned_by_its_class(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class UserService
              def find(id)
                id
              end
            end
        """})
        idx = index_workspace(root)

        assert next(m for m in idx.methods if m.name == "find").owner.name == "UserService"

    def test_reopened_classes_accumulate_supertypes(self, tmp_path):
        """Two separate `class Widget < X` reopenings across files must not
        let the second overwrite the first, the same trade Rust's trait
        impls and C#'s partial classes both made."""
        root = workspace(tmp_path, {
            "a.rb": "class Widget < Foo; end",
            "b.rb": "class Widget < Bar; end",
        })
        idx = index_workspace(root)

        assert set(idx.supertypes["Widget"]) == {"Foo", "Bar"}


class TestSingletonMethods:
    def test_a_def_self_method_is_indexed_under_its_class(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class CommandService
              def self.run(host)
                host
              end
            end
        """})
        idx = index_workspace(root)
        method = next(m for m in idx.methods if m.name == "run")

        assert method.owner.name == "CommandService" and method.arity == 1

    def test_a_call_to_a_singleton_method_still_resolves(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class UsersController < ApplicationController
              def index
                CommandService.run(params[:host])
              end
            end

            class CommandService
              def self.run(host)
                host
              end
            end
        """})
        idx = index_workspace(root)
        run_method = next(m for m in idx.methods if m.name == "run")

        assert [c.callee for c in idx.calls if c.callee == "run"]
        assert run_method.arity == 1


class TestCrossFileCalls:
    def test_a_sink_traces_back_through_a_helper_to_the_route(self, tmp_path):
        root = workspace(tmp_path, {
            "users_controller.rb": """
                class UsersController < ApplicationController
                  def show
                    find_user(params[:id])
                  end
                end
            """,
            "db.rb": """
                def find_user(username)
                  "SELECT * FROM users WHERE username = '" + username + "'"
                end
            """,
            "routes.rb": "get '/users/:id', to: 'users#show'",
        })
        idx = index_workspace(root)
        find_user = next(m for m in idx.methods if m.name == "find_user")
        chains = trace_to_entry_points(idx, "db.rb", find_user.start_line)

        assert chains
        assert chains[0][-1].caller.entry_reason == "GET /users/:id"

    def test_a_method_nothing_calls_has_no_entry_point(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": "def orphan(x) end"})
        idx = index_workspace(root)
        orphan = next(m for m in idx.methods if m.name == "orphan")

        assert trace_to_entry_points(idx, "a.rb", orphan.start_line) == []


class TestSelfCalls:
    def test_calling_through_self_stays_inside_the_type(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class Consumer
              def start
                self.run(1)
              end

              def run(x)
              end
            end

            class Unrelated
              def run(x)
              end
            end
        """})
        idx = index_workspace(root)
        consumer_run = next(m for m in idx.methods if m.name == "run" and m.owner.name == "Consumer")

        assert [c.caller.name for c in callers_of(idx, consumer_run)] == ["start"]

    def test_a_call_through_a_field_is_not_treated_as_a_self_call(self, tmp_path):
        root = workspace(tmp_path, {"a.rb": """
            class Handler
              def get_user(id)
                @svc.lookup(id)
              end
            end
        """})
        idx = index_workspace(root)
        lookup_call = next(c for c in idx.calls if c.callee == "lookup")

        assert lookup_call.receiver_is_self is False


class TestMixedLanguageWorkspace:
    def test_all_nine_languages_index_into_one_shared_graph(self, tmp_path):
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
        })
        idx = index_workspace(root)
        entries = [m for m in idx.methods if m.is_entry_point]

        assert len(entries) == 8

    def test_a_java_only_repo_pays_nothing_for_the_empty_ruby_glob(self, tmp_path):
        root = workspace(tmp_path, {"A.java": "class A { void m() {} }"})
        idx = index_workspace(root)

        assert [m.name for m in idx.methods] == ["m"]
