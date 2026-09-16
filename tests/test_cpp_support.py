import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.callgraph import callers_of, enclosing_method, index_workspace
from scanner.common import ROOT
from scanner.core import normalize
from scanner.languages import CPP_SUFFIXES, is_cpp_path
from scanner.pipeline import verify_all


CPP_RULES = ROOT / "rules" / "custom" / "cpp"


class TestCppClassification:
    @pytest.mark.parametrize("suffix", sorted(CPP_SUFFIXES))
    def test_declared_cpp_suffixes_are_supported(self, tmp_path, suffix):
        path = tmp_path / f"sample{suffix}"
        path.write_text("void run() {}\n", encoding="utf-8")
        assert is_cpp_path(path)

    def test_plain_c_header_is_not_cpp(self, tmp_path):
        path = tmp_path / "plain.h"
        path.write_text("/* class is documentation */\nint checksum(const char *p);\n", encoding="utf-8")
        assert not is_cpp_path(path)

    @pytest.mark.parametrize("signal", [
        "namespace demo { void run(); }",
        "class Handler {};",
        "template <typename T> T value();",
        "#include <string>\nstd::string value;",
    ])
    def test_cpp_header_is_selected_by_content(self, tmp_path, signal):
        path = tmp_path / "cpp_style.h"
        path.write_text(signal, encoding="utf-8")
        assert is_cpp_path(path)


class TestCppCallGraph:
    def test_cpp_functions_and_calls_enter_the_shared_index(self, tmp_path):
        (tmp_path / "service.cpp").write_text(
            "int sink(const char *q) { return system(q); }\n"
            "int handler(const char *q) { return sink(q); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        assert {m.name for m in index.methods} >= {"sink", "handler"}
        call = next(c for c in index.calls if c.callee == "sink")
        assert call.caller is not None and call.caller.name == "handler"

    def test_plain_c_header_does_not_enter_cpp_index(self, tmp_path):
        (tmp_path / "plain.h").write_text("int c_function(void) { return 1; }\n", encoding="utf-8")
        assert not index_workspace(tmp_path).methods

    def test_same_arity_overloads_are_resolved_by_argument_type(self, tmp_path):
        (tmp_path / "overloads.cpp").write_text(
            "void run(int value) {}\n"
            "void run(const char *value) {}\n"
            "void numbers() { run(7); }\n"
            "void text() { run(\"seven\"); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        integer = next(m for m in index.methods if m.name == "run" and "int" in m.parameter_types)
        string = next(m for m in index.methods if m.name == "run"
                      and any("char" in value for value in m.parameter_types))
        assert {call.caller.name for call in callers_of(index, integer)} == {"numbers"}
        assert {call.caller.name for call in callers_of(index, string)} == {"text"}

    def test_qualified_owner_does_not_bridge_same_named_methods(self, tmp_path):
        (tmp_path / "owners.cpp").write_text(
            "struct Alpha { static void run(int value) {} };\n"
            "struct Beta { static void run(int value) {} };\n"
            "void caller() { Alpha::run(1); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        alpha = next(m for m in index.methods if m.name == "run" and m.owner.name == "Alpha")
        beta = next(m for m in index.methods if m.name == "run" and m.owner.name == "Beta")
        assert {call.caller.name for call in callers_of(index, alpha)} == {"caller"}
        assert callers_of(index, beta) == []

    def test_simple_function_pointer_alias_resolves_to_its_target(self, tmp_path):
        (tmp_path / "callbacks.cpp").write_text(
            "void target(int value) {}\n"
            "void caller() { auto callback = target; callback(1); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        assert any(call.callee == "target" and call.caller.name == "caller"
                   for call in index.calls)

    def test_function_like_macro_is_not_a_call_graph_edge(self, tmp_path):
        (tmp_path / "macro.cpp").write_text(
            "#define target(value) ((value) + 1)\n"
            "void caller() { target(1); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        assert not any(call.callee == "target" for call in index.calls)

    def test_macro_from_a_local_include_is_not_a_call_graph_edge(self, tmp_path):
        (tmp_path / "helpers.hpp").write_text(
            "#define target(value) ((value) + 1)\n", encoding="utf-8"
        )
        (tmp_path / "main.cpp").write_text(
            '#include "helpers.hpp"\nvoid caller() { target(1); }\n',
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        assert not any(call.callee == "target" for call in index.calls)

    def test_template_instantiation_resolves_to_template_definition(self, tmp_path):
        (tmp_path / "template.cpp").write_text(
            "template<class T> void target(T value) {}\n"
            "void caller() { target<int>(1); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        target = next(method for method in index.methods if method.name == "target")
        assert {call.caller.name for call in callers_of(index, target)} == {"caller"}

    def test_function_pointer_parameter_links_the_concrete_callback(self, tmp_path):
        (tmp_path / "callbacks.cpp").write_text(
            "void target(int first, int second) {}\n"
            "void invoke(void (*callback)(int, int)) { callback(1, 2); }\n"
            "void caller() { invoke(target); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        target = next(method for method in index.methods if method.name == "target")
        assert {call.caller.name for call in callers_of(index, target)} == {"caller"}


class TestCppFrameworkEntries:
    def test_crow_named_handler_is_a_definitive_entry(self, tmp_path):
        (tmp_path / "crow.cpp").write_text(
            "void sink() {}\n"
            "void users() { sink(); }\n"
            "CROW_ROUTE(app, \"/users\").methods(crow::HTTPMethod::GET)(users);\n",
            encoding="utf-8",
        )
        method = next(m for m in index_workspace(tmp_path).methods if m.name == "users")
        assert method.entry_definitive and method.entry_reason == "Crow GET /users"

    def test_drogon_registration_resolves_an_out_of_class_definition(self, tmp_path):
        (tmp_path / "controller.hpp").write_text(
            "class UserController { public: void save(); };\n"
            "ADD_METHOD_TO(UserController::save, \"/users\", Post);\n",
            encoding="utf-8",
        )
        (tmp_path / "controller.cpp").write_text(
            "void UserController::save() { dangerous(); }\n",
            encoding="utf-8",
        )
        method = next(m for m in index_workspace(tmp_path).methods if m.name == "save")
        assert method.owner.name == "UserController"
        assert method.entry_definitive and method.entry_reason == "Drogon POST /users"

    def test_oat_endpoint_body_becomes_an_entry_method(self, tmp_path):
        (tmp_path / "controller.cpp").write_text(
            "ENDPOINT(\"GET\", \"/items\", getItems) { dangerous(); }\n",
            encoding="utf-8",
        )
        index = index_workspace(tmp_path)
        method = enclosing_method(index, "controller.cpp", 1)
        assert method is not None and method.entry_reason == "Oat++ GET /items"
        assert any(call.callee == "dangerous" and call.caller is method for call in index.calls)

    def test_grpc_server_method_signature_is_an_entry(self, tmp_path):
        (tmp_path / "service.cpp").write_text(
            "grpc::Status Fetch(grpc::ServerContext *ctx, const Request *request, "
            "Reply *reply) { dangerous(); }\n",
            encoding="utf-8",
        )
        method = next(m for m in index_workspace(tmp_path).methods if m.name == "Fetch")
        assert method.entry_definitive and method.entry_reason == "gRPC service method"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_all_cpp_extensions_execute_real_cpp_rules(tmp_path):
    for suffix in (".cpp", ".cc", ".cxx", ".hpp"):
        (tmp_path / f"sample{suffix}").write_text(
            "void run(const char *q) { system(q); }\n", encoding="utf-8"
        )
    proc = subprocess.run(
        ["semgrep", "--json", "--metrics=off", "--no-git-ignore",
         "--config", str(CPP_RULES / "CPP002-system-command.yml"), str(tmp_path)],
        capture_output=True,
    )
    assert proc.returncode in (0, 1), proc.stderr.decode("utf-8", errors="replace")
    results = json.loads(proc.stdout).get("results", [])
    assert {Path(item["path"]).suffix for item in results} == {".cpp", ".cc", ".cxx", ".hpp"}


def test_normalize_rejects_cpp_rule_in_plain_c_header(tmp_path):
    header = tmp_path / "plain.h"
    header.write_text("void f() { system(\"id\"); }\n", encoding="utf-8")
    raw = {"results": [{
        "check_id": "CPP002",
        "path": str(header),
        "start": {"line": 1, "col": 12, "offset": 11},
        "end": {"line": 1, "col": 24, "offset": 23},
        "extra": {"message": "system", "severity": "ERROR",
                  "metadata": {"hawkeye_language": "cpp", "cwe": ["CWE-78"]}},
    }]}
    assert normalize(raw, tmp_path) == []


def test_normalize_keeps_location_columns_and_exact_snippet(tmp_path):
    source = "void f() { system(\"id\"); }\n"
    path = tmp_path / "sample.cpp"
    path.write_text(source, encoding="utf-8")
    start = source.index("system")
    end = source.index(";", start)
    raw = {"results": [{
        "check_id": "CPP002",
        "path": str(path),
        "start": {"line": 1, "col": start + 1, "offset": start},
        "end": {"line": 1, "col": end + 1, "offset": end},
        "extra": {"message": "system", "severity": "ERROR",
                  "metadata": {"hawkeye_language": "cpp", "cwe": ["CWE-78"]}},
    }]}
    candidate = normalize(raw, tmp_path)[0]
    assert candidate["sink_column"] == start + 1
    assert candidate["code_snippet"] == 'system("id")'


def _normalized_cpp_match(tmp_path, source, snippet, validator, rule_id):
    path = tmp_path / "sample.cpp"
    path.write_text(source, encoding="utf-8", newline="")
    raw_bytes = path.read_bytes()
    start = raw_bytes.rindex(snippet.encode("utf-8"))
    end = start + len(snippet.encode("utf-8"))
    raw = {"results": [{
        "check_id": rule_id,
        "path": str(path),
        "start": {"line": source[:source.rindex(snippet)].count("\n") + 1,
                  "col": 1, "offset": start},
        "end": {"line": source[:source.rindex(snippet)].count("\n") + 1,
                "col": len(snippet) + 1, "offset": end},
        "extra": {
            "message": rule_id,
            "severity": "WARNING",
            "metadata": {
                "hawkeye_language": "cpp",
                "hawkeye_validator": validator,
                "hawkeye_verification": "static",
                "confidence": "HIGH",
                "hawkeye_remediation": "fix it",
                "cwe": ["CWE-000"],
            },
        },
    }]}
    return normalize(raw, tmp_path)


class TestCppRuleAnalysis:
    def test_memcpy_drops_a_proven_safe_copy_and_keeps_an_overflow(self, tmp_path):
        safe = "void f(char *src) { char dst[8]; memcpy(dst, src, 8); }\n"
        unsafe = "void f(char *src) { char dst[8]; memcpy(dst, src, 9); }\n"
        assert not _normalized_cpp_match(tmp_path, safe, "memcpy(dst, src, 8)",
                                         "memcpy-bounds", "CPP004")
        finding = _normalized_cpp_match(tmp_path, unsafe, "memcpy(dst, src, 9)",
                                        "memcpy-bounds", "CPP004")[0]
        assert finding["message"] == "memcpy length 9 exceeds destination capacity 8."
        assert finding["rule_confidence"] == "HIGH"
        assert finding["static_analysis"] == "definite-overflow"

    @pytest.mark.parametrize("source", [
        "void f() { int *raw = new int[4]; int *alias = raw; delete alias; }\n",
        "struct X { int *items; X(){ items = new int[4]; } ~X(){ delete items; } };\n",
        "int *make(){ return new int[4]; } void f(){ int *p = make(); delete p; }\n",
    ])
    def test_new_delete_tracks_alias_member_and_factory_return(self, tmp_path, source):
        assert _normalized_cpp_match(
            tmp_path, source, "delete " + ("alias" if "alias" in source else
                                           "items" if "items;" in source else "p"),
            "new-delete-mismatch", "CPP005",
        )

    def test_new_delete_follows_ownership_into_a_function_in_another_file(self, tmp_path):
        destroy = "void destroy(int *value) { delete value; }\n"
        (tmp_path / "destroy.cpp").write_text(destroy, encoding="utf-8", newline="")
        (tmp_path / "caller.cpp").write_text(
            "void caller() { int *items = new int[4]; destroy(items); }\n",
            encoding="utf-8",
        )
        assert _normalized_cpp_match(
            tmp_path, destroy, "delete value", "new-delete-mismatch", "CPP005"
        )

    def test_null_analysis_handles_null_and_reassignment(self, tmp_path):
        unsafe = "void f() { Item *item = NULL; *item; }\n"
        safe = "void f(Item *ready) { Item *item = nullptr; item = ready; *item; }\n"
        assert _normalized_cpp_match(tmp_path, unsafe, "*item",
                                     "null-dereference", "CPP006")
        assert not _normalized_cpp_match(tmp_path, safe, "*item",
                                         "null-dereference", "CPP006")

    def test_null_analysis_follows_alias_and_honours_terminating_guard(self, tmp_path):
        alias = "void f() { Item *item = nullptr; Item *alias = item; alias->run(); }\n"
        guarded = (
            "void f() { Item *item = nullptr; if (!item) { return; } item->run(); }\n"
        )
        assert _normalized_cpp_match(tmp_path, alias, "alias->run()",
                                     "null-dereference", "CPP006")
        assert not _normalized_cpp_match(tmp_path, guarded, "item->run()",
                                         "null-dereference", "CPP006")

    def test_hardcoded_secret_follows_a_constant_alias(self, tmp_path):
        source = (
            "void f() { const char *fallback = \"built-in\"; "
            "const char *api_key = fallback; }\n"
        )
        assert _normalized_cpp_match(tmp_path, source, "api_key = fallback;",
                                     "hardcoded-secret", "CPP007")

    @pytest.mark.parametrize(("snippet", "expected"), [
        ('chmod(path, 0666)', True),
        ('chmod(path, 0750)', False),
        ('fopen(\"/tmp/report.txt\", \"w\")', True),
        ('fopen(\"/var/lib/app/report.txt\", \"r\")', False),
    ])
    def test_file_operations_only_keep_proven_dangerous_combinations(
            self, tmp_path, snippet, expected):
        source = f"void f(const char *path) {{ {snippet}; }}\n"
        found = _normalized_cpp_match(
            tmp_path, source, snippet, "dangerous-file-operation", "CPP008"
        )
        assert bool(found) is expected


def test_static_cpp_finding_bypasses_request_reachability_llm():
    class Provider:
        def chat(self, *_args, **_kwargs):
            raise AssertionError("static findings must not call the LLM")

    candidate = {
        "verification_mode": "static",
        "rule_confidence": "HIGH",
        "rule_remediation": "use RAII",
        "message": "mismatched allocation",
    }
    verified = verify_all([candidate], None, None, "", Provider(), "unused")
    assert verified[0]["finding"] == {
        "reachable": "yes",
        "verdict_kind": "static",
        "sanitized": False,
        "confidence": 95,
        "reasoning": "Static rule confirmed: mismatched allocation",
        "exploit_scenario": "",
        "remediation": "use RAII",
    }
