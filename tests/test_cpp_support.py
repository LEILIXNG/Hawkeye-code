import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.callgraph import index_workspace
from scanner.common import ROOT
from scanner.core import normalize
from scanner.languages import CPP_SUFFIXES, is_cpp_path


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
