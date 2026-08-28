"""Guards for rules/ruleset.yml and the hand-written rules under
rules/custom/.

None of this needs an LLM or a scan target -- it is all things that
currently only surface as a broken (or silently degraded) scan:

  - a typo'd path in ruleset.yml makes semgrep skip that whole config
    with a warning the pipeline does not treat as fatal;
  - a custom rule with malformed YAML is rejected by semgrep at scan time,
    not at edit time;
  - a custom rule missing metadata.cwe still fires, but render.py's
    vuln_type_label() falls back to "Uncategorized", so the finding is
    quietly unlabelled in the report instead of erroring.
"""
import shutil
import subprocess

import pytest
import yaml

from scanner.common import ROOT, RULESET_PATH, load_default_configs

CUSTOM_RULES_DIR = ROOT / "rules" / "custom"
REQUIRED_RULE_FIELDS = ("id", "languages", "severity", "message")


def custom_rule_files():
    return sorted(p for p in CUSTOM_RULES_DIR.rglob("*") if p.suffix in (".yml", ".yaml"))


def custom_rules():
    for path in custom_rule_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in doc.get("rules", []):
            yield path, rule


class TestRulesetFile:
    def test_configs_is_a_non_empty_list_of_strings(self):
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        configs = ruleset["configs"]
        assert isinstance(configs, list) and configs
        assert all(isinstance(c, str) and c for c in configs)

    def test_paths_are_repo_relative(self):
        """An absolute path here would work on whoever added it and break
        for everyone else."""
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        for entry in ruleset["configs"]:
            assert not entry.startswith(("/", "\\")) and ":" not in entry, entry
            assert ".." not in entry.split("/"), entry

    def test_every_config_path_exists(self):
        missing = [c for c in load_default_configs() if not (ROOT / c).exists()]
        assert not missing, (
            f"ruleset.yml points at paths that do not exist: {missing}. "
            "If these are under rules/vendor/, the submodule is probably not "
            "checked out -- run `git submodule update --init --recursive`."
        )


class TestCustomRules:
    def test_there_is_at_least_one_custom_rule(self):
        assert list(custom_rules()), "rules/custom is listed in ruleset.yml but holds no rules"

    def test_required_fields_are_present(self):
        for path, rule in custom_rules():
            for field in REQUIRED_RULE_FIELDS:
                assert rule.get(field), f"{path.name}: rule is missing `{field}`"

    def test_rule_ids_are_unique(self):
        seen = {}
        for path, rule in custom_rules():
            rule_id = rule["id"]
            assert rule_id not in seen, f"duplicate rule id `{rule_id}` in {path.name} and {seen[rule_id]}"
            seen[rule_id] = path.name

    def test_cwe_metadata_is_usable_by_the_renderer(self):
        """render.py derives the report's vulnerability-type label from this
        field, so a rule without it lands under "Uncategorized" silently."""
        for path, rule in custom_rules():
            cwe = (rule.get("metadata") or {}).get("cwe")
            assert isinstance(cwe, list) and cwe, f"{path.name}: `{rule['id']}` has no metadata.cwe list"
            for entry in cwe:
                assert entry.startswith("CWE-"), f"{path.name}: cwe entry does not start with CWE-: {entry!r}"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_semgrep_accepts_the_whole_ruleset():
    """Catches malformed custom rules, and vendored rules that the pinned
    semgrep version can no longer parse after a submodule bump."""
    cmd = ["semgrep", "scan", "--validate", "--metrics=off"]
    for config in load_default_configs():
        cmd += ["--config", config]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"semgrep rejected the ruleset:\n{proc.stdout}\n{proc.stderr}"
