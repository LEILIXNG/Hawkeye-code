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
    quietly unlabelled in the report instead of erroring;
  - an exclude_paths glob that matches nothing (see the anchoring trap in
    ruleset.yml) excludes nothing, and a scan that got noisier is not a
    failure anyone notices.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from scanner.common import (
    ROOT,
    RULESET_PATH,
    load_default_configs,
    load_excluded_paths,
    load_excluded_rules,
)

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

    def test_exclude_rules_is_a_list_of_strings(self):
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        excluded = ruleset.get("exclude_rules") or []
        assert isinstance(excluded, list)
        assert all(isinstance(r, str) and r.strip() for r in excluded)
        assert len(set(excluded)) == len(excluded), "duplicate ids in exclude_rules"

    def test_excluded_rules_are_loaded_verbatim(self):
        """`--exclude-rule` matches on the exact id, so anything that looks
        like a path or a glob here would silently exclude nothing."""
        for rule_id in load_excluded_rules():
            assert "/" not in rule_id and "*" not in rule_id, rule_id

    def test_exclude_paths_is_a_list_of_strings(self):
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        excluded = ruleset.get("exclude_paths") or []
        assert isinstance(excluded, list)
        assert all(isinstance(g, str) and g.strip() for g in excluded)
        assert len(set(excluded)) == len(excluded), "duplicate globs in exclude_paths"

    def test_multi_segment_globs_are_unanchored(self):
        """semgrep anchors an --exclude pattern containing a slash to the
        scan root, so a bare `src/it` matches the top-level one and silently
        misses moduleA/src/it. Those have to be written as `**/src/it`."""
        for glob in load_excluded_paths():
            if "/" in glob:
                assert glob.startswith("**/"), (
                    f"{glob!r} contains a slash, so it only matches at the scan root. "
                    "Write it as `**/" + glob.lstrip("/") + "` to match at any depth."
                )

    def test_exclude_paths_are_relative_globs(self):
        """An absolute path, or one climbing out of the target, cannot match
        anything inside an uploaded workspace."""
        for glob in load_excluded_paths():
            assert not glob.startswith(("/", "\\")) and ":" not in glob, glob
            assert ".." not in glob.split("/"), glob

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


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_exclude_paths_actually_keep_files_out_of_the_scan(tmp_path):
    """The failure this catches is silent: a glob that matches nothing still
    scans clean, just with the noise it was meant to remove. So rather than
    re-asserting the strings, plant one file per configured glob and check
    semgrep's own list of scanned paths.

    Each glob is exercised both at the top level and one directory down,
    because that is exactly where the anchoring trap shows up.
    """
    def plant(rel: str):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class V {}\n", encoding="utf-8")

    plant("src/main/java/Kept.java")  # control: must survive every exclusion
    expected_excluded = set()
    for glob in load_excluded_paths():
        stem = glob.removeprefix("**/")
        if stem.startswith("*."):  # file glob, e.g. *.min.js
            paths = [f"a{stem[1:]}", f"moduleA/b{stem[1:]}"]
        else:
            paths = [f"{stem}/V.java", f"moduleA/{stem}/V.java"]
        for rel in paths:
            plant(rel)
            expected_excluded.add(rel)

    cmd = ["semgrep", "--json", "--metrics=off", "--no-git-ignore",
           "--config", str(ROOT / "rules" / "custom")]
    for glob in load_excluded_paths():
        cmd += ["--exclude", glob]
    cmd.append(str(tmp_path))

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), f"semgrep failed:\n{proc.stderr}"

    scanned = {
        str(Path(p).resolve().relative_to(tmp_path.resolve())).replace("\\", "/")
        for p in json.loads(proc.stdout).get("paths", {}).get("scanned", [])
    }
    assert "src/main/java/Kept.java" in scanned, (
        "the exclusions swallowed ordinary source code: " + repr(sorted(scanned))
    )
    leaked = sorted(expected_excluded & scanned)
    assert not leaked, f"exclude_paths did not keep these out of the scan: {leaked}"


def test_every_custom_rule_file_has_an_annotated_fixture():
    """A custom rule with no fixture is a rule nothing checks. Kept separate
    from the semgrep-backed test below so the gap is reported even on a
    machine without semgrep installed."""
    for path in custom_rule_files():
        fixture = path.with_suffix(".java")
        assert fixture.exists(), (
            f"{path.name} has no {fixture.name} next to it -- every rule under "
            "rules/custom/ needs an annotated fixture (see the vendored rules "
            "for the // ruleid: / // ok: convention)"
        )


def test_every_custom_rule_is_exercised_by_its_fixture():
    """`semgrep --test` reports a rule with zero annotations as passing, so a
    rule can be added to an existing file and be covered by nothing."""
    for path, rule in custom_rules():
        fixture = path.with_suffix(".java").read_text(encoding="utf-8")
        assert f"ruleid: {rule['id']}" in fixture, (
            f"{path.with_suffix('.java').name} has no `// ruleid: {rule['id']}` case"
        )
        assert f"ok: {rule['id']}" in fixture, (
            f"{path.with_suffix('.java').name} has no `// ok: {rule['id']}` case -- "
            "a rule with only positive cases cannot catch over-matching"
        )


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_custom_rules_match_their_fixtures():
    """The regression net for rules/custom/. Widening a pattern until it
    swallows a hardened shape, or narrowing one until it drops the shape the
    rule exists for, both look like a clean scan otherwise."""
    for path in custom_rule_files():
        proc = subprocess.run(
            ["semgrep", "--test", "--metrics=off",
             "--config", str(path), str(path.with_suffix(".java"))],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0 and "did not pass" not in proc.stdout, (
            f"{path.name} does not match its fixture:\n{proc.stdout}\n{proc.stderr}"
        )


def pinned_semgrep_version():
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line.startswith("semgrep=="):
            return line.removeprefix("semgrep==")
    raise AssertionError("requirements.txt no longer pins semgrep to an exact version")


def test_semgrep_is_pinned_to_an_exact_version():
    """Standing decision: the engine stays on one version and detection
    improves through rules/custom/ instead. A floating `semgrep>=x` would let
    a fresh install pick up a release whose matching, constant propagation or
    taint behaviour differs, moving findings with no change to this repo."""
    version = pinned_semgrep_version()
    assert version.count(".") == 2 and all(p.isdigit() for p in version.split(".")), version


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_installed_semgrep_matches_the_pin():
    """Pinning requirements.txt does nothing for a machine that already had a
    different semgrep on PATH, which is the case that silently shifts results:
    every number in eval/labels.json was measured against the pinned engine."""
    proc = subprocess.run(["semgrep", "--version"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    # The CLI prints an upgrade notice on its own line before the version.
    reported = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()][-1]
    expected = pinned_semgrep_version()
    assert reported == expected, (
        f"semgrep on PATH is {reported}, requirements.txt pins {expected}. "
        "The engine is deliberately frozen -- reinstall the pinned version "
        "rather than re-baselining, unless the pin was changed on purpose."
    )
