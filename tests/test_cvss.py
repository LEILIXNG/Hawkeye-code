"""CVSS v3.1 scoring and the CWE table it is keyed by."""
from pathlib import Path

import pytest

from scanner import cvss


# Vectors whose scores are published in the CVSS v3.1 examples and on NVD,
# so these pin the formula against an outside source rather than against
# whatever this implementation happens to produce.
REFERENCE = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
    ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.5),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
]


@pytest.mark.parametrize("vector,expected", REFERENCE)
def test_base_score_matches_the_published_value(vector, expected):
    assert cvss.base_score(vector) == expected


def test_a_prefixed_vector_scores_the_same():
    bare = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    assert cvss.base_score("CVSS:3.1/" + bare) == cvss.base_score(bare)


def test_no_impact_scores_zero():
    assert cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_roundup_does_not_trust_binary_floats():
    """The spec calls this failure out by name: the obvious ceil(x*10)/10
    gets 4.02 - 0.1 wrong, because that is 3.9199999999999995 in binary."""
    assert cvss.roundup(4.02 - 0.1) == 4.0
    assert cvss.roundup(0.1 + 0.2) == 0.3
    assert cvss.roundup(6.0) == 6.0
    assert cvss.roundup(6.01) == 6.1


@pytest.mark.parametrize("score,expected", [
    (10.0, "critical"), (9.0, "critical"),
    (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"),
    (3.9, "low"), (0.1, "low"),
    (0.0, "none"),
])
def test_bands_follow_the_qualitative_scale(score, expected):
    assert cvss.band(score) == expected


def test_every_table_vector_parses_and_scores():
    for cwe, vector in cvss.CWE_VECTORS.items():
        score = cvss.base_score(vector)
        assert 0.1 <= score <= 10.0, f"{cwe} scored {score}"


def test_the_table_covers_what_the_ruleset_reports():
    """Not exhaustive coverage of CWE, but of the classes these rules can
    actually emit -- a miss here silently becomes the default 7.5."""
    expected = {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-611", "CWE-327",
                # Both were found taking the default silently on real
                # reports, which is what a missing entry looks like.
                "CWE-23", "CWE-918"}

    assert expected <= set(cvss.CWE_VECTORS)


def test_an_unmapped_cwe_falls_back_without_guessing_critical():
    """A weakness nobody has classified should not outrank a confirmed
    injection in the report's own ordering."""
    score = cvss.base_score(cvss.DEFAULT_VECTOR)

    assert cvss.band(score) == "high"
    assert cvss.vector_for({"cwe": ["CWE-99999: Nothing known"]}) == cvss.DEFAULT_VECTOR


def test_a_finding_with_no_cwe_uses_the_default():
    assert cvss.vector_for({}) == cvss.DEFAULT_VECTOR
    assert cvss.vector_for({"cwe": None}) == cvss.DEFAULT_VECTOR


def test_several_cwes_take_the_worst():
    """A rule tagged with more than one is classifying one weakness several
    ways, not reporting several weaknesses."""
    item = {"cwe": ["CWE-327: Broken crypto", "CWE-89: SQL injection"]}

    assert cvss.score_for(item) == 9.8


def test_a_plain_string_cwe_is_accepted():
    """Older fixtures store it as a string rather than a list."""
    assert cvss.score_for({"cwe": "CWE-89: SQL injection"}) == 9.8


def test_risk_level_grades_the_band_by_reachability():
    """The two axes: CVSS says how bad the class is, the verifier says
    whether it is real."""
    from scanner.render import risk_level

    def item(cwe, verdict):
        return {"cwe": [cwe], "severity": "ERROR", "finding": {"reachable": verdict}}

    assert risk_level(item("CWE-89: SQL injection", "yes")) == "critical"
    assert risk_level(item("CWE-89: SQL injection", "uncertain")) == "high"
    assert risk_level(item("CWE-89: SQL injection", "no")) == "low"


def test_semgrep_severity_no_longer_decides_the_level():
    """The point of the change: ERROR cannot separate an unauthenticated
    SQL injection from a weak hash, and CVSS puts them four points apart."""
    from scanner.render import risk_level

    injection = {"cwe": ["CWE-89: SQL injection"], "severity": "ERROR", "finding": {"reachable": "yes"}}
    weak_hash = {"cwe": ["CWE-327: Broken crypto"], "severity": "ERROR", "finding": {"reachable": "yes"}}

    assert risk_level(injection) == "critical"
    assert risk_level(weak_hash) == "medium"


def test_a_low_band_finding_cannot_drop_below_the_floor():
    """Every band has a one-step-down entry, including the bottom ones --
    a KeyError here would take down the whole report."""
    from scanner.render import risk_level

    for cwe in cvss.CWE_VECTORS:
        assert risk_level({"cwe": [cwe], "finding": {"reachable": "uncertain"}}) in {"critical", "high", "medium", "low"}


def test_report_json_carries_the_score(tmp_path):
    """The web UI, the Markdown export and the database all read this file;
    a table re-implemented three times is three tables that drift."""
    import json

    from scanner.render import render

    item = {"rule_id": "r", "message": "m", "severity": "ERROR",
            "cwe": ["CWE-89: SQL injection"], "source_file": "A.java", "source_line": 1,
            "sink_file": "A.java", "sink_line": 2, "dedup_key": "k",
            "finding": {"reachable": "yes"}}

    out = render([item], "demo", tmp_path)
    finding = json.loads(Path(out["json_path"]).read_text(encoding="utf-8"))["findings"][0]

    assert finding["cvss_score"] == 9.8
    assert finding["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert finding["risk_level"] == "critical"
