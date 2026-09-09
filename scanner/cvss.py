"""CVSS v3.1 base scores for findings, keyed by CWE.

Neither Semgrep nor the vendored rules carry a CVSS score -- the engine
emits ERROR/WARNING/INFO and the rule metadata adds LOW/MEDIUM/HIGH for
impact and likelihood. So the score has to come from somewhere, and here it
comes from the weakness class: each CWE this ruleset can report is mapped to
a base vector that is typical for that class in a server-side Java web
application, and the score is computed from the vector by the published
formula rather than written down.

Storing vectors instead of numbers is the point: a number in a table cannot
be argued with, while `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` states exactly
what is being claimed and can be corrected metric by metric. What this
cannot be is per-finding truth -- every SQL injection scores 9.8 here,
because the table describes the class, not the instance.
"""
from scanner.core import cwe_ids

# CVSS v3.1 specification, section 7.4 (metric values).
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Section 5, qualitative severity rating scale. Ordered high to low so the
# first match wins.
BANDS = (("critical", 9.0), ("high", 7.0), ("medium", 4.0), ("low", 0.1))

# One vector per weakness class. Rationale for the recurring shapes:
# an unauthenticated remote injection that yields code or data execution is
# the 9.8 shape (AV:N/AC:L/PR:N/UI:N, C/I/A all High); a read-only
# disclosure is 7.5 (C:H alone); anything that needs the victim to click is
# UI:R with scope change, the 6.1 shape XSS is scored at; and the crypto
# weaknesses take AC:H because exploiting them needs a position on the
# network or many samples, which is what drops them to 5.9.
CWE_VECTORS = {
    "CWE-22": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-23": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-78": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-79": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-89": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-90": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-93": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-94": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-95": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-113": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-116": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-150": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-183": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "CWE-200": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-269": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CWE-276": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CWE-287": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-295": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-297": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-319": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-323": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-326": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-327": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-328": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-329": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-330": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-345": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "CWE-352": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "CWE-454": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "CWE-470": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-501": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "CWE-502": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-601": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-611": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "CWE-614": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-643": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-704": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "CWE-798": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-918": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-943": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-1004": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-1333": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
}

# What an unmapped CWE scores. Deliberately the 7.5 read-only shape rather
# than the 9.8 one: an unknown weakness reaching a sink is worth a look, but
# guessing "critical" for something nobody has classified would put it above
# confirmed injections in the report's own ordering.
DEFAULT_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def parse_vector(vector: str) -> dict[str, str]:
    """The metric part of a base vector. A `CVSS:3.1/` prefix is accepted
    but not required, since the table stores the metrics alone."""
    metrics = {}
    for part in vector.split("/"):
        if part.startswith("CVSS:"):
            continue
        key, _, value = part.partition(":")
        metrics[key] = value
    return metrics


def roundup(value: float) -> float:
    """CVSS v3.1 Appendix A: the smallest number, to one decimal, that is
    not smaller than the input. Done in integer arithmetic because the
    obvious `math.ceil(value * 10) / 10` gets 4.02 - 0.1 wrong on binary
    floats and the spec calls that failure out by name."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (integer // 10000 + 1) / 10.0


def base_score(vector: str) -> float:
    """CVSS v3.1 base score, section 7.1."""
    m = parse_vector(vector)
    scope_changed = m.get("S") == "C"

    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    privileges = PR_CHANGED if scope_changed else PR_UNCHANGED
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * privileges[m["PR"]] * UI[m["UI"]]

    combined = impact + exploitability
    return roundup(min(combined * 1.08, 10.0) if scope_changed else min(combined, 10.0))


def band(score: float) -> str:
    for name, floor in BANDS:
        if score >= floor:
            return name
    return "none"


def vector_for(item: dict) -> str:
    """The finding's vector: the worst of its CWEs, since a rule tagged with
    several is reporting one weakness that can be classified more than one
    way, not several weaknesses that each need their own score."""
    vectors = [CWE_VECTORS[cwe] for cwe in cwe_ids(item) if cwe in CWE_VECTORS]
    if not vectors:
        return DEFAULT_VECTOR
    return max(vectors, key=base_score)


def score_for(item: dict) -> float:
    return base_score(vector_for(item))
