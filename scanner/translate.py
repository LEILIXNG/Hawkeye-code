"""F: fill in the other language for a finding's free-text fields.

The report page has had a zh/en toggle since 2026-08-28, but it only ever
swapped the static labels. The three fields the reader actually reads --
reasoning, exploit_scenario, remediation -- come back in whatever language
the model felt like: of the 92 findings that carried any free text, 66 came
back in English and 26 in Chinese, so the toggle was inert for whichever
side the reader was on.

This is a separate stage rather than two more fields on prompts/verify_taint.md
on purpose. Touching the verify prompt invalidates every entry in
data/llm_cache/ and forces a full re-verify plus an eval re-run, at a ~16%
run-to-run flip rate that re-rolls verdicts that had nothing to do with the
change (see MEMORY.md). Translation is a different job from judgement, it
caches on its own text, and skipping it leaves the report exactly as it was.

Nothing here is allowed to invent content. A translation that fails to
parse leaves both languages holding the original text -- a reader seeing
the same English twice has lost nothing, where a silently dropped field
would look like the model had no answer.
"""
import json
import re

from scanner.core import parse_llm_json

# The free-text fields, in the order the report renders them. The verdict
# fields (reachable/sanitized/confidence) are not translated: they are enum
# and numeric values the page already localizes through its own i18n table.
TRANSLATABLE_FIELDS = ("reasoning", "exploit_scenario", "remediation")

LANGUAGES = ("zh", "en")
LANGUAGE_NAMES = {"zh": "简体中文", "en": "English"}

_CJK = re.compile(r"[一-鿿]")
_LATIN = re.compile(r"[A-Za-z]")

# Chinese says the same thing in far fewer characters, and every one of
# these texts quotes Java identifiers, so a Chinese sentence still carries a
# stretch of Latin letters. Measured on the corpus, the two populations sit
# either side of this by a wide margin rather than crowding it.
CJK_RATIO_THRESHOLD = 0.15


def detect_language(text: str) -> str:
    """"zh" or "en" for a finding's free text. Latin-only text is "en";
    anything with a meaningful proportion of Han characters is "zh"."""
    if not text:
        return "en"
    cjk = len(_CJK.findall(text))
    if not cjk:
        return "en"
    latin = len(_LATIN.findall(text))
    return "zh" if cjk / max(cjk + latin, 1) >= CJK_RATIO_THRESHOLD else "en"


def finding_language(finding: dict) -> str:
    """One language for the whole finding rather than one per field: the
    three texts are written in a single reply and never disagree, and
    deciding per field would let a one-word remediation outvote a paragraph
    of reasoning."""
    return detect_language(" ".join(finding.get(f) or "" for f in TRANSLATABLE_FIELDS))


def needs_translation(finding: dict) -> bool:
    return any((finding.get(f) or "").strip() for f in TRANSLATABLE_FIELDS)


def build_translate_prompt(template: str, finding: dict, target: str) -> str:
    payload = {f: finding.get(f) or "" for f in TRANSLATABLE_FIELDS}
    return template.format(
        target_language=LANGUAGE_NAMES[target],
        payload=json.dumps(payload, ensure_ascii=False, indent=2),
    )


def apply_translation(finding: dict, source_language: str, translated: dict | None) -> dict:
    """`finding` plus `<field>_zh` / `<field>_en` for every translatable
    field, leaving the original fields untouched.

    The source language always gets the text verbatim -- round-tripping it
    through the model would degrade wording the verify stage was careful
    about. When `translated` is None (the call failed, or came back
    unparseable) both sides get the original: the report then shows the same
    text under either toggle, which is honest, rather than an empty panel.
    """
    other = "en" if source_language == "zh" else "zh"
    out = dict(finding)
    for field in TRANSLATABLE_FIELDS:
        original = finding.get(field) or ""
        out[f"{field}_{source_language}"] = original
        candidate = (translated or {}).get(field)
        out[f"{field}_{other}"] = candidate if isinstance(candidate, str) and candidate.strip() else original
    return out


def is_language(text: str, target: str) -> bool:
    """Did the model actually translate, rather than hand the text back?

    Deliberately laxer than detect_language(): this is a did-the-job check,
    not a classifier, and rejecting a correct translation costs a retry and
    then a fallback. For Chinese, any Han character at all counts -- a
    Chinese sentence about `getCanonicalPath()` can be mostly Latin. For
    English, the full classifier applies, since English prose has no reason
    to carry Han characters.

    Measured before this existed: asked for Chinese, the model returned the
    English input unchanged for 35 of 92 findings and paraphrased it in
    English for 2 more. All of it was valid JSON with the right keys, so
    shape validation alone reported 0 failures and shipped a report whose
    Chinese side was 41% English.
    """
    if not text.strip():
        return True
    return bool(_CJK.search(text)) if target == "zh" else detect_language(text) == "en"


def validate_translation(parsed, target: str) -> dict:
    """The checks, separated from the parsing so they can also be run on a
    value that came back from the cache.

    scanner.verify.call_llm_cached returns a cache hit without re-running
    the parse callback, which means an entry written before a check existed
    would slip past it forever. That is not hypothetical: the first run of
    this stage cached 37 replies that never left English, and re-running it
    after adding the language check changed nothing until the prompt --
    and therefore the cache key -- changed too.
    """
    if not isinstance(parsed, dict) or not any(k in parsed for k in TRANSLATABLE_FIELDS):
        raise json.JSONDecodeError("no translatable fields in reply", str(parsed), 0)
    kept = {k: v for k, v in parsed.items() if k in TRANSLATABLE_FIELDS and isinstance(v, str)}
    joined = " ".join(kept.values())
    if joined.strip() and not is_language(joined, target):
        raise json.JSONDecodeError(f"reply is not in {target}", joined, 0)
    return kept


def parse_translation(raw_text: str, target: str) -> dict:
    """Explicit validation rather than trusting the reply, per CLAUDE.md
    section 4. Raises json.JSONDecodeError for the caller to handle -- which
    lets the shared retry in scanner.verify.call_llm_cached have another go
    before the stage falls back to the original text.

    Three ways a reply fails: it does not parse, it parses but carries none
    of the expected keys, or it carries them and never left the source
    language. The last one is the common one and the only one that looks
    like success.
    """
    return validate_translation(parse_llm_json(raw_text), target)
