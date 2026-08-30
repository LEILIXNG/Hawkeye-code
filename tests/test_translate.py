"""Unit tests for scanner/translate.py.

No LLM is called here. What is worth pinning is the deterministic half:
which language a finding is in, what happens to the text when the call
fails, and that a translated finding never loses the original wording the
verify stage produced.
"""
import json

import pytest

from scanner.translate import (
    TRANSLATABLE_FIELDS,
    apply_translation,
    build_translate_prompt,
    detect_language,
    finding_language,
    needs_translation,
    is_language,
    parse_translation,
)


def finding(reasoning="", exploit_scenario="", remediation=""):
    return {
        "reachable": "yes",
        "confidence": 90,
        "reasoning": reasoning,
        "exploit_scenario": exploit_scenario,
        "remediation": remediation,
    }


class TestDetectLanguage:
    def test_plain_english(self):
        assert detect_language("The sink concatenates a request parameter into SQL.") == "en"

    def test_plain_chinese(self):
        assert detect_language("该 sink 把请求参数直接拼进了 SQL 语句。") == "zh"

    def test_chinese_quoting_java_identifiers_is_still_chinese(self):
        """Every one of these texts names code, so a Chinese sentence always
        carries a run of Latin letters -- counting 'any Latin at all' as
        English would call the whole corpus English."""
        text = ("在第 292 行处对 `gradeInfoId` 进行白名单校验,并在第 299 行后添加 "
                "`canonicalPath.startsWith(basePath)` 检查。")
        assert detect_language(text) == "zh"

    def test_english_with_no_han_characters_is_english(self):
        assert detect_language("Replace ${sortParam} with #{sortParam}.") == "en"

    def test_empty_text_is_english(self):
        assert detect_language("") == "en"


class TestFindingLanguage:
    def test_decided_over_all_three_fields_together(self):
        """One reply writes all three, so they never disagree; judging per
        field would let a two-word remediation outvote a paragraph."""
        f = finding(reasoning="该参数来自 HTTP 请求,未经校验直接拼接。", remediation="Use #{param}.")
        assert finding_language(f) == "zh"

    def test_an_all_english_finding(self):
        f = finding(reasoning="Parameter flows from the controller.", remediation="Use a prepared statement.")
        assert finding_language(f) == "en"


class TestNeedsTranslation:
    def test_a_finding_with_no_free_text_is_skipped(self):
        """A not-reachable finding carries an empty exploit_scenario and
        remediation; there is nothing to spend a call on."""
        assert not needs_translation(finding())

    def test_reasoning_alone_is_enough(self):
        assert needs_translation(finding(reasoning="Not reachable."))


class TestApplyTranslation:
    def test_the_source_language_keeps_the_original_verbatim(self):
        """Round-tripping the original through the model would degrade
        wording the verify stage was careful about."""
        f = finding(reasoning="Parameter flows from the controller.", remediation="Use #{param}.")
        out = apply_translation(f, "en", {"reasoning": "参数来自控制器。", "remediation": "改用 #{param}。"})
        assert out["reasoning_en"] == "Parameter flows from the controller."
        assert out["reasoning_zh"] == "参数来自控制器。"

    def test_the_original_fields_are_left_alone(self):
        """03_eval.py and the report both still read them."""
        f = finding(reasoning="Parameter flows from the controller.")
        out = apply_translation(f, "en", {"reasoning": "参数来自控制器。"})
        assert out["reasoning"] == "Parameter flows from the controller."
        assert out["reachable"] == "yes" and out["confidence"] == 90

    def test_a_failed_call_leaves_the_original_on_both_sides(self):
        """Seeing the same English twice loses the reader nothing; an empty
        panel looks like the model had no answer."""
        f = finding(reasoning="Parameter flows from the controller.")
        out = apply_translation(f, "en", None)
        assert out["reasoning_zh"] == out["reasoning_en"] == "Parameter flows from the controller."

    def test_a_blank_translation_falls_back_rather_than_blanking_the_field(self):
        f = finding(reasoning="Parameter flows from the controller.")
        out = apply_translation(f, "en", {"reasoning": "   "})
        assert out["reasoning_zh"] == "Parameter flows from the controller."

    def test_every_translatable_field_gets_both_sides(self):
        f = finding(reasoning="a", exploit_scenario="b", remediation="c")
        out = apply_translation(f, "en", None)
        for field in TRANSLATABLE_FIELDS:
            assert f"{field}_zh" in out and f"{field}_en" in out


class TestParseTranslation:
    def test_keeps_only_the_translatable_fields(self):
        """The model is asked for three keys; anything else it volunteers --
        a verdict of its own, say -- must not reach the finding."""
        parsed = parse_translation('{"reasoning": "x", "remediation": "y", "reachable": "no"}', "en")
        assert parsed == {"reasoning": "x", "remediation": "y"}

    def test_a_reply_with_no_translatable_field_is_a_failure(self):
        """Valid JSON is not the same as an answer; CLAUDE.md section 4 says
        an unusable reply is marked, not massaged into a default."""
        with pytest.raises(json.JSONDecodeError):
            parse_translation('{"status": "ok"}', "en")

    def test_unparseable_output_raises(self):
        with pytest.raises(json.JSONDecodeError):
            parse_translation("I could not translate that.", "en")


class TestTargetLanguageIsChecked:
    """The failure that shipped once: asked for Chinese, the model handed the
    English input straight back for 35 of 92 findings and paraphrased it in
    English for 2 more. Every reply was valid JSON carrying the right keys,
    so shape validation reported zero failures and the report's Chinese side
    came out 41% English."""

    def test_echoed_source_text_is_rejected(self):
        with pytest.raises(json.JSONDecodeError):
            parse_translation('{"reasoning": "The sink concatenates a request parameter."}', "zh")

    def test_a_real_chinese_translation_passes(self):
        parsed = parse_translation('{"reasoning": "该 sink 直接拼接了请求参数。"}', "zh")
        assert parsed["reasoning"].startswith("该")

    def test_chinese_returned_when_english_was_asked_for_is_rejected(self):
        with pytest.raises(json.JSONDecodeError):
            parse_translation('{"reasoning": "该 sink 直接拼接了请求参数。"}', "en")

    def test_empty_fields_do_not_trip_the_check(self):
        """A not-reachable finding translates to empty strings, and empty is
        not a language."""
        assert parse_translation('{"reasoning": "", "remediation": ""}', "zh") == {
            "reasoning": "", "remediation": ""}

    def test_a_chinese_sentence_that_is_mostly_code_still_counts(self):
        """is_language is a did-the-job check, not a classifier: rejecting a
        correct translation costs a retry and then a fallback to English."""
        assert is_language("把 `${sortParam}` 换成 `#{sortParam}`", "zh")

    def test_english_naming_a_chinese_free_identifier_counts_as_english(self):
        assert is_language("Replace ${sortParam} with #{sortParam} in VulInfMapper.xml.", "en")


class TestPrompt:
    def test_renders_without_tripping_over_literal_braces(self):
        """prompts/*.md go through str.format(), and this template is full of
        JSON and `#{param}` examples -- the trap MEMORY.md records."""
        template = (
            "Translate to {target_language}.\n{payload}\n"
            "{{\n  \"reasoning\": \"\"\n}}\nkeep #{{sortParam}} as is"
        )
        out = build_translate_prompt(template, finding(reasoning="hello"), "zh")
        assert "简体中文" in out and '"reasoning": "hello"' in out
        assert "#{sortParam}" in out

    def test_the_real_template_renders(self):
        from scanner.common import PROMPTS_DIR
        template = (PROMPTS_DIR / "translate_finding.md").read_text(encoding="utf-8")
        out = build_translate_prompt(template, finding(reasoning="hello"), "en")
        assert "English" in out and "hello" in out
