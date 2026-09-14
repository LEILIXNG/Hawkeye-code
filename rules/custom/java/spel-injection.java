// Annotated fixture for spel-injection.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
//
// This rule exists for the one shape the vendored spel-injection rule
// cannot see: no parser variable or field anywhere for its pattern-inside
// to match against, because the parser is constructed and used in one
// chained expression.
import org.springframework.expression.spel.standard.SpelExpressionParser;

class SpelInjectionFixture {

    // The HA_Benchmark-suite-412cases shape.
    void inlineChain(String value) {
        String template = "'seq-' + '" + value + "'";
        // ruleid: spel-injection-inline-parser
        new SpelExpressionParser().parseExpression(template).getValue();
    }

    void inlineChainNoTrailingCall(String value) {
        String template = "'seq-' + '" + value + "'";
        // ruleid: spel-injection-inline-parser
        new SpelExpressionParser().parseExpression(template);
    }

    // A fully literal expression carries no external input.
    void inlineChainConstant() {
        // ok: spel-injection-inline-parser
        new SpelExpressionParser().parseExpression("'fixed'").getValue();
    }

    // Same, via a constant local -- semgrep's constant propagation should
    // still see through this.
    void inlineChainConstantLocal() {
        String template = "'fixed'";
        // ok: spel-injection-inline-parser
        new SpelExpressionParser().parseExpression(template).getValue();
    }

    // The parser assigned to a local first is the vendored spel-injection
    // rule's shape, not this one's -- claiming it here would double-report
    // the same sink.
    void viaLocalVariable(String value) {
        String template = "'seq-' + '" + value + "'";
        SpelExpressionParser parser = new SpelExpressionParser();
        // ok: spel-injection-inline-parser
        parser.parseExpression(template).getValue();
    }
}
