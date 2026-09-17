// Annotated fixture for sql-string-formatting.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).

fun loginQueryBareInterpolation(username: String): String {
    // ruleid: kotlin-sql-string-built-from-nonconstant-segment
    return "SELECT * FROM users WHERE username = '$username'"
}

fun loginQueryBracedInterpolation(username: String): String {
    // ruleid: kotlin-sql-string-built-from-nonconstant-segment
    return "SELECT * FROM users WHERE username = '${username}'"
}

fun userByIdConcat(id: String): String {
    // ruleid: kotlin-sql-string-built-from-nonconstant-segment
    return "SELECT * FROM users WHERE id = '" + id + "'"
}

// An interpolated string with no SQL keyword is not this rule's concern.
fun greeting(name: String): String {
    // ok: kotlin-sql-string-built-from-nonconstant-segment
    return "Welcome back, $name!"
}

// A fully literal statement carries no external input.
fun listActive(): String {
    // ok: kotlin-sql-string-built-from-nonconstant-segment
    return "SELECT * FROM users WHERE active = true"
}

// Concatenation with no SQL keyword is not this rule's concern either.
fun greetingConcat(name: String): String {
    // ok: kotlin-sql-string-built-from-nonconstant-segment
    return "Welcome back, " + name
}
