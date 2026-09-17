// Annotated fixture for sql-string-formatting.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).

fn login_query(username: &str) -> String {
    // ruleid: rust-sql-string-built-from-nonconstant-segment
    format!("SELECT * FROM users WHERE username = '{}'", username)
}

fn user_by_id_concat(id: &str) -> String {
    // ruleid: rust-sql-string-built-from-nonconstant-segment
    "SELECT * FROM users WHERE id = '".to_string() + id + "'"
}

fn user_by_id_from(id: &str) -> String {
    // ruleid: rust-sql-string-built-from-nonconstant-segment
    String::from("SELECT * FROM users WHERE id = '") + id
}

// A format! call with no SQL keyword is not this rule's concern -- the
// keyword check is what keeps it off every other format! in a codebase.
fn greeting(name: &str) -> String {
    // ok: rust-sql-string-built-from-nonconstant-segment
    format!("Welcome back, {}!", name)
}

// A fully literal statement carries no external input.
fn list_active() -> String {
    // ok: rust-sql-string-built-from-nonconstant-segment
    "SELECT * FROM users WHERE active = true".to_string()
}
