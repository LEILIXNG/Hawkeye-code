// A small, self-contained actix-web-shaped app with a handful of genuine
// vulnerabilities and their safe counterparts, checked into the repo so
// eval/labels.json's Rust entries are reproducible without an external
// download -- the same role python_demo/app.py and express_demo/app.js
// play for their languages. Every vulnerable handler has a `_safe` sibling
// doing the equivalent job correctly, so the label set is not all "yes".
//
// This is a fixture for the rule library and call graph, not a crate that
// builds: it is never compiled, only parsed by tree-sitter and scanned by
// Semgrep, the same way the other *_demo fixtures are.
use actix_web::{get, web, HttpResponse};
use std::process::Command;

fn run_ping(host: &str) {
    // CWE-78: the host is handed straight to a shell.
    Command::new("sh").arg("-c").arg(host).output().unwrap();
}

#[get("/ping")]
async fn ping(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let host = query.get("host").cloned().unwrap_or_default();
    run_ping(&host);
    HttpResponse::Ok().finish()
}

#[get("/ping/safe")]
async fn ping_safe(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let host = query.get("host").cloned().unwrap_or_default();
    Command::new("ping").arg("-c").arg("1").arg(host).output().unwrap();
    HttpResponse::Ok().finish()
}

fn find_user(username: &str) -> String {
    // CWE-89: the query is built by string formatting from a request
    // parameter, straight into what would be a query-execution call.
    format!("SELECT * FROM users WHERE username = '{}'", username)
}

#[get("/users")]
async fn users(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let username = query.get("username").cloned().unwrap_or_default();
    let sql = find_user(&username);
    HttpResponse::Ok().body(sql)
}

#[get("/users/safe")]
async fn users_safe(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let username = query.get("username").cloned().unwrap_or_default();
    // sqlx::query("SELECT * FROM users WHERE username = ?").bind(username)
    HttpResponse::Ok().body(format!("looked up {}", "<parameterized>"))
}

// Never called from anywhere -- exists to confirm the verifier (or a
// human) reads "not reachable" here, not "not vulnerable"; the sink itself
// is exactly as dangerous as run_ping()'s.
fn orphan_vulnerable_helper(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).output().unwrap();
}
