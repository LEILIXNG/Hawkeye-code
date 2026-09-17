// Annotated fixture for command-injection.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
use std::process::Command;

fn run_ping(host: String) {
    // ruleid: rust-shell-invocation-with-nonconstant-command
    Command::new("sh").arg("-c").arg(host).output().unwrap();
}

fn run_backup(target_dir: &str) {
    // ruleid: rust-shell-invocation-with-nonconstant-command
    Command::new("bash").args(["-c", target_dir]).output().unwrap();
}

// A fully literal shell line carries no external input.
fn list_home() {
    // ok: rust-shell-invocation-with-nonconstant-command
    Command::new("sh").arg("-c").arg("ls -la /home").output().unwrap();
}

fn list_home_array() {
    // ok: rust-shell-invocation-with-nonconstant-command
    Command::new("bash").args(["-c", "ls -la /home"]).output().unwrap();
}

// Same two-argument shape, but no shell is invoked: the value is one argv
// entry to curl, not a command line a shell parses, so this rule's scope
// (see command-injection.yml's header) deliberately stays off it.
fn fetch(url: &str) {
    // ok: rust-shell-invocation-with-nonconstant-command
    Command::new("curl").arg("-s").arg(url).output().unwrap();
}
