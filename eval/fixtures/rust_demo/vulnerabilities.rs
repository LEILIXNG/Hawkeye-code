use std::process::Command;

fn ping(host: String) {
    Command::new("sh").arg("-c").arg(host).output().unwrap();
}

fn ping_safe(host: &str) {
    let allowed = ["localhost", "127.0.0.1"];
    if allowed.contains(&host) {
        Command::new("ping").arg("-c").arg("1").arg(host).output().unwrap();
    }
}

fn find_user(username: &str) -> String {
    format!("SELECT * FROM users WHERE username = '{}'", username)
}

fn find_user_safe() -> String {
    "SELECT * FROM users WHERE active = true".to_string()
}
