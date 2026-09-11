/**
 * A small, self-contained Express app with a handful of genuine
 * vulnerabilities and their safe counterparts, checked into the repo so
 * eval/labels.json's JS entries are reproducible without an external
 * download -- see eval/fixtures/python_demo/app.py for the same reasoning.
 * Every vulnerable handler has a safe sibling doing the equivalent job
 * correctly, so the label set is not all "yes".
 */
const express = require("express");
const { execSync } = require("child_process");
const app = express();

function runQuery(sql) {
  return db.query(sql);
}

app.get("/users", (req, res) => {
  // CWE-89: the name is concatenated straight into the query string.
  const name = req.query.name;
  res.send(runQuery("select * from users where name = '" + name + "'"));
});

app.get("/users/safe", (req, res) => {
  const name = req.query.name;
  res.send(db.query("select * from users where name = ?", [name]));
});

function ping(host) {
  execSync("ping -c 1 " + host, { shell: true });
}

app.get("/ping", (req, res) => {
  // CWE-78: the host is handed straight to a shell. Only caller is the
  // handler below -- exercises cross-function call-graph tracing.
  ping(req.query.host);
  res.send("pinged");
});

app.get("/ping/safe", (req, res) => {
  execSync("ping", { args: ["-c", "1", req.query.host], shell: false });
  res.send("pinged");
});

const readReport = (filename) => {
  return require("fs").readFileSync("/var/reports/" + filename, "utf8");
};

app.get("/reports", (req, res) => {
  // CWE-22: the filename can carry ../.. and escape /var/reports.
  res.send(readReport(req.query.file));
});

app.get("/go", (req, res) => {
  // CWE-601: redirects straight to a request-controlled URL.
  res.redirect(req.query.to);
});

app.get("/go/safe", (req, res) => {
  const allowed = ["/home", "/about"];
  const to = req.query.to;
  res.redirect(allowed.includes(to) ? to : "/home");
});

function orphanVulnerableHelper(cmd) {
  // Never called from anywhere -- same dangerous shape as ping() above,
  // tests that the verifier says not-reachable, not not-vulnerable.
  execSync(cmd, { shell: true });
}

module.exports = app;
