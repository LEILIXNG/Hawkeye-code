"""A small, self-contained Flask app with a handful of genuine
vulnerabilities and their safe counterparts, checked into the repo so
eval/labels.json's Python entries are reproducible without an external
download -- unlike the Java labels, which reference VulnerableApp, a real
teaching corpus nobody here redistributes. Every vulnerable function has a
`_safe` sibling doing the equivalent job correctly, so the label set is not
all "yes": scoring a verifier that says "reachable" for everything would
still look perfect against an all-vulnerable corpus.
"""
import os
import sqlite3
import subprocess

from flask import Flask, redirect, render_template_string, request
import requests

app = Flask(__name__)


def _run_query(sql):
    conn = sqlite3.connect(":memory:")
    return conn.execute(sql).fetchall()


@app.route("/users")
def search_users():
    # CWE-89: the query is built by string concatenation from a request
    # parameter, straight into execute().
    name = request.args.get("name")
    return str(_run_query("select * from users where name = '" + name + "'"))


@app.route("/users/safe")
def search_users_safe():
    name = request.args.get("name")
    conn = sqlite3.connect(":memory:")
    return str(conn.execute("select * from users where name = ?", (name,)).fetchall())


def _ping(host):
    subprocess.call("ping -c 1 " + host, shell=True)


@app.route("/ping")
def ping():
    # CWE-78: the host is handed straight to a shell.
    host = request.args.get("host")
    _ping(host)
    return "pinged"


@app.route("/ping/safe")
def ping_safe():
    host = request.args.get("host")
    subprocess.call(["ping", "-c", "1", host], shell=False)
    return "pinged"


@app.route("/greet")
def greet():
    # CWE-1336 (SSTI): the template string itself is attacker-controlled,
    # not just a value substituted into a fixed template.
    name = request.args.get("name")
    return render_template_string("Hello " + name + "!")


@app.route("/greet/safe")
def greet_safe():
    name = request.args.get("name")
    return render_template_string("Hello {{ name }}!", name=name)


def _read_report(filename):
    with open(os.path.join("/var/reports", filename)) as f:
        return f.read()


@app.route("/reports")
def reports():
    # CWE-22: the filename can carry ../.. and escape /var/reports.
    filename = request.args.get("file")
    return _read_report(filename)


@app.route("/go")
def go():
    # CWE-601: redirects straight to a request-controlled URL.
    target = request.args.get("to")
    return redirect(target)


@app.route("/go/safe")
def go_safe():
    target = request.args.get("to")
    allowed = {"/home", "/about"}
    return redirect(target if target in allowed else "/home")


@app.route("/fetch")
def fetch():
    # CWE-918 (SSRF): fetches whatever URL the caller supplies.
    url = request.args.get("url")
    return requests.get(url).text


def orphan_vulnerable_helper(cmd):
    """Never called from anywhere -- exists to confirm the verifier (or a
    human) reads "not reachable" here, not "not vulnerable"; the sink
    itself is exactly as dangerous as ping()'s."""
    subprocess.call(cmd, shell=True)
