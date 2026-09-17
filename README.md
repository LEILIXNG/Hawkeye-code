<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="Hawkeye Code logo">
</p>

<h1 align="center">Hawkeye Code</h1>

<p align="center"><a href="README.zh-CN.md">中文</a> · English</p>

A local-first SAST tool for server-side web apps. Semgrep surfaces candidate sinks, a self-built cross-file call graph reconstructs how a request reaches each one, and an LLM rules on reachability and gives a fix. Java/Spring, Python (Flask, Django, FastAPI), JavaScript/TypeScript (Express, Koa, NestJS), Go (net/http, gorilla/mux, chi, gin, echo), and C++ all have full call-graph reachability tracing. Rust is scanned by the rule library too (vendored checks plus custom command-injection/SQL-injection rules), but has no call-graph indexer yet, so a Rust finding is judged from its own function body alone.

Only findings with a complete source→sink path are reported. Everything runs on your own machine.

```
zip → Semgrep candidates → call graph → LLM verdict → report
```

## Requirements

- Python 3.10+
- An API key for any OpenAI-compatible endpoint (OpenAI, DeepSeek, Kimi, 通义千问, Zhipu GLM, or a self-hosted gateway)

## Install

```bash
git clone --recurse-submodules https://github.com/LEILIXNG/Hawkeye-code.git
cd Hawkeye-code
pip install -r requirements.txt
```

Semgrep is pinned in `requirements.txt` — no separate install.

> Cloned without `--recurse-submodules`? Run `git submodule update --init`. Without it `rules/vendor/semgrep-rules` is empty and scans miss most of the rule set.

## Configure

```bash
cp .env.example .env
```

| Variable | Required | Notes |
| --- | --- | --- |
| `OPENAI_API_KEY` | yes | |
| `OPENAI_BASE_URL` | no | Only for non-OpenAI providers |
| `OPENAI_VERIFY_MODEL` | no | Model used for verdicts |

Providers can also be configured in the web UI and switched per scan, without editing `.env`.

## Run

`./start.sh` on macOS and Linux, `start.cmd` on Windows. Either picks a free port
(8000-8020), starts the server, and opens a real application window rather than a
browser tab. Launching twice does not start a second server; it reuses the one
already running.

Drag a zip of the project onto **New scan** and it becomes a row under **Scans**, where
its progress, elapsed time and live log live. Deleting a scan that is still running
stops it first. Reports are saved under `data/reports/` and open straight from disk —
no server needed to read one. A rate limit from the LLM endpoint (common on free
tiers) does not fail the scan outright: candidates already judged keep their verdict,
and the rest are marked "unverified" rather than folded into "safe" or "uncertain".

This window is the server's window: closing it stops the server (with a confirmation
first if a scan is still running); **Server** also has a button to stop it the same
way. A scan interrupted by the server stopping is marked as such the next time it
starts, rather than sitting at "verifying" forever.

To run the server yourself instead:

```bash
uvicorn apps.api.main:app --port 8000
```

### System dependencies for the native window

The window comes from `pywebview`, which drives the OS's own browser engine rather
than bundling Chromium. Where it can't be installed or can't run, the app falls back
to opening a system browser tab automatically — nothing stops working, you just lose
the standalone window.

| Platform | Needs |
| --- | --- |
| Windows | Usually nothing — WebView2 ships with Win10 (1803+) / Win11 |
| macOS | Usually nothing with the system Python; a standalone install (Homebrew/python.org) needs `pip install pyobjc-core pyobjc-framework-Cocoa pyobjc-framework-Quartz pyobjc-framework-WebKit pyobjc-framework-security` |
| Ubuntu/Debian | `sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1` |

## Command line

Each stage runs standalone and exchanges JSON files under `data/`.

```bash
python scripts/01_scan.py --target /path/to/repo
python scripts/02_verify.py --target /path/to/repo
python scripts/03_eval.py
python scripts/04_translate.py          # optional
```

| Script | Does | Writes |
| --- | --- | --- |
| `01_scan.py` | Semgrep → deduped, in-scope candidates | `data/candidates.json` |
| `02_verify.py` | call graph + LLM → verdicts | `data/verified.json` |
| `03_eval.py` | score verdicts against `eval/labels.json` | stdout |
| `04_translate.py` | fill in the other language | rewrites `data/verified.json` |

Useful flags: `--config p/java,p/owasp-top-ten` (01), `--limit N` (02, 04).

Skip `04_translate.py` and the report reads in whichever language the model answered in. HTML reports are produced by the web UI, not by these scripts.

## Test

```bash
python -m pytest tests/ -v
```

560 unit tests cover the deterministic half — dedup, path handling, context extraction, the call graph for all five language groups, the rule set contract, the HTTP API, and the launcher/window lifecycle. No test makes a real LLM call; LLM quality is tracked separately through `eval/labels.json`.

## How it works

- **Cross-file analysis, five language groups.** Semgrep OSS taint analysis stops at the method boundary. `scanner/callgraph/` walks the other way — from the sink up through its callers, across files — until it reaches an entry point a request can come in through. Java, Python and JavaScript/TypeScript retain their framework-specific entry recognizers; Go recognises net/http, gorilla/mux, chi, gin and echo route registrations. C++ recognises Crow, Drogon, Oat++ and gRPC entries and uses tree-sitter types, owners, overloads, template calls, local include macros and common function-pointer flows to remove ambiguous edges. A mixed-language checkout indexes into one shared graph.
- **Semgrep for candidates, LLM for dataflow verdicts.** Request-driven candidates keep the `reachable` / `sanitized` / `confidence` / `reasoning` contract. Deterministic C++ memory, null, secret and file-operation findings use rule validators and are labelled **Statically confirmed** without an irrelevant request-reachability LLM call.
- **Hybrid scope.** Generic static-property findings remain excluded by CWE, while custom rules carrying a deterministic validator can explicitly opt into the static-verdict path.
- **Risk from CVSS, not from the engine's own severity.** Semgrep grades everything ERROR or WARNING, which cannot separate an unauthenticated SQL injection from a weak hash. `scanner/cvss.py` maps each CWE to a v3.1 base vector and computes the score from it; reachability then grades that band, so a finding proved unreachable ends up lowest whatever it scored.
- **Reproducible rules.** `rules/vendor/semgrep-rules` is a locked submodule, curated for server-side Java/Spring, Python, JavaScript/TypeScript, Go and (rule-library only, see above) Rust. Nineteen custom rules under `rules/custom` add project-specific Java/XML coverage, eight C++ checks (`CPP001`–`CPP008`), and Rust command-injection/SQL-injection rules the vendored `rust/lang/security` bucket has no equivalent of. C++ rules use Semgrep's C++ AST; `.h` files require C++-specific content before their findings are accepted.

Full architecture: `docs/framework.md`. Development conventions: `CLAUDE.md`.

## Status

Phase 1 is done — upload → scan → report works end to end.

- 45 hand-labeled candidates in `eval/labels.json`: 19 Java, 9 Python, 7 JavaScript, 8 C++ (`eval/fixtures/cpp_demo`) and 2 Rust (`eval/fixtures/rust_demo`). C++ command-execution rules retain request reachability; deterministic CPP004–CPP008 findings use the static-verdict path. Rust has neither: both labels are `no`, since there is no call-graph indexer yet to show whether a value came from a request.
- C++ resolution is source based and deliberately does not execute a build. Conditional compilation, generated code and virtual/function-pointer targets that require a compiler database remain conservative rather than pretending to be exact.
- The verifier flips roughly 16% of verdicts between identical re-runs, so a ±1 move on any label set is noise. Engine changes are argued with deterministic counts instead.
- Java measured on a real 13-module Maven application, not only on a teaching target.

## License

[LGPL-2.1](LICENSE)
