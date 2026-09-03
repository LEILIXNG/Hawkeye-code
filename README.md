<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="Hawkeye Code logo">
</p>

<h1 align="center">Hawkeye Code</h1>

<p align="center"><a href="README.zh-CN.md">中文</a> · English</p>

A local-first SAST tool for Java/Spring. Semgrep surfaces candidate sinks, a self-built cross-file call graph reconstructs how a request reaches each one, and an LLM rules on reachability and gives a fix.

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

```bash
uvicorn apps.api.main:app --port 8000
```

Open `http://localhost:8000`, drag in a zip of the project, wait for the scan, read the report. Reports are saved under `data/reports/` and open straight from disk — no server needed to read one.

There is a launcher for either platform that picks a free port (8000-8020), starts the
server and opens the browser: `./start.sh` on macOS and Linux, `启动前端.cmd` on Windows.

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

213 unit tests cover the deterministic half — dedup, path handling, context extraction, the call graph, the rule set contract, the HTTP API. No test makes a real LLM call; LLM quality is tracked separately through `eval/labels.json`.

## How it works

- **Cross-file analysis.** Semgrep OSS taint analysis stops at the method boundary. `scanner/callgraph.py` walks the other way — from the sink up through its callers, across files — until it reaches an entry point a request can come in through. Recognises HTTP handlers, message listeners (Kafka/Rabbit/JMS), Servlet/Filter methods, and MyBatis mapper XML.
- **Semgrep for candidates, LLM for verdicts.** Every verdict carries `reachable` / `sanitized` / `confidence` / `reasoning`, plus an exploit scenario and a concrete fix naming the line and the replacement.
- **Dataflow-scoped.** Findings that match a static property — weak hash, missing cookie flag, disabled cert check — are filtered out by CWE before they cost a verify call.
- **Reproducible rules.** `rules/vendor/semgrep-rules` is a locked submodule, curated in `rules/ruleset.yml` down to server-side Java/Spring. Five custom rules under `rules/custom` cover command injection, path traversal, XXE, open redirect and MyBatis `${}`.

Full architecture: `docs/framework.md`. Development conventions: `CLAUDE.md`.

## Status

Phase 1 is done — upload → scan → report works end to end.

- 19 hand-labeled candidates in `eval/labels.json`, all matched by the current rule set, agreement 18/19 on the most recent full run.
- The verifier flips roughly 16% of verdicts between identical re-runs, so a ±1 move on 19 labels is noise. Engine changes are argued with deterministic counts instead.
- Measured on a real 13-module Maven application, not only on a teaching target.

## License

[LGPL-2.1](LICENSE)
