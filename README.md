<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="Hawkeye Code logo">
</p>

<h1 align="center">Hawkeye Code</h1>

<p align="center"><a href="README.zh-CN.md">中文</a> · English</p>

A local-first static code security scanner: upload a zip → Semgrep finds candidate source→sink paths → an LLM re-checks reachability → an LLM writes the fix-suggestion report.

No GitHub integration, no public server — single-user, runs entirely on your own machine. Full design: [`docs/framework.md`](docs/framework.md).

## Current stage

Phase 1: FastAPI backend + a single-page frontend, full upload → scan → report flow, LLM provider configurable from `/settings`.

## Running it

```bash
pip install -r requirements.txt
copy .env.example .env   # fill in OPENAI_API_KEY (or configure it from the /settings page instead)
uvicorn apps.api.main:app --reload --port 8000
```

Open `http://localhost:8000` to upload a zip, kick off a scan, and view the report — the frontend is served as static files by the same process, no separate Node server needed.

The Phase 0 command-line scripts (`scripts/01_scan.py`, `scripts/02_verify.py`) still work; their logic now lives in the `scanner/` package so the API can reuse it — both entry points share the same scan/verify code.

## Progress

- [x] ① Semgrep rule set wired up, producing a candidate list
- [x] ②③ Minimal context extraction + LLM verification scripts
- [x] `eval/labels.json` labeled data + accuracy comparison (9/9 candidates covered, 8/9 agreement)
- [x] Phase 1: FastAPI + SQLite + single-page frontend, full upload → scan → report loop verified end to end
