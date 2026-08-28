<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="Hawkeye Code logo">
</p>

<h1 align="center">Hawkeye Code</h1>

<p align="center"><a href="README.zh-CN.md">中文</a> · English</p>

A local-first static code security scanner: upload a zip → Semgrep finds candidate source→sink paths → an LLM re-checks reachability → you get a browsable report.

No GitHub integration, no public server — single-user, runs entirely on your own machine. Full design: [`docs/framework.md`](docs/framework.md).

## Features

- **Semgrep candidates, LLM-verified reachability.** Semgrep stays cheap and fast at surfacing candidate taint paths; an LLM does the expensive part — deciding whether each one is actually reachable, sanitized, or a false positive — instead of a full from-scratch LLM analysis of the whole codebase.
- **Bring your own LLM.** Any OpenAI-compatible endpoint works (OpenAI, DeepSeek, Kimi, 通义千问, Zhipu GLM, a self-hosted gateway...). Save multiple provider configs from the web UI, switch which one is active, and pick a specific one per scan without touching `.env`.
- **Vendored, pinned rule set.** `rules/vendor/semgrep-rules` is a locked git submodule, not a live pull from the Semgrep Registry, so scans are reproducible across machines and over time. `rules/ruleset.yml` curates it down to what's relevant for server-side Java/Spring apps (Android- and Lambda-specific rules excluded).
- **One process, no build step.** FastAPI serves both the API and the single-page frontend as static files — `uvicorn` is the only thing you need to run.
- **The web UI**: drag-and-drop zip upload, a filterable inline view of each past scan's findings (reachable / not reachable / uncertain / verification failed), a collapsible settings panel, and a zh/en language toggle — all with automatic light/dark theming.

## Getting started

```bash
git clone --recurse-submodules https://github.com/LEILIXNG/Hawkeye-code.git
cd Hawkeye-code
pip install -r requirements.txt
copy .env.example .env   # fill in OPENAI_API_KEY (or configure a provider from the /settings page instead)
uvicorn apps.api.main:app --reload --port 8000
```

Already cloned without `--recurse-submodules`? Run `git submodule update --init` — without it, `rules/vendor/semgrep-rules` is empty and scans will miss most of the rule set.

Open `http://localhost:8000` to upload a zip, kick off a scan, and browse the report.

The Phase 0 command-line scripts (`scripts/01_scan.py`, `scripts/02_verify.py`, `scripts/03_eval.py`) still work standalone — their logic lives in the importable `scanner/` package, shared with the API.

## Testing

```bash
python -m pytest tests/ -v
```

Deterministic logic (dedup, path handling, context extraction, the API's HTTP contract) is covered by unit tests. LLM-verification quality is tracked separately via `eval/labels.json` — an automated test suite is the wrong place to make real, billed API calls with nondeterministic output.

## Status

Phase 1 (FastAPI + SQLite + web UI, full upload → scan → report loop) is done and has been under active iteration since: the rule set moved from live Registry packs to a pinned vendored submodule, LLM provider configs became independently saveable/switchable/selectable-per-scan, and the frontend went through several rounds of redesign. `eval/labels.json`'s 9 hand-labeled candidates are all covered by the current rule set, with LLM-verification agreement holding at 8/9 as prompt and provider changes are made — see `docs/framework.md` for the full architecture and `CLAUDE.md` for the project's own development conventions.

## License

[LGPL-2.1](LICENSE)
