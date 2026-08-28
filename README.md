<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="Hawkeye Code logo">
</p>

<h1 align="center">Hawkeye Code</h1>

<p align="center"><a href="README.zh-CN.md">中文</a> · English</p>

A local-first static code security scanner built **on top of** Semgrep rather than around it: upload a zip → Semgrep surfaces candidates → Hawkeye's own cross-file call-graph analysis reconstructs how a request actually reaches each sink → an LLM rules on reachability → you get a browsable report.

No GitHub integration, no public server — single-user, runs entirely on your own machine. Full design: [`docs/framework.md`](docs/framework.md).

## Features

- **Cross-file source→sink analysis, self-built.** Semgrep's open-source taint analysis is intraprocedural: it stops at the method boundary, so a SQL sink inside a service class reports a local string as its "source" and says nothing about the `@RequestParam` in the controller that actually feeds it. `scanner/callgraph.py` closes that gap with its own tree-sitter–based reverse call graph — from a sink, up through its callers across files, until it reaches something a request can enter through. Adding those call paths to the verification context took agreement against the labeled set from 9/11 to 11/11 and emptied the `uncertain` bucket. No proprietary engine involved.
- **Semgrep for candidates, not for verdicts.** Semgrep stays cheap and fast at surfacing candidate taint paths, and that is all it is asked to do; deciding whether each one is genuinely reachable, sanitized, or a false positive is the LLM's job, informed by the call graph above — rather than a from-scratch LLM analysis of the whole codebase.
- **Rules measured against the target, then filled in.** Coverage is checked against what a codebase actually contains, and the gaps are closed with hand-written rules under `rules/custom`. `rules/ruleset.yml` also carries `exclude_rules` / `exclude_paths` for noise, and `scripts/rule_stats.py` reports per-rule and per-(rule, file) hit statistics so exclusions are made on evidence rather than by feel.
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

Phase 1 (FastAPI + SQLite + web UI, full upload → scan → report loop) is done and has been under active iteration since: the rule set moved from live Registry packs to a pinned vendored submodule, LLM provider configs became independently saveable/switchable/selectable-per-scan, the frontend went through several rounds of redesign, and analysis grew past what Semgrep alone reports — hand-written rules for measured blind spots, and the cross-file call graph described above.

All 11 of `eval/labels.json`'s hand-labeled candidates are covered by the current rule set, and LLM-verification agreement stands at 11/11 on the most recent full run, up from 8/9 before the call graph existed. That is one run of a nondeterministic verifier, not a guarantee — but the candidate that had been mismatching consistently since the eval was created now matches, and the call graph shows why it was previously unanswerable. See `docs/framework.md` for the full architecture and `CLAUDE.md` for the project's own development conventions.

## License

[LGPL-2.1](LICENSE)
