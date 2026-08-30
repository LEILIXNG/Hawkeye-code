<p align="center">
  <img src="docs/brand/hawkeye-logo.png" width="120" alt="Hawkeye Code logo">
</p>

<h1 align="center">Hawkeye Code</h1>

<p align="center"><a href="README.zh-CN.md">中文</a> · English</p>

A local-first SAST tool for Java/Spring. Semgrep surfaces candidates, a self-built cross-file call graph reconstructs how a request reaches each sink, and an LLM rules on reachability and says how to fix it.

**Only findings with a complete source→sink path are reported.** Single-user, no GitHub integration, no public server — it runs entirely on your own machine.

```
zip → Semgrep candidates → call graph → LLM verdict → report
```

## Features

**Cross-file source→sink analysis, self-built**
- Semgrep OSS taint analysis is intraprocedural — it stops at the method boundary, so a SQL sink in a service class reports a local string as its "source" and never mentions the `@RequestParam` feeding it.
- `scanner/callgraph.py` walks the other way: from the sink up through its callers, across files, until it reaches something a request can enter through.
- Breadth-first with a shared visited set, so depth is bounded by the code rather than by cost. Depth 7 is the measured saturation point of a real layered Spring app.
- Recognises HTTP handlers, message listeners (Kafka/Rabbit/JMS), and servlet/filter methods by supertype.
- MyBatis mapper XML is in the graph too: `<mapper namespace>` names the interface, `<select id>` names the method, so a `${}` in a mapper traces back to the controller that reaches it.

**Semgrep for candidates, not for verdicts**
- Semgrep is asked only to surface candidate sinks — cheap and fast.
- Whether each one is genuinely reachable, sanitized, or a false positive is the LLM's call, informed by the call graph.
- Every verdict carries `reachable` / `sanitized` / `confidence` / `reasoning`, plus an exploit scenario and a concrete fix.

**Fix suggestions, not platitudes**
- The verifier names the line and the replacement — "swap `${sortParam}` for `#{sortParam}`; where `ORDER BY` cannot be parameterised, map the value through an allowlist of column names".
- Filled in for reachable and uncertain findings; empty for the ones with nothing to fix.

**Dataflow-scoped by design**
- A weakness counts only when externally controlled data reaches a dangerous operation.
- Rules matching a static property — a weak hash, a missing cookie flag, a disabled certificate check — are filtered out by CWE before they cost a verify call. They are real weaknesses; they belong to a different tool.
- The filter is a CWE denylist, so a vendor rule nobody here has seen is classified the first time it fires.

**Noise removed deterministically, not by feel**
- Copied modules are merged: the same file shipped under two package names is verified once and the report points at every copy.
- `scripts/rule_stats.py` reports per-rule and per-(rule, file) hit statistics, so any exclusion is made on evidence.
- `rules/ruleset.yml` carries generic `exclude_paths` for build output, generated code and vendored dependencies.

**Vendored, pinned rule set**
- `rules/vendor/semgrep-rules` is a locked git submodule, not a live Registry pull — scans are reproducible across machines and over time.
- Curated in `rules/ruleset.yml` down to server-side Java/Spring (Android and Lambda rules excluded).
- Five hand-written rules under `rules/custom` close measured blind spots: command injection, path traversal, XXE, open redirect, MyBatis `${}`.
- Every custom rule ships an annotated fixture; the test suite fails a rule with no positive or no negative case.

**Bring your own LLM**
- Any OpenAI-compatible endpoint: OpenAI, DeepSeek, Kimi, 通义千问, Zhipu GLM, a self-hosted gateway.
- Save several provider configs in the web UI, switch the active one, or pick one per scan without touching `.env`.

**Bilingual reports**
- zh/en toggle switches the labels *and* the LLM's own prose — reasoning, exploit scenario and fix.
- Reports open straight from disk; no server needed to read one.

**One process, no build step**
- FastAPI serves the API and the single-page frontend together. `uvicorn` is the only thing to run.
- Drag-and-drop upload, filterable inline findings, collapsible settings, automatic light/dark theming.

## Getting started

```bash
git clone --recurse-submodules https://github.com/LEILIXNG/Hawkeye-code.git
cd Hawkeye-code
pip install -r requirements.txt
copy .env.example .env   # fill in OPENAI_API_KEY, or configure a provider from the settings panel
uvicorn apps.api.main:app --reload --port 8000
```

Open `http://localhost:8000`, drop in a zip, and browse the report.

> Cloned without `--recurse-submodules`? Run `git submodule update --init`. Without it `rules/vendor/semgrep-rules` is empty and scans miss most of the rule set.

### Command line

Each stage runs standalone and exchanges JSON files; the logic lives in the importable `scanner/` package shared with the API.

| Script | Does |
| --- | --- |
| `scripts/01_scan.py` | Semgrep → deduped, in-scope candidates |
| `scripts/02_verify.py` | call graph + LLM → verdicts |
| `scripts/03_eval.py` | score verdicts against `eval/labels.json` |
| `scripts/04_translate.py` | fill in the other language (optional) |

`04_translate.py` is optional: skip it and the report reads exactly as before, in whichever language the model answered in.

## Testing

```bash
python -m pytest tests/ -v
```

- 213 unit tests cover the deterministic half: dedup, path handling, context extraction, the call graph, the rule set contract and the API's HTTP surface.
- No test makes a real LLM call — nondeterministic, billed output does not belong in CI.
- LLM quality is tracked separately through `eval/labels.json`.

## Status

Phase 1 is done — upload → scan → report works end to end — and has been iterated on since.

- 19 hand-labeled candidates in `eval/labels.json`, all matched by the current rule set, agreement 18/19 on the most recent full run.
- The verifier flips roughly 16% of verdicts between identical re-runs, so a ±1 move on 19 labels is noise. Engine changes are argued with deterministic counts instead: candidates without a reachable entry point, methods no longer truncated, chains recovered.
- Measured on a real 13-module Maven application, not only on a teaching target.

`docs/framework.md` has the full architecture; `CLAUDE.md` has the development conventions.

## License

[LGPL-2.1](LICENSE)
