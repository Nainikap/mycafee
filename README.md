# NetSentry

**On-device network behaviour monitor for applications.**
Computer Networks — Digital Assignment 2 · Nainika Pathak (24BCE0230)

NetSentry watches which process on your machine talks to which host, how often and how much. It scores that behaviour with transparent, rule-based heuristics and shows a severity per application in a live dashboard. It is a behaviour monitor, **not** an antivirus: it inspects metadata only and never decrypts payloads.

## Documentation

| # | Document | What it covers |
|---|----------|----------------|
| 1 | [System architecture](docs/01-architecture.md) | Goals, layers, components, runtime/threading model, privilege modes, key decisions |
| 2 | [End-to-end pipeline](docs/02-pipeline.md) | What happens on every tick, from the OS socket table to a persisted alert, plus the feedback loop |
| 3 | [Data model & storage](docs/03-data-model.md) | Domain objects, SQLite schema, retention |
| 4 | [Detection engine](docs/04-detection-engine.md) | Features, baselines, the 8 heuristics, scoring formula, severity, `rules.yaml` |
| 5 | [Technical implementation](docs/05-implementation.md) | Stack, repo layout, module interfaces, CLI, config, testing strategy |
| 6 | [Build plan](docs/06-build-plan.md) | Phased milestones with acceptance criteria — the order we build in |
| 7 | [Validation plan](docs/07-validation.md) | Attack simulators, demo script, how we measure true and false positives |

## At a glance

```
 OS socket table ─┐                                      ┌─► Textual TUI (MVP)
 (psutil, 2 s)    ├─► Attribution ─► Flow table ─► Features ─► 8 heuristics ─► Scorer ─► Alerts ─┤
 Npcap sniffer ───┘   (flow → PID)    (live flows)  (per app,   (each 0..1 +    (noisy-OR,  (dedupe, ├─► FastAPI + web dashboard
 (bytes, DNS, SNI, JA3)                             1-min buckets) evidence)     0..100)     SQLite)  │
                                    ▲                                                                │
                                    └──────── allow / deny / mute / "this is normal" ◄───────────────┘
```

## Quickstart (Windows)

```bash
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\netsentry doctor
.venv\Scripts\netsentry run
```

| Command | What it does |
|---------|--------------|
| `netsentry run` | Live dashboard (Textual TUI). Run from an **elevated** terminal for full mode (bytes, DNS, SNI, JA3 via Npcap). Without admin it runs in standard mode with 6 of 8 heuristics. |
| `netsentry run --profile demo` | Same, with a 10-minute learning period instead of 24 h |
| `netsentry demo` | Plays a synthetic attack scenario (beacon, exfiltration, blocklist hit, Word → PowerShell) through the real engine. No network needed. |
| `netsentry run --ui none` | Headless: prints alerts to the console |
| `netsentry record --out day.jsonl` / `netsentry replay day.jsonl` | Record raw capture, replay it later deterministically |
| `netsentry status`, `alerts`, `rules`, `export` | Read the database (`%LOCALAPPDATA%\NetSentry\netsentry.db`) |
| `netsentry allow/deny/mute --app onedrive.exe [--dest example.com]` | Feedback rules; a running engine picks them up within 10 s |

TUI keys: `enter` details · `a` allow · `d` deny · `m` mute 1 h · `n` this is normal · `k` acknowledge · `f` only flagged · `q` quit.

Tuning lives in [config/rules.yaml](config/rules.yaml) (weights and thresholds), [config/ports.yaml](config/ports.yaml), [config/lolbins.yaml](config/lolbins.yaml) and [config/blocklists/](config/blocklists). All of them are reloaded while running.

Attack simulators for validation are in [tools/simulate/sim.py](tools/simulate/sim.py) (see [doc 7](docs/07-validation.md)). Tests: `.venv\Scripts\python -m pytest`.

## Status

Phases P0–P7 of the [build plan](docs/06-build-plan.md) are implemented: capture, storage, sniffer, baselines, all 8 heuristics, TUI, CLI, simulators and tests. The P8 stretch goals (FastAPI + web dashboard, AbuseIPDB reputation, desktop toasts) are not started.
