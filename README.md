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

## Status

Design phase. Building starts with Phase 0 in the [build plan](docs/06-build-plan.md).
