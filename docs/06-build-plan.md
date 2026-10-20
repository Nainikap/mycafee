# 6. Build Plan

Build in this order: **capture → storage → correlation → detection → UI → stretch**. Each phase ends with something runnable and a check that passes. Never start detection logic before real data is flowing into the DB.

```mermaid
flowchart LR
  P0[P0 Scaffold] --> P1[P1 Capture: sockets + processes]
  P1 --> P2[P2 Storage + flow table]
  P2 --> P3[P3 Sniffer: bytes, DNS, SNI, JA3]
  P2 --> P4[P4 Features + baselines]
  P3 --> P4
  P4 --> P5[P5 Heuristics + scorer + policy + alerts]
  P5 --> P6[P6 Textual TUI · MVP demo]
  P6 --> P7[P7 Record/replay + simulators + validation]
  P7 --> P8[P8 Stretch: FastAPI + web, reputation, toast]
```

| Phase | Deliverable | Done when |
|-------|-------------|-----------|
| **P0 · Scaffold** | `pyproject.toml`, package skeleton, `models.py`, `config.py` with `rules.yaml` validation, `clock.py`, `netsentry doctor`, ruff, pytest | `netsentry doctor` reports Python, admin state, Npcap presence and config validity. `pytest` is green. |
| **P1 · Capture (standard mode)** | `SocketPoller`, `ProcessResolver` (with lineage), `IdleMonitor`, `netsentry capture --dump` | With a browser on two known sites, the dump shows `chrome.exe` → their IPs on :443. PIDs match `netstat -ano`. System PIDs degrade to `pid:N` without crashing. |
| **P2 · Storage + flow table** | `schema.sql`, `Store`, `StorageWriter`, `Attributor` (socket-only path), `FlowTable`, `Engine.tick()` running steps 1–5 + 12 | After 10 min of `run --ui none`, `flows` has open/closed rows with correct timestamps. Killing and restarting the process loses ≤ 30 s of data. |
| **P3 · Sniffer (full mode)** | `PacketSniffer`, `tls.py`, `dns.py`, attribution of packet counters, `Enricher` (DNS → SNI → rDNS) | Downloading a 100 MB file shows ≈ 100 MB `bytes_in` on the right process (±10 %). `domain` is filled for > 90 % of browser flows. JA3 unit tests pass. Without admin, the engine falls back to standard mode cleanly. |
| **P4 · Features + baselines** | `FeatureExtractor`, buckets, window, `Baseline` (EWMA, known sets, hour hist, maturity), persistence, poisoning guard | `app_minutes` fills every minute. Baselines survive a restart. The learning countdown is visible in logs. |
| **P5 · Detection** | 8 heuristics, `Scorer`, `PolicyEngine`, `AlertManager`, worked-example tests | All doc 4.4 examples pass as unit tests. A replayed synthetic beacon produces exactly one HIGH alert with top heuristic `frequency`. |
| **P6 · TUI (MVP)** | Textual app table + alert pane + detail screen + allow/deny/mute/normal keys | End-to-end live demo: run a simulator → alert appears within 1 min. Pressing `n` suppresses it on the next tick, and that is visible in `user_actions`. |
| **P7 · Validation** | `record`/`replay`, `tools/simulate/*`, `export`, results tables | Every scenario in doc 7 has been run, with TP/FP numbers recorded. A demo replay file is committed. |
| **P8 · Stretch** | FastAPI + WS, React dashboard with per-app history charts, AbuseIPDB enrichment, desktop toast for HIGH, optional "block with Windows Firewall" (asks for confirmation; admin) | Each item is independent, so pick them by the time left. |

## Milestone mapping to the DA2 objectives

| DA2 objective | Satisfied by |
|---------------|--------------|
| Capture connections + attribute to process (PID + exe) | P1, P3 |
| Log metadata: destination, port, protocol, volume, frequency | P2, P3, P4 |
| Rule-based heuristic engine | P5 |
| Dashboard / CLI with severity + per-app history | P6 (P8 adds the web view) |
| Whitelist / blacklist | P5 policy + P6 keys |
| Honest validation, TP and FP | P7 |

## Decisions to confirm before P0
1. **Repository/folder:** build in `C:\MyProjects\mycafee` as-is (the package is called `netsentry`), or rename the folder?
2. **Git:** initialise a repo now and commit per phase? (Recommended.)
3. **Stretch priority:** web dashboard first, or reputation + toast first?
