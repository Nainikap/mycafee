# 5. Technical Implementation

## 5.1 Stack

| Concern | Choice | Version pin (initial) |
|---------|--------|-----------------------|
| Language | Python | 3.13 (installed) |
| Packaging | `pyproject.toml` + `uv` (fall back to `pip -e .`) | |
| Process / socket table | `psutil` | ≥ 6.0 |
| Packet capture | `scapy` on **Npcap** (already installed) | ≥ 2.6 |
| Config | `pydantic` v2 models + `PyYAML` | |
| Domain parsing | `tldextract` (offline suffix list snapshot) | |
| CLI | `typer` | |
| TUI | `textual` (+ `rich`) | |
| Storage | stdlib `sqlite3` | |
| API (stretch) | `fastapi` + `uvicorn` (WebSocket) | |
| Web UI (stretch) | Vite + React + TypeScript + Recharts, built into `src/netsentry/ui/api/static/` | Node 25 (installed) |
| Tests | `pytest`, `pytest-asyncio`, `hypothesis` (for the scorer properties) | |
| Lint / format | `ruff` (lint + format), `mypy --strict` on `detection/` | |

## 5.2 Repository layout

```
mycafee/                          # repo root (project = NetSentry)
├─ README.md
├─ pyproject.toml
├─ config/
│  ├─ rules.yaml                  # doc 4.6
│  ├─ ports.yaml                  # common_ports, suspicious_ports (+ labels)
│  ├─ lolbins.yaml                # script hosts, suspicious parents, system binaries, staging paths
│  └─ blocklists/{ips,domains,ja3}.txt
├─ src/netsentry/
│  ├─ __main__.py                 # python -m netsentry
│  ├─ cli.py                      # typer commands (5.5)
│  ├─ config.py                   # pydantic models, load + hot-reload
│  ├─ clock.py                    # Clock protocol; SystemClock, FakeClock
│  ├─ models.py                   # dataclasses (doc 3.1)
│  ├─ bus.py                      # EventBus: publish/subscribe of typed events
│  ├─ capture/
│  │  ├─ socket_poller.py
│  │  ├─ process_resolver.py
│  │  ├─ sniffer.py
│  │  ├─ tls.py                   # ClientHello → SNI, JA3, JA3N
│  │  ├─ dns.py                   # DNS response → DnsAnswer
│  │  ├─ idle.py                  # GetLastInputInfo (Windows) / stub elsewhere
│  │  └─ source.py                # CaptureSource protocol: LiveSource, ReplaySource
│  ├─ pipeline/
│  │  ├─ attributor.py
│  │  ├─ flow_table.py
│  │  ├─ enricher.py
│  │  ├─ recorder.py              # JSONL record
│  │  └─ engine.py                # tick orchestration (doc 2.1)
│  ├─ detection/
│  │  ├─ features.py              # Bucket, AppWindow, FeatureExtractor
│  │  ├─ baseline.py              # Baseline, EWMA, maturity
│  │  ├─ heuristics/
│  │  │  ├─ base.py               # Heuristic protocol, HeuristicContext, dev()
│  │  │  ├─ unusual_port.py  frequency.py  new_destination.py  volume.py
│  │  │  └─ blocklist.py  off_hours.py  lineage.py  tls_fingerprint.py
│  │  ├─ scorer.py                # noisy-OR + overrides
│  │  ├─ policy.py
│  │  └─ alerts.py
│  ├─ enrich/reputation.py        # stretch
│  ├─ storage/
│  │  ├─ schema.sql  migrations/  db.py  writer.py  queries.py
│  └─ ui/
│     ├─ tui/app.py  tui/widgets.py
│     └─ api/server.py  api/static/   # stretch
├─ web/                            # stretch: React source
├─ tools/simulate/                 # attack simulators (doc 7)
├─ tests/
│  ├─ unit/  integration/  fixtures/replays/
└─ docs/
```

## 5.3 Core interfaces

```python
# capture/source.py
class CaptureSource(Protocol):
    full_mode: bool
    async def start(self) -> None: ...
    async def sample(self) -> RawTick: ...         # sockets, processes, packet_stats, dns, tls, idle_s, ts
    async def stop(self) -> None: ...
# LiveSource wraps SocketPoller + ProcessResolver + PacketSniffer + IdleMonitor
# ReplaySource reads JSONL and drives FakeClock

# detection/heuristics/base.py
@dataclass(frozen=True, slots=True)
class HeuristicContext:
    now: float
    full_mode: bool
    system_mature: bool
    lists: StaticLists          # ports, lolbins, blocklists (hot-reloaded)
    cfg: HeuristicsConfig

class Heuristic(Protocol):
    name: str
    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult: ...

# detection/scorer.py
def score(results: list[HeuristicResult], policy: PolicyDecision, cfg: SeverityConfig) -> Verdict: ...

# pipeline/engine.py
class Engine:
    def __init__(self, source: CaptureSource, store: Store, cfg: Config, bus: EventBus, clock: Clock): ...
    async def run(self) -> None          # loop: tick() every poll_interval
    async def tick(self) -> TickResult   # public for tests: one deterministic step
    async def apply_user_action(self, action: UserAction) -> None
```

Events on the bus: `TickResult(apps: list[AppRow], stats)`, `AlertOpened`, `AlertUpdated`, `AlertResolved`, `ModeChanged`, `PolicyChanged`.

## 5.4 Implementation notes per component

**SocketPoller.** Wrap `psutil.net_connections("inet")` in `try/except psutil.AccessDenied`. On Windows it works without admin. Normalise IPv4-mapped IPv6 (`::ffff:1.2.3.4` → `1.2.3.4`). PID 0 or None goes to the app `system`.

**ProcessResolver.** Use `p.as_dict(attrs=[name, exe, username, cmdline, create_time, ppid])` inside one `oneshot()`. Walk parents with `psutil.Process(ppid)` and verify `parent.create_time() <= child.create_time()` to avoid PID-reuse lies. Cache misses cost ~1 ms each, which is acceptable.

**PacketSniffer.**
- `AsyncSniffer(filter="ip or ip6", prn=self._on_pkt, store=False, iface=<all non-loopback>)`.
- `_on_pkt` must be cheap. Read the IP/TCP/UDP header fields, decide direction (local if src ∈ `psutil.net_if_addrs()` IPs), and do `counters[key] += len`. Parse the payload **only** when (a) UDP sport 53 → DNS, or (b) TCP with payload where the first byte is `0x16` and the handshake type is `0x01` → ClientHello. Only check the first 3 data packets of each flow.
- Record SYN timestamps for beacon timing (cap 20 per flow key).
- Expose `pcap_stats()` (received/dropped) for the status bar.
- If `scapy` cannot open Npcap (not admin, or Npcap set to admin-only), log one clear warning and switch to standard mode.

**tls.py.** Hand-parse the ClientHello: version, cipher suites, extensions, supported_groups, ec_point_formats, SNI. Strip GREASE values (`0x?a?a`). `JA3 = md5("ver,ciphers,exts,groups,fmts")`. `JA3N` = the same with the extensions list sorted. Unit-test against published JA3 test vectors.

**Attributor.** Build `tcp_index: dict[FlowKey, SocketEntry]` and `udp_index: dict[(laddr|*, lport), SocketEntry]` per tick. Look up the packet key both as-is and reversed (for inbound direction). Keep pending entries for 2 ticks.

**FlowTable.** A dict keyed by `FlowKey`, with a `misses` counter per flow. When the remote is LAN or multicast, flag `ip_class` with the `ipaddress` module.

**IdleMonitor.** `ctypes.windll.user32.GetLastInputInfo` with a `LASTINPUTINFO` struct, then `(GetTickCount64() − dwTime) / 1000`. It returns 0 for non-interactive sessions.

**Storage.** Keep `schema.sql` idempotent. The writer uses `executemany` per table per tick. Use `check_same_thread=False` only on the writer connection, which is used by one coroutine.

**TUI (Textual).**
```
┌ NetSentry ─ FULL MODE ─ 47 apps ─ poll 42 ms ─ pcap drop 0 ─ learning: 4h12m left ┐
│ SEV  SCORE APP              PID   CONNS  DEST (top)          OUT/min  IN/min  WHY  │
│ HIGH   81  beacon.exe       9120     7   203.0.113.9:4444    1 KB     1 KB   H2 H1 │
│ MED    60  OneDrive.exe     4400    12   *.sharepoint.com    48 MB    0.2 MB H4    │
│ LOW    31  powershell.exe   7764     1   198.51.100.4:443    3 KB     40 KB  H7    │
│        12  chrome.exe       1220    63   google.com          0.4 MB   6 MB         │
├ Alerts ─────────────────────────────────────────────────────────────────────────────┤
│ 14:02 HIGH beacon.exe: 7 connections to 203.0.113.9 every 30.1 s; port 4444 …        │
└ [enter] details  [a] allow  [d] deny  [m] mute 1h  [n] this is normal  [f] filter  [q] ┘
```
The detail screen shows the parent chain, every heuristic with score, weight and evidence, a 60-minute sparkline from `app_minutes`, and the open flows.

**API (stretch).** `GET /api/apps`, `GET /api/apps/{id}/history?minutes=`, `GET /api/alerts?status=`, `POST /api/actions` (`{alert_id?, app_id, dest?, action}`), `WS /api/stream` (TickResult and alert events). It binds to **127.0.0.1 only**. A random token is generated at startup and printed to the console. Every request must send it as a header, which stops other local web pages from driving the API.

## 5.5 CLI

```
netsentry run      [--ui tui|web|none] [--profile default|demo] [--db PATH] [--no-sniff]
netsentry record   --out FILE [--minutes N]          # capture raw ticks, no scoring UI
netsentry replay   FILE [--speed 10] [--ui tui|none] [--db :memory:]
netsentry status                                      # one-shot table from the DB
netsentry alerts   [--status open] [--json]
netsentry allow|deny|mute  --app PATH|NAME [--dest D] [--minutes N]
netsentry export   --since 24h --format csv|json     # for the report
netsentry doctor                                      # checks admin, Npcap, psutil access, DB, config validity
```

`--profile demo` sets `learning_period_h = 0.17`, `min_buckets_mature = 5`, `quiet_hours = now`, so the whole story fits into a 15-minute demo.

## 5.6 Testing strategy

| Level | What | How |
|-------|------|-----|
| Unit | Every heuristic, each sub-rule, both the boundary and over it | Synthetic `AppWindow` / `Baseline` builders in `tests/factories.py` |
| Unit | Scorer | Worked-example table (doc 4.4) as parametrised tests. Hypothesis checks that the score is monotonic in each `s_i`, stays in [0, 100], and that overrides respect their order. |
| Unit | tls.py, dns.py | Byte fixtures of real ClientHellos and DNS responses |
| Unit | Attributor, FlowTable | Hand-built `RawTick`s: TCP exact match, UDP by port, pending → unknown, open → closing → closed |
| Integration | Engine end-to-end | `ReplaySource` + `FakeClock` + in-memory DB. Assert that the expected alert opens at the expected tick with the expected top heuristic. |
| System | Live capture correctness | Doc 7 V1: compare with `netstat -ano` and Resource Monitor |
| Performance | Tick budget | Replay a busy recording at 50× and assert p95 tick < 250 ms |

## 5.7 Conventions

- Detection code is pure. It does no I/O and never calls `time.time()`; it takes the clock and data as arguments.
- Every heuristic's evidence string is understandable by a non-expert and includes the numbers.
- Config errors fail fast at startup with the file name and line (pydantic validation).
- Logging uses stdlib `logging` to `%LOCALAPPDATA%\NetSentry\netsentry.log` with rotation, and prints a one-line tick summary at DEBUG.
- Secrets (the AbuseIPDB key) come only from environment variables.
