# 3. Data Model & Storage

## 3.1 In-memory domain objects (`models.py`)

All of these are `@dataclass(slots=True)`. Objects that cross the capture/engine boundary are frozen.

```python
FlowKey      = (proto: "tcp"|"udp", laddr: str, lport: int, raddr: str, rport: int)
ProcKey      = (pid: int, create_time: float)       # stable identity; PIDs get reused
AppId        = str                                   # lower-cased exe path, or "name:<n>" / "pid:<n>" / "unknown" if exe is not readable

SocketEntry  (proto, laddr, lport, raddr, rport, status, pid)
ProcessInfo  (proc_key, name, exe, app_id, username, cmdline, parents: list[(name, exe)], signed: bool|None)
PacketStat   (flow_key, bytes_out, bytes_in, pkts_out, pkts_in, first_ts, last_ts, syn_ts: list[float])
DnsAnswer    (ip, qname, ttl, ts)
TlsHello     (flow_key, sni, ja3, ja3n, tls_version, ts)

Flow         (flow_key, pid, app_id, domain, dest, ip_class, inbound, source: socket|packet, opened_at,
              last_seen, closed_at, bytes_out, bytes_in, sni, ja3n, misses)
Bucket       (app_id, minute_ts, new_flows, dests: Counter[str], dest_info, remotes: {ip: domain},
              rports: {(proto, port): ips}, listen_ports, ip_bytes_out, bytes_out, bytes_in, ja3: {ja3n: ja3},
              idle_max, max_score, max_severity, marked_normal)
AppWindow    (app_id, buckets: last ≤5 closed + current, process: ProcessInfo,
              starts: {(raddr, rport): deque[start_ts] (≤ 20)}, now)
Baseline     (app_id, first_seen, n_buckets, ewma: dict[feature → (mean, var)],
              known_dests: dict[str → (first_seen, hits)], known_ports: set[int] (LISTEN ports negated),
              known_ja3n: set[str],
              hour_hist: list[int] (24), talker: bool)
HeuristicResult (name, score: float|None, weight, evidence: str, data: dict)   # score None = unavailable
Verdict      (app_id, ts, score: int 0..100, severity, results: list[HeuristicResult], policy: str|None)
Alert        (id, app_id, opened_at, updated_at, resolved_at, peak_score, severity, top_heuristic,
              summary, evidence_json, status: open|acked|resolved|false_positive)
PolicyRule   (id, scope: app|dest|app+dest, app_id?, dest?, action: allow|deny|mute, created_at, expires_at?, note)
```

## 3.2 SQLite schema (`storage/schema.sql`)

The database lives at `%LOCALAPPDATA%\NetSentry\netsentry.db` (overridable with `--db`). It uses `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`. Schema versions are tracked with `PRAGMA user_version`, and migrations are numbered `.sql` files.

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- e.g. system_first_seen (learning start)

CREATE TABLE apps (
  app_id        TEXT PRIMARY KEY,           -- lower-cased exe path
  name          TEXT NOT NULL,
  first_seen    REAL NOT NULL,
  last_seen     REAL NOT NULL,
  signed        INTEGER                     -- NULL = unknown
);

CREATE TABLE flows (
  id            INTEGER PRIMARY KEY,
  app_id        TEXT NOT NULL REFERENCES apps(app_id),
  pid           INTEGER NOT NULL,
  proto         TEXT NOT NULL,
  laddr TEXT, lport INTEGER, raddr TEXT NOT NULL, rport INTEGER NOT NULL,
  domain        TEXT,
  ip_class      TEXT NOT NULL,              -- public | private | multicast
  opened_at     REAL NOT NULL,
  closed_at     REAL,                        -- NULL while open
  bytes_out     INTEGER DEFAULT 0,
  bytes_in      INTEGER DEFAULT 0,
  ja3n          TEXT
);
CREATE INDEX ix_flows_app_time ON flows(app_id, opened_at);
CREATE INDEX ix_flows_raddr    ON flows(raddr);

CREATE TABLE app_minutes (                    -- closed 1-min buckets: feeds history charts
  app_id        TEXT NOT NULL,
  minute_ts     INTEGER NOT NULL,
  new_flows     INTEGER, unique_dests INTEGER, new_dests INTEGER,
  bytes_out     INTEGER, bytes_in INTEGER,
  score         INTEGER, severity TEXT,
  PRIMARY KEY (app_id, minute_ts)
) WITHOUT ROWID;

CREATE TABLE baselines (
  app_id        TEXT PRIMARY KEY,
  first_seen    REAL NOT NULL,
  n_buckets     INTEGER NOT NULL,
  ewma_json     TEXT NOT NULL,              -- {feature: [mean, var]}
  hour_hist     TEXT NOT NULL,              -- JSON list[24]
  talker        INTEGER NOT NULL,
  updated_at    REAL NOT NULL
);
CREATE TABLE baseline_dests (app_id TEXT, dest TEXT, first_seen REAL, hits INTEGER,
                             PRIMARY KEY (app_id, dest)) WITHOUT ROWID;
CREATE TABLE baseline_ports (app_id TEXT, rport INTEGER, PRIMARY KEY (app_id, rport)) WITHOUT ROWID;
CREATE TABLE baseline_ja3   (app_id TEXT, ja3n TEXT,  PRIMARY KEY (app_id, ja3n)) WITHOUT ROWID;

CREATE TABLE alerts (
  id            INTEGER PRIMARY KEY,
  app_id        TEXT NOT NULL,
  opened_at     REAL NOT NULL,
  updated_at    REAL NOT NULL,
  resolved_at   REAL,
  status        TEXT NOT NULL,              -- open | acked | resolved | false_positive
  severity      TEXT NOT NULL,
  peak_score    INTEGER NOT NULL,
  top_heuristic TEXT NOT NULL,
  summary       TEXT NOT NULL,              -- one human line
  evidence_json TEXT NOT NULL               -- all HeuristicResults at peak
);
CREATE INDEX ix_alerts_status ON alerts(status, updated_at);

CREATE TABLE policy_rules (
  id            INTEGER PRIMARY KEY,
  scope         TEXT NOT NULL CHECK (scope IN ('app','dest','app+dest')),
  app_id        TEXT,
  dest          TEXT,                       -- domain, IP or CIDR
  action        TEXT NOT NULL CHECK (action IN ('allow','deny','mute')),
  created_at    REAL NOT NULL,
  expires_at    REAL,
  note          TEXT
);

CREATE TABLE user_actions (                   -- audit trail, used for FP statistics
  id INTEGER PRIMARY KEY, ts REAL, alert_id INTEGER, action TEXT, detail TEXT
);

CREATE TABLE dns_cache (ip TEXT PRIMARY KEY, name TEXT, source TEXT, expires_at REAL) WITHOUT ROWID;
CREATE TABLE reputation_cache (ip TEXT PRIMARY KEY, score INTEGER, fetched_at REAL) WITHOUT ROWID;
```

## 3.3 Write strategy

- One `StorageWriter` coroutine owns the connection. The engine hands it a `WriteBatch` per tick, and it commits once.
- **Open flows** are inserted when they open (to get an `id`), updated with bytes every 30 s, and given `closed_at` when they close. A crash loses at most 30 s of byte counts.
- `app_minutes` rows are written at bucket close. History charts read **only** this table, never `flows`, so they stay fast.
- Readers (the API, `netsentry status`) open their own read-only connection. WAL means they never block the writer.

## 3.4 Retention and size

| Table | Retention | Approx. size |
|-------|-----------|--------------|
| flows | 7 days (`retention_days`) | ~2–5k flows/hour on a busy laptop → ~150 B/row → 30–90 MB/week |
| app_minutes | 30 days | ~50 apps × 1440 min/day, only for active minutes |
| alerts, user_actions, policy_rules, baselines | forever | small |

## 3.5 Config & static data (`config/`)

```
config/
  rules.yaml              # all heuristic weights and thresholds (see doc 4)
  blocklists/
    ips.txt               # one IP or CIDR per line; # comments
    domains.txt           # one domain per line; matches sub-domains
    ja3.txt               # known-bad JA3/JA3N hashes (e.g. abuse.ch SSLBL)
  ports.yaml              # common service ports and suspicious ports
  lolbins.yaml            # script hosts / LOLBins and suspicious parent→child pairs
```

All of these are plain text that a grader can open and edit. They are reloaded on change: the engine checks file modification times every 10 s.
