-- NetSentry schema v1 (docs/03-data-model.md). Idempotent.
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS apps (
  app_id      TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  first_seen  REAL NOT NULL,
  last_seen   REAL NOT NULL,
  signed      INTEGER
);

CREATE TABLE IF NOT EXISTS flows (
  id          INTEGER PRIMARY KEY,
  app_id      TEXT NOT NULL,
  pid         INTEGER NOT NULL,
  proto       TEXT NOT NULL,
  laddr TEXT, lport INTEGER, raddr TEXT NOT NULL, rport INTEGER NOT NULL,
  domain      TEXT,
  ip_class    TEXT NOT NULL,
  opened_at   REAL NOT NULL,
  closed_at   REAL,
  bytes_out   INTEGER DEFAULT 0,
  bytes_in    INTEGER DEFAULT 0,
  ja3n        TEXT
);
CREATE INDEX IF NOT EXISTS ix_flows_app_time ON flows(app_id, opened_at);
CREATE INDEX IF NOT EXISTS ix_flows_raddr ON flows(raddr);

CREATE TABLE IF NOT EXISTS app_minutes (
  app_id       TEXT NOT NULL,
  minute_ts    INTEGER NOT NULL,
  new_flows    INTEGER, unique_dests INTEGER, new_dests INTEGER,
  bytes_out    INTEGER, bytes_in INTEGER,
  score        INTEGER, severity TEXT,
  PRIMARY KEY (app_id, minute_ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS baselines (
  app_id      TEXT PRIMARY KEY,
  first_seen  REAL NOT NULL,
  n_buckets   INTEGER NOT NULL,
  ewma_json   TEXT NOT NULL,
  hour_hist   TEXT NOT NULL,
  talker      INTEGER NOT NULL,
  updated_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS baseline_dests (app_id TEXT, dest TEXT, first_seen REAL, hits INTEGER,
                                           PRIMARY KEY (app_id, dest)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS baseline_ports (app_id TEXT, rport INTEGER, PRIMARY KEY (app_id, rport)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS baseline_ja3 (app_id TEXT, ja3n TEXT, PRIMARY KEY (app_id, ja3n)) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS alerts (
  id            INTEGER PRIMARY KEY,
  app_id        TEXT NOT NULL,
  opened_at     REAL NOT NULL,
  updated_at    REAL NOT NULL,
  resolved_at   REAL,
  status        TEXT NOT NULL,
  severity      TEXT NOT NULL,
  peak_score    INTEGER NOT NULL,
  top_heuristic TEXT NOT NULL,
  summary       TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, updated_at);

CREATE TABLE IF NOT EXISTS policy_rules (
  id          INTEGER PRIMARY KEY,
  scope       TEXT NOT NULL CHECK (scope IN ('app','dest','app+dest')),
  app_id      TEXT,
  dest        TEXT,
  action      TEXT NOT NULL CHECK (action IN ('allow','deny','mute')),
  created_at  REAL NOT NULL,
  expires_at  REAL,
  note        TEXT
);

CREATE TABLE IF NOT EXISTS user_actions (
  id INTEGER PRIMARY KEY, ts REAL, alert_id INTEGER, action TEXT, detail TEXT
);

CREATE TABLE IF NOT EXISTS dns_cache (ip TEXT PRIMARY KEY, name TEXT, source TEXT, expires_at REAL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS reputation_cache (ip TEXT PRIMARY KEY, score INTEGER, fetched_at REAL) WITHOUT ROWID;
