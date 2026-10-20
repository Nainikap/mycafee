"""SQLite persistence. The engine owns one Store and writes once per tick inside a single transaction."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Any

from ..models import Alert, Flow, PolicyRule, Severity


class Store:
    def __init__(self, path: str | Path, read_only: bool = False) -> None:
        self.path = str(path)
        if read_only:
            self.conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5)
        else:
            self.conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            self.conn.executescript(resources.files(__package__).joinpath("schema.sql").read_text("utf-8"))
        self.conn.row_factory = sqlite3.Row
        self._in_tx = False

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[None]:
        if self._in_tx:
            yield
            return
        self.conn.execute("BEGIN")
        self._in_tx = True
        try:
            yield
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        finally:
            self._in_tx = False

    # ------------------------------------------------------------ meta
    def meta_get(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def meta_set(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, value))

    # ------------------------------------------------------------ apps & flows
    def upsert_app(self, app_id: str, name: str, ts: float) -> None:
        self.conn.execute(
            "INSERT INTO apps(app_id,name,first_seen,last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(app_id) DO UPDATE SET last_seen=excluded.last_seen, name=excluded.name",
            (app_id, name, ts, ts))

    def insert_flow(self, f: Flow) -> int:
        proto, laddr, lport, raddr, rport = f.key
        cur = self.conn.execute(
            "INSERT INTO flows(app_id,pid,proto,laddr,lport,raddr,rport,domain,ip_class,opened_at,bytes_out,bytes_in,ja3n)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f.app_id, f.pid, proto, laddr, lport, raddr, rport, f.domain, f.ip_class, f.opened_at,
             f.bytes_out, f.bytes_in, f.ja3n))
        return int(cur.lastrowid or 0)

    def update_flow(self, f: Flow) -> None:
        self.conn.execute("UPDATE flows SET domain=?, bytes_out=?, bytes_in=?, ja3n=?, closed_at=? WHERE id=?",
                          (f.domain, f.bytes_out, f.bytes_in, f.ja3n, f.closed_at, f.db_id))

    def insert_app_minute(self, app_id: str, minute_ts: int, new_flows: int, unique_dests: int, new_dests: int,
                          bytes_out: int, bytes_in: int, score: int, severity: Severity) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO app_minutes VALUES(?,?,?,?,?,?,?,?,?)",
            (app_id, minute_ts, new_flows, unique_dests, new_dests, bytes_out, bytes_in, score, severity.label))

    # ------------------------------------------------------------ baselines
    def save_baseline(self, b: Any) -> None:
        """``b`` is a detection.baseline.Baseline (kept untyped to avoid an import cycle)."""
        self.conn.execute(
            "INSERT OR REPLACE INTO baselines VALUES(?,?,?,?,?,?,?)",
            (b.app_id, b.first_seen, b.n_buckets, json.dumps(b.ewma), json.dumps(b.hour_hist), int(b.talker),
             b.updated_at))
        self.conn.executemany("INSERT OR REPLACE INTO baseline_dests VALUES(?,?,?,?)",
                              [(b.app_id, d, v[0], v[1]) for d, v in b.known_dests.items()])
        self.conn.executemany("INSERT OR IGNORE INTO baseline_ports VALUES(?,?)",
                              [(b.app_id, p) for p in b.known_ports])
        self.conn.executemany("INSERT OR IGNORE INTO baseline_ja3 VALUES(?,?)",
                              [(b.app_id, j) for j in b.known_ja3n])

    def load_baseline_rows(self) -> list[dict[str, Any]]:
        out = []
        for r in self.conn.execute("SELECT * FROM baselines"):
            app = r["app_id"]
            out.append({
                "app_id": app, "first_seen": r["first_seen"], "n_buckets": r["n_buckets"],
                "ewma": json.loads(r["ewma_json"]), "hour_hist": json.loads(r["hour_hist"]),
                "talker": bool(r["talker"]), "updated_at": r["updated_at"],
                "known_dests": {d: [fs, h] for d, fs, h in self.conn.execute(
                    "SELECT dest, first_seen, hits FROM baseline_dests WHERE app_id=?", (app,))},
                "known_ports": {p for (p,) in self.conn.execute(
                    "SELECT rport FROM baseline_ports WHERE app_id=?", (app,))},
                "known_ja3n": {j for (j,) in self.conn.execute(
                    "SELECT ja3n FROM baseline_ja3 WHERE app_id=?", (app,))},
            })
        return out

    # ------------------------------------------------------------ alerts
    def insert_alert(self, a: Alert) -> int:
        cur = self.conn.execute(
            "INSERT INTO alerts(app_id,opened_at,updated_at,resolved_at,status,severity,peak_score,top_heuristic,"
            "summary,evidence_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (a.app_id, a.opened_at, a.updated_at, a.resolved_at, a.status, a.severity.label, a.peak_score,
             a.top_heuristic, a.summary, json.dumps(a.evidence)))
        return int(cur.lastrowid or 0)

    def update_alert(self, a: Alert) -> None:
        self.conn.execute(
            "UPDATE alerts SET updated_at=?, resolved_at=?, status=?, severity=?, peak_score=?, summary=?, "
            "evidence_json=? WHERE id=?",
            (a.updated_at, a.resolved_at, a.status, a.severity.label, a.peak_score, a.summary,
             json.dumps(a.evidence), a.id))

    def load_alerts(self, statuses: tuple[str, ...] = ("open", "acked"), since: float = 0.0) -> list[Alert]:
        q = f"SELECT * FROM alerts WHERE status IN ({','.join('?' * len(statuses))}) AND updated_at >= ? ORDER BY updated_at"
        return [_row_to_alert(r) for r in self.conn.execute(q, (*statuses, since))]

    def recent_alerts(self, limit: int = 50, status: str | None = None) -> list[Alert]:
        if status:
            rows = self.conn.execute("SELECT * FROM alerts WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                                     (status, limit))
        else:
            rows = self.conn.execute("SELECT * FROM alerts ORDER BY updated_at DESC LIMIT ?", (limit,))
        return [_row_to_alert(r) for r in rows]

    # ------------------------------------------------------------ policy & audit
    def add_rule(self, r: PolicyRule) -> int:
        cur = self.conn.execute(
            "INSERT INTO policy_rules(scope,app_id,dest,action,created_at,expires_at,note) VALUES(?,?,?,?,?,?,?)",
            (r.scope, r.app_id, r.dest, r.action, r.created_at, r.expires_at, r.note))
        return int(cur.lastrowid or 0)

    def delete_rule(self, rule_id: int) -> None:
        self.conn.execute("DELETE FROM policy_rules WHERE id=?", (rule_id,))

    def list_rules(self, now: float | None = None) -> list[PolicyRule]:
        rows = self.conn.execute("SELECT * FROM policy_rules ORDER BY id")
        out = [PolicyRule(r["id"], r["scope"], r["action"], r["app_id"], r["dest"], r["created_at"],
                          r["expires_at"], r["note"] or "") for r in rows]
        return [r for r in out if now is None or r.expires_at is None or r.expires_at > now]

    def rules_version(self) -> tuple[int, int]:
        row = self.conn.execute("SELECT COUNT(*), COALESCE(MAX(id),0) FROM policy_rules").fetchone()
        return (row[0], row[1])

    def user_action(self, ts: float, alert_id: int | None, action: str, detail: str) -> None:
        self.conn.execute("INSERT INTO user_actions(ts,alert_id,action,detail) VALUES(?,?,?,?)",
                          (ts, alert_id, action, detail))

    # ------------------------------------------------------------ reporting
    def app_history(self, app_id: str, since_minute: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM app_minutes WHERE app_id=? AND minute_ts>=? ORDER BY minute_ts", (app_id, since_minute)))

    def app_summary(self, since: float) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT app_id, COUNT(*) AS flows, COUNT(DISTINCT raddr) AS dests, SUM(bytes_out) AS out, "
            "SUM(bytes_in) AS inb, MAX(opened_at) AS last FROM flows WHERE opened_at>=? "
            "GROUP BY app_id ORDER BY flows DESC", (since,)))

    def flows_since(self, since: float) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM flows WHERE opened_at>=? ORDER BY opened_at", (since,)))

    def retention(self, now: float, days: int) -> None:
        cutoff = now - days * 86400
        self.conn.execute("DELETE FROM flows WHERE closed_at IS NOT NULL AND closed_at < ?", (cutoff,))
        self.conn.execute("DELETE FROM app_minutes WHERE minute_ts < ?", (int(now - 30 * 86400),))


def _row_to_alert(r: sqlite3.Row) -> Alert:
    return Alert(r["id"], r["app_id"], r["opened_at"], r["updated_at"], r["status"], Severity.parse(r["severity"]),
                 r["peak_score"], r["top_heuristic"], r["summary"], json.loads(r["evidence_json"]), r["resolved_at"])
