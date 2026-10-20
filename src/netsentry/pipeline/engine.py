"""Tick orchestration: capture -> attribute -> flows -> enrich -> features -> heuristics -> score -> alerts -> DB -> bus.

See docs/02-pipeline.md. Only this coroutine mutates engine state, so nothing here needs locks.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..bus import EventBus
from ..capture.source import CaptureSource, Recorder
from ..clock import Clock
from ..config import DEFAULT_CONFIG_DIR, Config, StaticLists, load_config
from ..detection import scorer
from ..detection.alerts import AlertEvent, AlertManager, app_label
from ..detection.baseline import Baseline
from ..detection.features import Bucket, FeatureExtractor
from ..detection.heuristics import ALL as HEURISTICS
from ..detection.heuristics import HeuristicContext
from ..detection.policy import PolicyEngine
from ..models import Flow, PolicyRule, ProcessInfo, RawTick, Severity, Verdict
from ..storage.db import Store
from .attributor import Attributor
from .enricher import Enricher
from .flow_table import FlowTable

log = logging.getLogger(__name__)

FLOW_FLUSH_S = 30
BASELINE_FLUSH_S = 300
RELOAD_CHECK_S = 10
RETENTION_S = 3600


@dataclass(slots=True)
class AppRow:
    app_id: str
    name: str
    pid: int
    conns: int
    top_dest: str
    out_per_min: int
    in_per_min: int
    score: int
    severity: Severity
    codes: list[str]
    policy: str | None
    learning: bool


@dataclass(slots=True)
class TickStats:
    ts: float
    tick_ms: float
    full_mode: bool
    mode_reason: str
    n_apps: int
    n_flows: int
    pcap_recv: int
    learning_left_s: float
    ticks: int


@dataclass(slots=True)
class TickResult:
    stats: TickStats
    apps: list[AppRow]
    events: list[AlertEvent] = field(default_factory=list)


class Engine:
    def __init__(self, source: CaptureSource, store: Store, cfg: Config, bus: EventBus, clock: Clock,
                 config_dir: Path = DEFAULT_CONFIG_DIR, profile: str = "default", rdns: bool = True,
                 recorder: Recorder | None = None) -> None:
        self.source = source
        self.store = store
        self.cfg = cfg
        self.bus = bus
        self.clock = clock
        self.config_dir = config_dir
        self.profile = profile
        self.recorder = recorder
        self.lists = StaticLists(config_dir)
        self.attributor = Attributor()
        self.flows = FlowTable(ignore_loopback=cfg.engine.ignore_loopback)
        self.enricher = Enricher(rdns=rdns)
        self.features = FeatureExtractor(cfg.engine.bucket_s, cfg.engine.window_buckets)
        self.policy = PolicyEngine()
        self.alerts = AlertManager(store, cfg.severity)
        self.baselines: dict[str, Baseline] = {r["app_id"]: Baseline.from_row(r) for r in store.load_baseline_rows()}
        self.verdicts: dict[str, Verdict] = {}
        self.processes: dict[str, ProcessInfo] = {}
        self.system_first_seen: float | None = None
        self.ticks = 0
        self.full_mode = False
        self._pending_dest: list[Flow] = []
        self._last_flow_flush = 0.0
        self._last_baseline_flush = 0.0
        self._last_reload = 0.0
        self._last_retention = 0.0
        self._rules_version: tuple[int, int] | None = None
        self._rules_mtime = self._rules_file_mtime()
        self.last_result: TickResult | None = None
        self._reload_policy(0.0)

    # ------------------------------------------------------------------ lifecycle
    async def run(self, max_ticks: int | None = None) -> None:
        await self.source.start()
        try:
            while max_ticks is None or self.ticks < max_ticks:
                started = self.clock.now()
                res = await self.tick()
                if res is None:
                    break
                elapsed = self.clock.now() - started
                await self.clock.sleep(max(0.0, self.cfg.engine.poll_interval_s - elapsed))
        finally:
            await self.source.stop()
            self.flush_all()

    def flush_all(self) -> None:
        with self.store.tx():
            for f in self.flows.flows.values():
                if f.db_id is not None:
                    self.store.update_flow(f)
            for b in self.baselines.values():
                if b.dirty:
                    self.store.save_baseline(b)
                    b.dirty = False

    # ------------------------------------------------------------------ the tick
    async def tick(self) -> TickResult | None:
        t0 = time.perf_counter()
        raw = await self.source.sample()
        if raw is None:
            return None
        if self.recorder:
            self.recorder.write(raw)
        now = raw.ts
        self.full_mode = raw.full_mode
        first = self.ticks == 0
        self.ticks += 1
        self._ensure_system_start(now)
        self._maybe_reload(now)

        # 1-5: attribution and flow table
        self.enricher.ingest_dns(raw.dns)
        attributed = self.attributor.attribute(raw, self.flows.pid_of)
        changes = self.flows.apply(raw, attributed)

        # close buckets whose minute has passed *before* adding this tick's activity
        self._roll_buckets(now)

        new_flows: list[Flow] = []
        for f in changes.opened:
            proc = raw.processes.get(f.pid)
            if proc is not None:
                self.processes[f.app_id] = proc
            if f.app_id not in self.baselines:
                self.baselines[f.app_id] = Baseline(f.app_id, now)
            start = changes.starts.get(f.key, f.opened_at)
            self.features.on_open(f, proc, start, count=not first)
            self._pending_dest.append(f)
            new_flows.append(f)

        for h in raw.tls:
            f = self.flows.get(h.key)
            if f is not None:
                f.sni, f.ja3n = h.sni or f.sni, h.ja3n
                self.features.on_tls(f, h.ja3, h.ja3n, now)

        # 6: names / destinations (rDNS may take a few ticks)
        still: list[Flow] = []
        for f in self._pending_dest:
            if f.closed_at is not None and f.dest is None:
                f.dest = f.raddr  # closed before naming finished
            if self.enricher.settle(f, now):
                self.features.on_dest(f, now)
            else:
                still.append(f)
        self._pending_dest = still
        for f in self.flows.flows.values():
            if f.domain is None:
                self.enricher.refresh(f, now)

        # 7: bytes, idle, listening ports
        for f, d_out, d_in in changes.bytes:
            self.features.on_bytes(f, d_out, d_in, now)
        self.features.on_idle(raw.idle_s)
        listens: dict[str, list[int]] = {}
        for s in raw.listens:
            if s.proto == "tcp" and s.laddr not in ("127.0.0.1", "::1"):
                p = raw.processes.get(s.pid)
                if p is not None:
                    listens.setdefault(p.app_id, []).append(s.lport)
        for app, ports in listens.items():
            self.features.on_listen(app, ports, now)

        # 8-10: heuristics, policy, score
        verdicts = self._evaluate(now, raw.idle_s)

        # 11-12: alerts and persistence (one transaction)
        with self.store.tx():
            for f in new_flows:
                self.store.upsert_app(f.app_id, self._name(f.app_id), now)
                f.db_id = self.store.insert_flow(f)
            for f in changes.closed:
                if f.db_id is not None:
                    self.store.update_flow(f)
            if now - self._last_flow_flush >= FLOW_FLUSH_S:
                self._last_flow_flush = now
                for f in self.flows.flows.values():
                    if f.db_id is not None and (f.bytes_out != f.persisted_out or f.bytes_in != f.persisted_in
                                                or f.domain):
                        self.store.update_flow(f)
                        f.persisted_out, f.persisted_in = f.bytes_out, f.bytes_in
            events = self.alerts.process(verdicts, now)
            if now - self._last_baseline_flush >= BASELINE_FLUSH_S:
                self._last_baseline_flush = now
                for b in self.baselines.values():
                    if b.dirty:
                        self.store.save_baseline(b)
                        b.dirty = False
            if now - self._last_retention >= RETENTION_S:
                self._last_retention = now
                self.store.retention(now, self.cfg.engine.retention_days)
                self.enricher.prune(now)

        # 13: publish
        res = TickResult(self._stats(raw, t0), self._rows(now), events)
        self.last_result = res
        self.bus.publish(res)
        tick_ms = res.stats.tick_ms
        if tick_ms > 250:
            log.warning("slow tick: %.0f ms", tick_ms)
        return res

    # ------------------------------------------------------------------ steps
    def _ensure_system_start(self, now: float) -> None:
        if self.system_first_seen is None:
            v = self.store.meta_get("system_first_seen")
            if v is None:
                self.store.meta_set("system_first_seen", str(now))
                v = str(now)
            self.system_first_seen = float(v)

    @property
    def system_matured_at(self) -> float:
        assert self.system_first_seen is not None
        return self.system_first_seen + self.cfg.engine.learning_period_h * 3600

    def _roll_buckets(self, now: float) -> None:
        closed = self.features.roll(now)
        if not closed:
            return
        alpha = self.cfg.baseline.ewma_alpha
        with self.store.tx():
            for b in closed:
                base = self.baselines.get(b.app_id)
                new_dests = sum(1 for d in b.dests if base is None or d not in base.known_dests)
                # poisoning guard: only clean (or user-confirmed) minutes teach the baseline
                if base is not None and (b.max_severity < Severity.MEDIUM or b.marked_normal):
                    base.fold(b, alpha, datetime.fromtimestamp(b.minute_ts).hour, self.full_mode, now)
                if b.active:
                    self.store.insert_app_minute(b.app_id, b.minute_ts, b.new_flows, len(b.dests), new_dests,
                                                 b.bytes_out, b.bytes_in, b.max_score, b.max_severity)

    def _evaluate(self, now: float, idle_s: float) -> list[Verdict]:
        dirty = self.features.take_dirty()
        todo = dirty | {a for a, v in self.verdicts.items() if v.score > 0}
        system_mature = now >= self.system_matured_at
        out: list[Verdict] = []
        for app in todo:
            win = self.features.window(app, now)
            if win is None:
                self.verdicts.pop(app, None)
                continue
            base = self.baselines.get(app)
            name = self._name(app)
            pol = self.policy.for_app(app, name, now)
            ctx = HeuristicContext(now, self.full_mode, system_mature, self.system_matured_at, idle_s,
                                   self.lists, self.cfg, pol)
            results = [h.evaluate(win, base, ctx) for h in HEURISTICS if h.hcfg(ctx).enabled]
            denied = None
            if pol.dest_rules:
                for ip, dom in win.remotes().items():
                    if pol.dest_action(win.ip_dest().get(ip), ip, dom) == "deny":
                        denied = dom or ip
                        break
            v = scorer.score(app, now, results, pol, self.cfg, denied)
            self.verdicts[app] = v
            cur = win.current
            if v.score > cur.max_score:
                cur.max_score = v.score
            if v.severity > cur.max_severity and v.policy not in ("allowed", "muted"):
                cur.max_severity = v.severity
            out.append(v)
        return out

    def _maybe_reload(self, now: float) -> None:
        if now - self._last_reload < RELOAD_CHECK_S:
            return
        self._last_reload = now
        if self.lists.reload_if_changed():
            log.info("static lists reloaded")
        m = self._rules_file_mtime()
        if m != self._rules_mtime:
            self._rules_mtime = m
            try:
                self.cfg = load_config(self.config_dir, self.profile)
                self.alerts.cfg = self.cfg.severity
                log.info("rules.yaml reloaded")
            except Exception as e:  # keep running on the old config if the edit is invalid
                log.error("rules.yaml invalid, keeping previous config: %s", e)
        self._reload_policy(now)

    def _reload_policy(self, now: float) -> None:
        v = self.store.rules_version()
        if v != self._rules_version:
            self._rules_version = v
            self.policy.load(self.store.list_rules())

    def _rules_file_mtime(self) -> float:
        try:
            return (self.config_dir / "rules.yaml").stat().st_mtime
        except OSError:
            return -1.0

    # ------------------------------------------------------------------ user feedback (doc 2.5)
    def user_action(self, action: str, app_id: str, dest: str | None = None, minutes: float | None = None,
                    alert_id: int | None = None, note: str = "") -> str:
        """allow | allow_dest | deny | deny_dest | mute | normal | ack. Takes effect on the next tick."""
        now = self.clock.now()
        alert = self.alerts.by_id(alert_id) if alert_id else self.alerts.latest_for_app(app_id)
        msg = ""
        with self.store.tx():
            if action in ("allow", "deny", "mute"):
                exp = now + minutes * 60 if minutes else None
                if action == "mute" and exp is None:
                    exp = now + 3600
                self.store.add_rule(PolicyRule(None, "app", action, app_id, None, now, exp, note))
                msg = f"{action} {app_label(app_id)}" + (f" for {minutes:g} min" if minutes else "")
            elif action in ("allow_dest", "deny_dest"):
                if not dest:
                    return "no destination given"
                self.store.add_rule(PolicyRule(None, "app+dest", action.split("_")[0], app_id, dest, now, None, note))
                if action == "allow_dest" and app_id in self.baselines:
                    self.baselines[app_id].known_dests.setdefault(dest, [now, 1])
                    self.baselines[app_id].dirty = True
                msg = f"{action.replace('_', ' ')} {dest} for {app_label(app_id)}"
            elif action == "normal":
                self._mark_normal(app_id, now)
                if alert is not None and alert.id is not None:
                    self.alerts.set_status(alert.id, "false_positive", now)
                msg = f"marked {app_label(app_id)}'s current behaviour as normal"
            elif action == "ack":
                if alert is not None and alert.id is not None:
                    self.alerts.set_status(alert.id, "acked", now)
                msg = "acknowledged"
            else:
                return f"unknown action {action}"
            self.store.user_action(now, alert.id if alert else None, action,
                                   f"app={app_id}" + (f" dest={dest}" if dest else ""))
        self._reload_policy(now)
        self.features.dirty.add(app_id)
        return msg

    def _mark_normal(self, app_id: str, now: float) -> None:
        """Fold the alerted window into the baseline — the only way flagged behaviour becomes 'normal'."""
        base = self.baselines.get(app_id)
        st = self.features.apps.get(app_id)
        if base is None or st is None:
            return
        for b in st.closed:
            b.marked_normal = True
            if not b.folded:
                base.fold(b, self.cfg.baseline.ewma_alpha, datetime.fromtimestamp(b.minute_ts).hour,
                          self.full_mode, now)
        st.current.marked_normal = True
        base.add_known(st.current, now)
        self.verdicts.pop(app_id, None)

    # ------------------------------------------------------------------ views
    def _name(self, app_id: str) -> str:
        p = self.processes.get(app_id)
        return p.name if p and p.name else app_label(app_id)

    def _stats(self, raw: RawTick, t0: float) -> TickStats:
        left = max(0.0, self.system_matured_at - raw.ts)
        return TickStats(raw.ts, (time.perf_counter() - t0) * 1000, raw.full_mode, self.source.mode_reason,
                         len(self.features.apps), len(self.flows.flows), raw.pcap_recv, left, self.ticks)

    def _rows(self, now: float) -> list[AppRow]:
        open_counts = self.flows.open_counts()
        top_dest: dict[str, tuple[int, str]] = {}
        pids: dict[str, int] = {}
        for f in self.flows.flows.values():
            pids.setdefault(f.app_id, f.pid)
        rows = []
        for app, st in self.features.apps.items():
            win = self.features.window(app, now)
            if win is None:
                continue
            counts: dict[str, int] = {}
            for b in win.buckets:
                for d, n in b.dests.items():
                    counts[d] = counts.get(d, 0) + n
            if counts:
                d = max(counts, key=counts.__getitem__)
                top_dest[app] = (counts[d], d)
            cur, last = win.current, win.last_closed
            per_min = last if last is not None else cur
            v = self.verdicts.get(app)
            base = self.baselines.get(app)
            rows.append(AppRow(
                app, self._name(app), pids.get(app, st.process.pid if st.process else 0), open_counts.get(app, 0),
                top_dest.get(app, (0, ""))[1], max(cur.bytes_out, per_min.bytes_out),
                max(cur.bytes_in, per_min.bytes_in), v.score if v else 0, v.severity if v else Severity.NONE,
                [r.code for r in v.firing()] if v else [], v.policy if v else None,
                not (base and base.mature(now, self.cfg.engine))))
        rows.sort(key=lambda r: (-r.score, -r.conns, r.name.lower()))
        return rows
