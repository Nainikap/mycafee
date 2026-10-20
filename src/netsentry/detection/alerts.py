"""Alert lifecycle: open -> (acked) -> resolved | false_positive. One active alert per app per incident."""

from __future__ import annotations

from dataclasses import dataclass

from ..config import SeverityCfg
from ..models import Alert, Verdict
from ..storage.db import Store


@dataclass(slots=True)
class AlertEvent:
    kind: str  # opened | escalated | resolved
    alert: Alert


def app_label(app_id: str) -> str:
    return app_id.replace("/", "\\").rsplit("\\", 1)[-1]


def summarize(app_id: str, v: Verdict) -> str:
    ev = [r.evidence for r in v.firing() if r.evidence][:2]
    return f"{app_label(app_id)}: " + "; ".join(ev) if ev else f"{app_label(app_id)}: score {v.score}"


class AlertManager:
    """While an app stays at or above ``alert_min``, its alert is updated in place (peak score, top
    heuristic, evidence). It resolves after ``resolve_after_s`` below threshold. If the same app flares up
    again within ``dedupe_cooldown_s`` of resolving, the old alert is reopened instead of a new one."""

    def __init__(self, store: Store, cfg: SeverityCfg) -> None:
        self.store = store
        self.cfg = cfg
        self.active: dict[str, Alert] = {}
        self.last_above: dict[str, float] = {}
        self.recent_closed: dict[str, Alert] = {}
        for a in store.load_alerts(("open", "acked")):
            self.active[a.app_id] = a
            self.last_above[a.app_id] = a.updated_at

    def by_id(self, alert_id: int) -> Alert | None:
        return next((a for a in self.active.values() if a.id == alert_id), None)

    def latest_for_app(self, app_id: str) -> Alert | None:
        return self.active.get(app_id)

    def process(self, verdicts: list[Verdict], now: float) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        for v in verdicts:
            if v.severity < self.cfg.alert_min_severity or v.policy in ("muted", "allowed"):
                continue
            top = v.top
            if top is None:
                continue
            self.last_above[v.app_id] = now
            evidence = [r.to_json() for r in v.results]
            a = self.active.get(v.app_id)
            if a is None:
                old = self.recent_closed.pop(v.app_id, None)
                if old is not None and now - (old.resolved_at or 0) < self.cfg.dedupe_cooldown_s:
                    a = old
                    a.status, a.resolved_at, a.updated_at = "open", None, now
                    self.active[v.app_id] = a
                    self._raise_peak(a, v, evidence)
                    self.store.update_alert(a)
                    events.append(AlertEvent("opened", a))
                    continue
                a = Alert(None, v.app_id, now, now, "open", v.severity, v.score, top.code,
                          summarize(v.app_id, v), evidence)
                a.id = self.store.insert_alert(a)
                self.active[v.app_id] = a
                events.append(AlertEvent("opened", a))
                continue
            a.updated_at = now
            before = a.severity
            if self._raise_peak(a, v, evidence) and a.severity > before:
                events.append(AlertEvent("escalated", a))
            self.store.update_alert(a)
        events.extend(self._resolve_stale(now))
        return events

    @staticmethod
    def _raise_peak(a: Alert, v: Verdict, evidence: list[dict]) -> bool:
        """Keep the evidence of the strongest moment; at an equal score, refresh it with the latest numbers."""
        if v.score < a.peak_score:
            return False
        rose = v.score > a.peak_score
        top = v.top
        a.peak_score, a.severity = v.score, max(a.severity, v.severity)
        a.top_heuristic = top.code if top else a.top_heuristic
        a.summary, a.evidence = summarize(v.app_id, v), evidence
        return rose

    def _resolve_stale(self, now: float) -> list[AlertEvent]:
        out = []
        for app, a in list(self.active.items()):
            if now - self.last_above.get(app, a.updated_at) >= self.cfg.resolve_after_s:
                a.status, a.resolved_at, a.updated_at = "resolved", now, now
                self.store.update_alert(a)
                del self.active[app]
                self.recent_closed[app] = a
                out.append(AlertEvent("resolved", a))
        return out

    def set_status(self, alert_id: int, status: str, now: float) -> Alert | None:
        for app, a in list(self.active.items()):
            if a.id == alert_id:
                a.status, a.updated_at = status, now
                if status in ("false_positive", "resolved"):
                    a.resolved_at = now
                    del self.active[app]
                self.store.update_alert(a)
                return a
        return None
