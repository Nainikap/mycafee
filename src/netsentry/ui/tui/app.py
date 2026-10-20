"""Textual dashboard: live per-app table, alert pane, detail screen, and allow/deny/mute/normal keys."""

from __future__ import annotations

import asyncio
from datetime import datetime

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Static

from ...detection.alerts import AlertEvent, app_label
from ...detection.heuristics.base import fmt_bytes
from ...models import Severity
from ...pipeline.engine import AppRow, Engine, TickResult

SEV_STYLE = {Severity.HIGH: "bold white on red", Severity.MEDIUM: "bold black on dark_orange",
             Severity.LOW: "black on yellow", Severity.NONE: ""}


def sev_text(sev: Severity) -> Text:
    return Text(f" {sev.label.upper():<6}" if sev else "", style=SEV_STYLE[sev])


def ts(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


class DetailScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,q,enter", "dismiss", "Close")]
    DEFAULT_CSS = """
    DetailScreen { align: center middle; }
    #detail { width: 92%; height: 90%; border: round $accent; background: $surface; padding: 0 1; }
    """

    def __init__(self, engine: Engine, app_id: str) -> None:
        super().__init__()
        self.engine = engine
        self.app_id = app_id

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="detail"):
            yield Static(self._render_detail())

    def _render_detail(self) -> Text:
        e, app = self.engine, self.app_id
        t = Text()
        proc = e.processes.get(app)
        v = e.verdicts.get(app)
        base = e.baselines.get(app)
        t.append(f"{app_label(app)}\n", style="bold")
        t.append(f"{app}\n", style="dim")
        if proc:
            chain = " ← ".join([f"{proc.name} ({proc.pid})"] + [n for n, _ in proc.parents])
            t.append(f"lineage: {chain}\n")
            if proc.cmdline:
                t.append(f"cmdline: {proc.cmdline[:200]}\n", style="dim")
        if base:
            mature = base.mature(e.clock.now(), e.cfg.engine)
            t.append(f"baseline: {base.n_buckets} active minutes, {len(base.known_dests)} known destinations, "
                     f"{'mature' if mature else 'learning'}\n")
        t.append("\n")
        if v:
            t.append(f"score {v.score}  ", style="bold")
            t.append_text(sev_text(v.severity))
            if v.policy:
                t.append(f"  [{v.policy}]", style="italic")
            t.append("\n\n")
            for r in sorted(v.results, key=lambda r: -r.contribution):
                if r.score is None:
                    t.append(f"  {r.code} {r.name:<16}  n/a    {r.evidence}\n", style="dim")
                else:
                    style = "bold" if r.contribution >= 0.05 else "dim"
                    t.append(f"  {r.code} {r.name:<16}  {r.score:.2f}×{r.weight:.2f}  {r.evidence}\n", style=style)
        t.append("\nopen flows\n", style="bold underline")
        flows = [f for f in e.flows.flows.values() if f.app_id == app]
        for f in sorted(flows, key=lambda f: -(f.bytes_out + f.bytes_in))[:25]:
            name = f.domain or f.raddr
            t.append(f"  {f.proto} {name}:{f.rport}  ({f.raddr})  since {ts(f.opened_at)}  "
                     f"out {fmt_bytes(f.bytes_out)} in {fmt_bytes(f.bytes_in)}"
                     + (f"  ja3n {f.ja3n[:10]}" if f.ja3n else "") + "\n")
        if not flows:
            t.append("  (none open right now)\n", style="dim")
        hist = e.store.app_history(app, int(e.clock.now() - 3600))
        if hist:
            t.append("\nlast hour (per minute)\n", style="bold underline")
            bars = "▁▂▃▄▅▆▇█"
            mx = max(r["new_flows"] or 0 for r in hist) or 1
            t.append("  connections " + "".join(bars[min(7, int((r["new_flows"] or 0) / mx * 7))] for r in hist)
                     + f"  (max {mx}/min)\n")
            mxs = max(r["score"] or 0 for r in hist)
            t.append("  score       " + "".join(bars[min(7, int((r["score"] or 0) / 100 * 7))] for r in hist)
                     + f"  (max {mxs})\n")
        t.append("\n[esc] close", style="dim")
        return t


class NetSentryApp(App[None]):
    TITLE = "NetSentry"
    CSS = """
    #status { height: 1; background: $accent-darken-2; color: $text; padding: 0 1; }
    #apps { height: 1fr; }
    #alerts-title { height: 1; background: $panel; padding: 0 1; }
    #alerts { height: 10; }
    #msg { height: 1; padding: 0 1; color: $text-muted; }
    """
    BINDINGS = [
        Binding("enter", "details", "Details"),
        Binding("a", "act('allow')", "Allow"),
        Binding("d", "act('deny')", "Deny"),
        Binding("m", "act('mute')", "Mute 1h"),
        Binding("n", "act('normal')", "This is normal"),
        Binding("k", "act('ack')", "Ack"),
        Binding("f", "toggle_filter", "Only flagged"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, engine: Engine) -> None:
        super().__init__()
        self.engine = engine
        self.only_flagged = False
        self._rows: list[AppRow] = []
        self._alert_ids: list[int] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("starting…", id="status")
            yield DataTable(id="apps", cursor_type="row", zebra_stripes=True)
            yield Static("Alerts", id="alerts-title")
            yield DataTable(id="alerts", cursor_type="row")
            yield Static("", id="msg")
        yield Footer()

    def on_mount(self) -> None:
        apps = self.query_one("#apps", DataTable)
        apps.add_columns("SEV", "SCORE", "APP", "PID", "CONNS", "TOP DESTINATION", "OUT/min", "IN/min", "WHY", "")
        alerts = self.query_one("#alerts", DataTable)
        alerts.add_columns("TIME", "SEV", "SCORE", "STATUS", "SUMMARY")
        for a in reversed(self.engine.store.recent_alerts(20)):
            self._add_alert_row(a)
        self._queue = self.engine.bus.subscribe()
        self.run_worker(self._run_engine(), exclusive=False, name="engine")
        self.run_worker(self._consume(), exclusive=False, name="ui-feed")

    async def _run_engine(self) -> None:
        try:
            await self.engine.run()
        except Exception as e:  # surface engine crashes instead of freezing the table
            self.query_one("#msg", Static).update(Text(f"engine stopped: {e!r}", style="bold red"))
            raise

    async def _consume(self) -> None:
        while True:
            res: TickResult = await self._queue.get()
            self._render_tick(res)
            await asyncio.sleep(0)

    # ------------------------------------------------------------------ rendering
    def _render_tick(self, res: TickResult) -> None:
        s = res.stats
        mode = "FULL" if s.full_mode else "STANDARD"
        learn = f"learning: {s.learning_left_s / 3600:.1f} h left" if s.learning_left_s > 0 else "baseline active"
        pcap = f" · pkts {s.pcap_recv:,}" if s.full_mode else ""
        self.query_one("#status", Static).update(
            f"{mode} MODE · {s.n_apps} apps · {s.n_flows} flows · tick {s.tick_ms:.0f} ms{pcap} · {learn}"
            f" · {ts(s.ts)}")
        if not s.full_mode and s.ticks == 1:
            self.query_one("#msg", Static).update(f"standard mode: {s.mode_reason}")

        table = self.query_one("#apps", DataTable)
        keep = self._selected_app()
        rows = [r for r in res.apps if r.score > 0] if self.only_flagged else res.apps
        self._rows = rows
        table.clear()
        for r in rows:
            name = Text(r.name, style="bold" if r.severity >= Severity.MEDIUM else "")
            tag = r.policy or ("learning" if r.learning else "")
            table.add_row(sev_text(r.severity), str(r.score) if r.score else "", name, str(r.pid or ""),
                          str(r.conns), r.top_dest[:34], fmt_bytes(r.out_per_min) if r.out_per_min else "",
                          fmt_bytes(r.in_per_min) if r.in_per_min else "", " ".join(r.codes),
                          Text(tag, style="dim italic"), key=r.app_id)
        if keep:
            for i, r in enumerate(rows):
                if r.app_id == keep:
                    table.move_cursor(row=i, animate=False)
                    break

        for ev in res.events:
            self._on_alert_event(ev)

    def _on_alert_event(self, ev: AlertEvent) -> None:
        a = ev.alert
        if ev.kind in ("opened", "escalated"):
            self._add_alert_row(a)
            self.notify(a.summary, title=f"{a.severity.label.upper()} · {app_label(a.app_id)}",
                        severity="error" if a.severity == Severity.HIGH else "warning", timeout=8)
        elif ev.kind == "resolved":
            self._add_alert_row(a)

    def _add_alert_row(self, a) -> None:  # noqa: ANN001
        table = self.query_one("#alerts", DataTable)
        table.add_row(ts(a.updated_at), sev_text(a.severity), str(a.peak_score), a.status, a.summary[:160])
        table.move_cursor(row=table.row_count - 1, animate=False)

    # ------------------------------------------------------------------ actions
    def _selected_app(self) -> str | None:
        table = self.query_one("#apps", DataTable)
        if not self._rows or table.cursor_row is None or table.cursor_row >= len(self._rows):
            return None
        return self._rows[table.cursor_row].app_id

    def action_details(self) -> None:
        app = self._selected_app()
        if app:
            self.push_screen(DetailScreen(self.engine, app))

    def action_act(self, action: str) -> None:
        app = self._selected_app()
        if not app:
            return
        msg = self.engine.user_action(action, app)
        self.query_one("#msg", Static).update(Text(f"✓ {msg} — applied on the next tick", style="green"))

    def action_toggle_filter(self) -> None:
        self.only_flagged = not self.only_flagged
        if self.engine.last_result:
            self._render_tick(self.engine.last_result)
