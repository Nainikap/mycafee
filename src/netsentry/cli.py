"""Command line: run | demo | record | replay | capture | status | alerts | allow | deny | mute | rules | export | doctor."""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .bus import EventBus
from .clock import FakeClock, SystemClock
from .config import DEFAULT_CONFIG_DIR, data_dir, load_config
from .models import PolicyRule, Severity

for _stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; evidence uses → ± ≈
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="NetSentry: on-device network behaviour monitor for applications.")
console = Console()

DbOpt = Annotated[Path | None, typer.Option("--db", help="SQLite database path (default: %LOCALAPPDATA%\\NetSentry)")]
ConfigOpt = Annotated[Path, typer.Option("--config", help="Config folder with rules.yaml etc.")]
ProfileOpt = Annotated[str, typer.Option("--profile", help="default | demo")]
UiOpt = Annotated[str, typer.Option("--ui", help="tui | none")]


def _db_path(db: Path | None) -> Path:
    return db or data_dir() / "netsentry.db"


def _setup_logging(console_too: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fh = RotatingFileHandler(data_dir() / "netsentry.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(fh)
    if console_too:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        root.addHandler(sh)


def _run_engine(engine, ui: str) -> None:  # noqa: ANN001
    if ui == "tui":
        from .ui.tui.app import NetSentryApp

        NetSentryApp(engine).run()
        engine.flush_all()
        return

    async def headless() -> None:
        q = engine.bus.subscribe()
        task = asyncio.create_task(engine.run())
        last_line = 0.0
        while not task.done():
            try:
                res = await asyncio.wait_for(q.get(), 1.0)
            except TimeoutError:
                continue
            for ev in res.events:
                if ev.kind in ("opened", "escalated", "resolved"):
                    a = ev.alert
                    style = "bold red" if a.severity == Severity.HIGH else "yellow"
                    console.print(f"[{style}]{ev.kind.upper():9} {a.severity.label.upper():6} {a.peak_score:3}[/] "
                                  f"{a.summary}")
            if res.stats.ts - last_line >= 30:
                last_line = res.stats.ts
                flagged = sum(1 for r in res.apps if r.severity >= Severity.LOW)
                console.print(f"[dim]{time.strftime('%H:%M:%S', time.localtime(res.stats.ts))} "
                              f"{res.stats.n_apps} apps, {res.stats.n_flows} flows, {flagged} flagged, "
                              f"tick {res.stats.tick_ms:.0f} ms[/]")
        await task

    try:
        asyncio.run(headless())
    except KeyboardInterrupt:
        engine.flush_all()


def _build_engine(source, db: Path | str, config: Path, profile: str, clock, rdns: bool, recorder=None):  # noqa: ANN001
    from .pipeline.engine import Engine
    from .storage.db import Store

    cfg = load_config(config, profile)
    return Engine(source, Store(db), cfg, EventBus(), clock, config, profile, rdns=rdns, recorder=recorder)


@app.command()
def run(ui: UiOpt = "tui", profile: ProfileOpt = "default", db: DbOpt = None, config: ConfigOpt = DEFAULT_CONFIG_DIR,
        no_sniff: Annotated[bool, typer.Option("--no-sniff", help="Skip packet capture (standard mode)")] = False,
        iface: Annotated[str | None, typer.Option(help="Capture interface (default: Scapy's default route)")] = None,
        record: Annotated[Path | None, typer.Option(help="Also record raw ticks to this JSONL file")] = None) -> None:
    """Monitor this machine live."""
    from .capture.source import LiveSource, Recorder

    _setup_logging(ui != "tui")
    cfg = load_config(config, profile)
    src = LiveSource(sniff=not no_sniff, iface=iface, ignore_loopback=cfg.engine.ignore_loopback)
    engine = _build_engine(src, _db_path(db), config, profile, SystemClock(), rdns=True,
                           recorder=Recorder(record) if record else None)
    _run_engine(engine, ui)


@app.command()
def record(out: Annotated[Path, typer.Option("--out", help="JSONL file to write")],
           minutes: Annotated[float, typer.Option(help="How long to record")] = 10.0,
           no_sniff: Annotated[bool, typer.Option("--no-sniff")] = False) -> None:
    """Record raw capture ticks (no scoring) for later replay."""
    from .capture.source import LiveSource, Recorder

    async def go() -> None:
        src = LiveSource(sniff=not no_sniff)
        await src.start()
        console.print(f"recording in {'FULL' if src.full_mode else 'STANDARD'} mode ({src.mode_reason}) → {out}")
        rec = Recorder(out)
        end = time.time() + minutes * 60
        n = 0
        try:
            while time.time() < end:
                t0 = time.time()
                rec.write(await src.sample())
                n += 1
                await asyncio.sleep(max(0, 2 - (time.time() - t0)))
        finally:
            rec.close()
            await src.stop()
            console.print(f"wrote {n} ticks")

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        pass


@app.command()
def replay(file: Path, speed: Annotated[float, typer.Option(help="Playback speed; 0 = as fast as possible")] = 0,
           ui: UiOpt = "none", profile: ProfileOpt = "default",
           db: Annotated[str, typer.Option("--db", help="Database (default: in-memory)")] = ":memory:",
           config: ConfigOpt = DEFAULT_CONFIG_DIR) -> None:
    """Feed a recording through the full pipeline with a simulated clock."""
    from .capture.source import ReplaySource

    _setup_logging(False)
    clock = FakeClock(speed=speed or None)
    engine = _build_engine(ReplaySource(file, clock), db, config, profile, clock, rdns=False)
    _run_engine(engine, ui)
    _print_alerts(engine.store.recent_alerts(50))


@app.command()
def demo(ui: UiOpt = "tui", speed: Annotated[float, typer.Option(help="Playback speed")] = 10,
         out: Annotated[Path | None, typer.Option(help="Only write the scenario to this JSONL and exit")] = None,
         config: ConfigOpt = DEFAULT_CONFIG_DIR) -> None:
    """Play a synthetic attack scenario (beacon, exfiltration, blocklist hit, Word→PowerShell)."""
    from .capture.source import ListSource, Recorder
    from .demo import Scenario

    ticks = Scenario().build()
    if out:
        rec = Recorder(out)
        for t in ticks:
            rec.write(t)
        rec.close()
        console.print(f"wrote {len(ticks)} ticks to {out}")
        return
    _setup_logging(False)
    clock = FakeClock(speed=speed or None)
    engine = _build_engine(ListSource(ticks, clock), ":memory:", config, "demo", clock, rdns=False)
    _run_engine(engine, ui)
    if ui == "none":
        _print_alerts(engine.store.recent_alerts(50))


@app.command()
def capture(dump: Annotated[bool, typer.Option("--dump", help="Print one snapshot of attributed connections")] = True,
            no_sniff: Annotated[bool, typer.Option("--no-sniff")] = True) -> None:
    """Print what the capture layer sees right now (compare with `netstat -ano`)."""
    from .capture.source import LiveSource

    async def go() -> None:
        src = LiveSource(sniff=not no_sniff)
        await src.start()
        tick = await src.sample()
        if src.full_mode:
            await asyncio.sleep(3)
            tick = await src.sample()
        await src.stop()
        t = Table(title=f"{len(tick.sockets)} connections · {'FULL' if src.full_mode else 'STANDARD'} mode")
        for c in ("PID", "PROCESS", "PROTO", "LOCAL", "REMOTE", "STATE", "PARENT"):
            t.add_column(c)
        for s in sorted(tick.sockets, key=lambda s: (tick.processes[s.pid].name.lower(), s.raddr)):
            p = tick.processes[s.pid]
            t.add_row(str(s.pid), p.name, s.proto, f"{s.laddr}:{s.lport}", f"{s.raddr}:{s.rport}", s.status,
                      p.parents[0][0] if p.parents else "")
        console.print(t)
        if tick.packets:
            console.print(f"{len(tick.packets)} packet flows, {len(tick.dns)} DNS answers, {len(tick.tls)} TLS hellos")

    asyncio.run(go())


@app.command()
def status(db: DbOpt = None, hours: float = 1.0) -> None:
    """Per-app summary from the database."""
    from .storage.db import Store

    store = Store(_db_path(db))
    t = Table(title=f"apps in the last {hours:g} h")
    for c in ("APP", "FLOWS", "DESTS", "OUT", "IN"):
        t.add_column(c)
    from .detection.heuristics.base import fmt_bytes

    for r in store.app_summary(time.time() - hours * 3600)[:40]:
        t.add_row(r["app_id"][-60:], str(r["flows"]), str(r["dests"]), fmt_bytes(r["out"] or 0),
                  fmt_bytes(r["inb"] or 0))
    console.print(t)
    _print_alerts(store.recent_alerts(10))


def _print_alerts(alerts) -> None:  # noqa: ANN001
    if not alerts:
        console.print("[dim]no alerts[/]")
        return
    t = Table(title="alerts")
    for c in ("ID", "OPENED", "SEV", "PEAK", "STATUS", "SUMMARY"):
        t.add_column(c, overflow="fold")
    for a in alerts:
        t.add_row(str(a.id), time.strftime("%m-%d %H:%M:%S", time.localtime(a.opened_at)), a.severity.label,
                  str(a.peak_score), a.status, a.summary)
    console.print(t)


@app.command()
def alerts(db: DbOpt = None, status_: Annotated[str | None, typer.Option("--status")] = None,
           as_json: Annotated[bool, typer.Option("--json")] = False, limit: int = 50) -> None:
    """List alerts."""
    from .storage.db import Store

    rows = Store(_db_path(db)).recent_alerts(limit, status_)
    if as_json:
        print(json.dumps([{"id": a.id, "app_id": a.app_id, "opened_at": a.opened_at, "status": a.status,
                           "severity": a.severity.label, "peak_score": a.peak_score, "summary": a.summary,
                           "evidence": a.evidence} for a in rows], indent=2))
    else:
        _print_alerts(rows)


def _add_rule(action: str, app_: str | None, dest: str | None, minutes: float | None, db: Path | None) -> None:
    from .storage.db import Store

    if not app_ and not dest:
        raise typer.BadParameter("give --app and/or --dest")
    scope = "app+dest" if app_ and dest else "app" if app_ else "dest"
    now = time.time()
    store = Store(_db_path(db))
    rid = store.add_rule(PolicyRule(None, scope, action, app_.lower() if app_ else None, dest, now,
                                    now + minutes * 60 if minutes else None, "cli"))
    store.user_action(now, None, f"{action}_{scope}", f"app={app_} dest={dest}")
    console.print(f"rule #{rid}: {action} {scope} app={app_} dest={dest}"
                  + (f" for {minutes:g} min" if minutes else "") + " (a running engine picks it up within 10 s)")


AppArg = Annotated[str | None, typer.Option("--app", help="exe path or name, e.g. onedrive.exe")]
DestArg = Annotated[str | None, typer.Option("--dest", help="domain, IP or CIDR")]


@app.command()
def allow(app_: AppArg = None, dest: DestArg = None, minutes: float | None = None, db: DbOpt = None) -> None:
    """Trust an app, a destination, or a destination for one app."""
    _add_rule("allow", app_, dest, minutes, db)


@app.command()
def deny(app_: AppArg = None, dest: DestArg = None, minutes: float | None = None, db: DbOpt = None) -> None:
    """Always flag an app / destination as High."""
    _add_rule("deny", app_, dest, minutes, db)


@app.command()
def mute(app_: AppArg = None, dest: DestArg = None, minutes: float = 60, db: DbOpt = None) -> None:
    """Score but don't alert for a while."""
    _add_rule("mute", app_, dest, minutes, db)


@app.command()
def rules(db: DbOpt = None, delete: Annotated[int | None, typer.Option(help="Delete rule by id")] = None) -> None:
    """List (or delete) allow/deny/mute rules."""
    from .storage.db import Store

    store = Store(_db_path(db))
    if delete is not None:
        store.delete_rule(delete)
        console.print(f"deleted rule #{delete}")
        return
    t = Table(title="policy rules")
    for c in ("ID", "ACTION", "SCOPE", "APP", "DEST", "EXPIRES"):
        t.add_column(c)
    for r in store.list_rules():
        t.add_row(str(r.id), r.action, r.scope, r.app_id or "", r.dest or "",
                  time.strftime("%m-%d %H:%M", time.localtime(r.expires_at)) if r.expires_at else "never")
    console.print(t)


@app.command()
def export(since_hours: Annotated[float, typer.Option("--since-hours")] = 24,
           fmt: Annotated[str, typer.Option("--format", help="csv | json")] = "csv",
           what: Annotated[str, typer.Option(help="flows | alerts")] = "alerts", db: DbOpt = None,
           out: Annotated[Path | None, typer.Option()] = None) -> None:
    """Export flows or alerts for the report."""
    from .storage.db import Store

    store = Store(_db_path(db))
    since = time.time() - since_hours * 3600
    if what == "flows":
        rows = [dict(r) for r in store.flows_since(since)]
    else:
        rows = [{"id": a.id, "app_id": a.app_id, "opened_at": a.opened_at, "updated_at": a.updated_at,
                 "status": a.status, "severity": a.severity.label, "peak_score": a.peak_score,
                 "top_heuristic": a.top_heuristic, "summary": a.summary}
                for a in store.recent_alerts(100_000) if a.updated_at >= since]
    fh = out.open("w", newline="", encoding="utf-8") if out else sys.stdout
    if fmt == "json":
        json.dump(rows, fh, indent=2)
    elif rows:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    if out:
        fh.close()
        console.print(f"wrote {len(rows)} rows to {out}")


@app.command()
def doctor(config: ConfigOpt = DEFAULT_CONFIG_DIR, db: DbOpt = None) -> None:
    """Check admin rights, Npcap, psutil access, config and database."""
    import psutil

    from .capture.idle import idle_seconds, is_admin
    from .config import StaticLists
    from .storage.db import Store

    ok = "[green]✓[/]"
    bad = "[red]✗[/]"
    warn = "[yellow]![/]"
    console.print(f"{ok} Python {sys.version.split()[0]} on {sys.platform}")
    admin = is_admin()
    console.print(f"{ok if admin else warn} administrator: {admin}"
                  + ("" if admin else " → standard mode (run an elevated terminal for full mode)"))
    npcap = Path(r"C:\Windows\System32\Npcap")
    console.print(f"{ok if npcap.exists() else warn} Npcap: {'installed' if npcap.exists() else 'not found'}")
    try:
        import scapy  # noqa: F401

        console.print(f"{ok} scapy importable")
    except Exception as e:
        console.print(f"{bad} scapy: {e}")
    try:
        n = len(psutil.net_connections("inet"))
        console.print(f"{ok} socket table readable ({n} entries)")
    except Exception as e:
        console.print(f"{bad} socket table: {e}")
    console.print(f"{ok} idle detection: user idle {idle_seconds():.0f} s")
    try:
        cfg = load_config(config)
        lists = StaticLists(config)
        console.print(f"{ok} config valid ({config}): {sum(1 for h in cfg.heuristics.__dict__.values() if h.enabled)}"
                      f"/8 heuristics on, {len(lists.bad_nets)} bad IPs, {len(lists.bad_domains)} bad domains")
    except Exception as e:
        console.print(f"{bad} config: {e}")
    p = _db_path(db)
    try:
        s = Store(p)
        first = s.meta_get("system_first_seen")
        console.print(f"{ok} database {p}" + (f" (learning since {time.ctime(float(first))})" if first else ""))
    except Exception as e:
        console.print(f"{bad} database {p}: {e}")


if __name__ == "__main__":
    app()
