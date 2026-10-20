"""End-to-end: the synthetic scenario through the real engine with a fake clock and in-memory DB."""

import pytest

from netsentry.bus import EventBus
from netsentry.capture.source import ListSource
from netsentry.clock import FakeClock
from netsentry.config import DEFAULT_CONFIG_DIR, load_config
from netsentry.demo import Scenario
from netsentry.models import Severity
from netsentry.pipeline.engine import Engine
from netsentry.storage.db import Store


async def run_scenario(full_mode: bool = True, stop_after: float | None = None) -> Engine:
    ticks = Scenario(full_mode=full_mode).build()
    if stop_after is not None:
        ticks = [t for t in ticks if t.ts < ticks[0].ts + stop_after]
    clock = FakeClock()
    engine = Engine(ListSource(ticks, clock), Store(":memory:"), load_config(DEFAULT_CONFIG_DIR, "demo"),
                    EventBus(), clock, rdns=False)
    await engine.run()
    return engine


def alerts_by_app(engine: Engine) -> dict[str, object]:
    return {a.app_id.rsplit("\\", 1)[-1]: a for a in engine.store.recent_alerts(100)}


@pytest.mark.asyncio
async def test_full_mode_catches_every_attack_and_nothing_else() -> None:
    engine = await run_scenario()
    got = alerts_by_app(engine)
    assert set(got) == {"updater.exe", "onedrive.exe", "chrome.exe", "powershell.exe"}
    assert got["updater.exe"].severity == Severity.HIGH  # beacon on :4444 from %TEMP%
    assert got["chrome.exe"].severity == Severity.HIGH and "blocklisted" in got["chrome.exe"].summary
    assert got["powershell.exe"].severity == Severity.MEDIUM and "WINWORD" in got["powershell.exe"].summary
    assert got["onedrive.exe"].severity >= Severity.MEDIUM and "uploaded" in got["onedrive.exe"].summary
    assert "ms-teams.exe" not in got  # its 60 s heartbeat is regular but to a known destination


@pytest.mark.asyncio
async def test_standard_mode_degrades_gracefully() -> None:
    engine = await run_scenario(full_mode=False)
    got = alerts_by_app(engine)
    assert "updater.exe" in got and "chrome.exe" in got and "powershell.exe" in got
    assert "onedrive.exe" not in got  # no byte counts without packet capture → no volume alert
    v = engine.verdicts.get("c:\\program files\\google\\chrome\\application\\chrome.exe")
    if v is not None:
        assert next(r for r in v.results if r.name == "volume").score is None


@pytest.mark.asyncio
async def test_learning_period_is_quiet() -> None:
    engine = await run_scenario(stop_after=11 * 60)  # before any attack starts
    assert engine.store.recent_alerts(10) == []


@pytest.mark.asyncio
async def test_baselines_and_history_persist() -> None:
    engine = await run_scenario(stop_after=8 * 60)
    rows = engine.store.load_baseline_rows()
    assert any(r["app_id"].endswith("chrome.exe") and r["n_buckets"] >= 5 for r in rows)
    hist = engine.store.app_history("c:\\program files\\google\\chrome\\application\\chrome.exe", 0)
    assert len(hist) >= 6


@pytest.mark.asyncio
async def test_this_is_normal_closes_alert_and_teaches_baseline() -> None:
    engine = await run_scenario(stop_after=(12 + 6) * 60 + 30)  # 30 s into the exfil
    app = "c:\\users\\user\\appdata\\local\\microsoft\\onedrive\\onedrive.exe"
    alert = engine.alerts.latest_for_app(app)
    assert alert is not None
    engine.user_action("normal", app)
    assert engine.alerts.latest_for_app(app) is None
    assert engine.store.recent_alerts(10, "false_positive")[0].id == alert.id
    assert "185.199.110.0/24" in engine.baselines[app].known_dests
