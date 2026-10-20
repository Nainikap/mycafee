"""H6 · Off-hours activity: significant traffic while the user is away or at unusual hours (amplifier)."""

from __future__ import annotations

from ...config import parse_hhmm
from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext, fmt_bytes


def in_quiet_hours(hour: int, quiet: list[str]) -> bool:
    if len(quiet) != 2:
        return False
    start, end = parse_hhmm(quiet[0]).hour, parse_hhmm(quiet[1]).hour
    return start <= hour < end if start <= end else hour >= start or hour < end


class OffHours(BaseHeuristic):
    name, code = "off_hours", "H6"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        h = self.hcfg(ctx)
        b = win.current
        if b.new_flows < int(h.get("min_new_flows", 3)) and b.bytes_out < int(h.get("min_bytes_out", 1_000_000)):
            return self.result(ctx, 0.0)
        idle = ctx.idle_s >= float(h.get("idle_threshold_s", 600))
        hour = ctx.hour
        quiet = in_quiet_hours(hour, list(h.get("quiet_hours", [])))
        unusual = False
        if not quiet and ctx.app_mature(base) and base is not None:
            total = sum(base.hour_hist)
            unusual = total >= 60 and base.hour_hist[hour] / total < float(h.get("min_hour_share", 0.02))
        odd_time = quiet or unusual
        if not (idle or odd_time):
            return self.result(ctx, 0.0)
        what = f"{b.new_flows} connections" + (f", {fmt_bytes(b.bytes_out)} out" if b.bytes_out else "")
        parts = []
        if idle:
            parts.append(f"user idle for {ctx.idle_s / 60:.0f} min")
        if quiet:
            parts.append(f"{hour:02d}:00 is inside quiet hours")
        elif unusual:
            parts.append(f"this app is rarely active at {hour:02d}:00")
        return self.result(ctx, 1.0 if idle and odd_time else 0.6, f"{what} while " + " and ".join(parts))
