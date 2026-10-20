"""H4 · Outbound data volume anomaly (full mode only)."""

from __future__ import annotations

from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext, fmt_bytes


class Volume(BaseHeuristic):
    name, code = "volume", "H4"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        if not ctx.full_mode:
            return self.result(ctx, None, "n/a (standard mode: no byte counts)")
        h = self.hcfg(ctx)
        ip_dest, remotes = win.ip_dest(), win.remotes()
        skip = {ip for ip in remotes if ctx.policy.dest_allowed(ip_dest.get(ip), ip, remotes.get(ip))}
        cur = win.current.bytes_out_excluding(skip)
        last = win.last_closed.bytes_out_excluding(skip) if win.last_closed else 0
        x = max(cur, last)
        src = win.current if cur >= last or win.last_closed is None else win.last_closed
        top_ip = max(src.ip_bytes_out, key=src.ip_bytes_out.__getitem__, default=None)
        to = f" to {remotes.get(top_ip) or top_ip}" if top_ip else ""
        if ctx.app_mature(base) and base is not None and base.has("bytes_out"):
            if x < float(h.get("min_bytes_out_per_min", 5_000_000)):
                return self.result(ctx, 0.0)
            s, z = base.dev("bytes_out", x, ctx.cfg.baseline)
            return self.result(ctx, s, f"uploaded {fmt_bytes(x)} in 1 min{to}; usually about "
                                       f"{fmt_bytes(base.typical('bytes_out'))}/min (z = {z:.1f})", bytes_out=x)
        if ctx.app_is_new(base) and x >= float(h.get("new_app_abs_bytes", 50_000_000)):
            return self.result(ctx, 0.7, f"new app uploaded {fmt_bytes(x)} in 1 min{to}", bytes_out=x)
        return self.result(ctx, 0.0)
