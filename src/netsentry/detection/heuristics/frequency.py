"""H2 · Connection frequency spike and beaconing (regular, machine-like connection intervals)."""

from __future__ import annotations

import statistics

from ...models import HeuristicResult
from ..baseline import Baseline, clamp01
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext, best


class Frequency(BaseHeuristic):
    name, code = "frequency", "H2"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        h = self.hcfg(ctx)
        cands: list[tuple[float, str]] = []
        mature = ctx.app_mature(base)

        # Rate spike vs this app's own baseline
        last = win.last_closed
        x = max(win.current.new_flows, last.new_flows if last else 0)
        if mature and base is not None and base.has("new_flows") and x >= h.get("min_new_flows", 10):
            s, z = base.dev("new_flows", x, ctx.cfg.baseline)
            cands.append((s, f"{x} new connections in 1 min; usually about {base.typical('new_flows'):.1f}/min "
                             f"(z = {z:.1f})"))

        # Beaconing: low coefficient of variation of the inter-arrival times to one remote IP
        min_events = int(h.get("beacon_min_events", 6))
        cv_full, cv_zero = float(h.get("cv_full", 0.10)), float(h.get("cv_zero", 0.35))
        min_iv = 1.0 if ctx.full_mode else float(h.get("min_interval_standard_s", 10))
        ip_dest = win.ip_dest()
        remotes = win.remotes()
        horizon = ctx.cfg.engine.bucket_s * ctx.cfg.engine.window_buckets
        for (ip, port), starts in win.starts.items():
            if len(starts) < min_events or win.now - starts[-1] > horizon:
                continue
            dest, domain = ip_dest.get(ip), remotes.get(ip)
            if ctx.policy.dest_allowed(dest, ip, domain):
                continue
            ts = sorted(starts)
            iv = [b - a for a, b in zip(ts, ts[1:], strict=False)]
            mean = statistics.fmean(iv)
            if mean < min_iv:
                continue
            sd = statistics.pstdev(iv)
            cv = sd / mean
            s = clamp01((cv_zero - cv) / (cv_zero - cv_full))
            if s <= 0:
                continue
            note = ""
            if mature and base is not None and dest in base.known_dests:
                s *= float(h.get("known_dest_factor", 0.3))
                note = " (known destination)"
            elif not ctx.system_mature:
                s *= float(h.get("known_dest_factor", 0.3))
                note = " (damped while learning)"
            cands.append((s, f"{len(ts)} connections to {domain or ip}:{port} every {mean:.1f} s ± {sd:.1f} s "
                             f"(cv {cv:.2f}){note}"))
        s, ev = best(cands)
        return self.result(ctx, s, ev)
