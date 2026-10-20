"""H3 · New / unrecognised destination."""

from __future__ import annotations

from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext


class NewDestination(BaseHeuristic):
    name, code = "new_destination", "H3"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        h = self.hcfg(ctx)
        if not ctx.system_mature:
            return self.result(ctx, None, "NetSentry is still learning; destinations are recorded silently")
        bonus, lan = float(h.get("direct_ip_bonus", 0.2)), float(h.get("lan_factor", 0.5))
        dests = {d: i for d, i in win.dests().items()
                 if not ctx.policy.dest_allowed(d, None, i.domain)
                 and (base is None or d not in base.known_dests)}
        if not dests:
            return self.result(ctx, 0.0)
        nameless = [i for i in dests.values() if not i.has_name]
        all_lan = all(i.ip_class == "private" for i in dests.values())
        sample = sorted(dests.values(), key=lambda i: i.has_name)[0].example
        if ctx.app_mature(base):
            s = min(0.8, 0.5 + 0.1 * (len(dests) - 1))
            ev = (f"first contact with {sample}" if len(dests) == 1
                  else f"{len(dests)} never-seen destinations, e.g. {sample}")
        elif ctx.app_is_new(base):
            s = 0.5
            ev = f"first time this app has used the network ({sample})"
        else:
            return self.result(ctx, None, "this app's baseline is still learning")
        if nameless:
            s += bonus
            ev += "; direct-to-IP, no DNS name"
        if all_lan:
            s *= lan
            ev += " (LAN)"
        return self.result(ctx, min(s, 1.0), ev, new=len(dests))
