"""H5 · Known-bad IP / domain. A hit is a hard override to High (doc 4.4)."""

from __future__ import annotations

from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext


class Blocklist(BaseHeuristic):
    name, code = "blocklist", "H5"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        lists = ctx.lists
        for ip, domain in win.remotes().items():
            if lists.ip_blocked(ip):
                return self.result(ctx, 1.0, f"contacted blocklisted IP {ip}" + (f" ({domain})" if domain else ""),
                                   hit=ip)
            d = lists.domain_blocked(domain)
            if d:
                return self.result(ctx, 1.0, f"contacted blocklisted domain {domain} ({ip}; list entry {d})", hit=d)
        return self.result(ctx, 0.0)
