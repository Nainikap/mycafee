"""H1 · Unusual port usage."""

from __future__ import annotations

from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext, best


class UnusualPort(BaseHeuristic):
    name, code = "unusual_port", "H1"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        lists = ctx.lists
        mature = ctx.app_mature(base)
        ip_dest = win.ip_dest()
        remotes = win.remotes()
        cands: list[tuple[float, str]] = []
        for (proto, port), ips in win.rports().items():
            ips = {ip for ip in ips if not ctx.policy.dest_allowed(ip_dest.get(ip), ip, remotes.get(ip))}
            if not ips:
                continue
            ip = sorted(ips)[0]
            where = f"{remotes.get(ip) or ip}:{port}"
            if port in lists.suspicious_ports:
                cands.append((1.0, f"connected to {where} (suspicious port: {lists.suspicious_ports[port]})"))
            elif (proto == "tcp" and mature and base is not None and port not in lists.common_ports
                  and port not in base.known_ports):
                s = 0.6 if port >= 49152 else 0.5
                cands.append((s, f"first use of non-standard port {where} by this app"))
        if mature and base is not None:
            for lp in sorted(win.listen_ports()):
                if -lp not in base.known_ports and lp not in lists.common_ports:
                    cands.append((0.5, f"started listening on new local port {lp}"))
                    break
        s, ev = best(cands)
        return self.result(ctx, s, ev)
