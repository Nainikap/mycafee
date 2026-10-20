"""H7 · Suspicious process lineage and context (masquerading, Office -> script host, staging paths)."""

from __future__ import annotations

from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext, best


def _dir(exe: str) -> str:
    return exe[: exe.rfind("\\") + 1] if "\\" in exe else ""


class Lineage(BaseHeuristic):
    name, code = "lineage", "H7"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        p = win.process
        if p is None or not p.name:
            return self.result(ctx, None, "process details unavailable")
        allowed_cls = {"public", "private"} if ctx.cfg.engine.include_lan else {"public"}
        if not any(i.ip_class in allowed_cls for i in win.dests().values()):
            return self.result(ctx, 0.0)
        lists = ctx.lists
        name, exe = p.name.lower(), p.exe.lower()
        parents = [n.lower() for n, _ in p.parents]
        chain = " → ".join([n for n, _ in reversed(p.parents[:2])] + [p.name])
        cands: list[tuple[float, str]] = []
        if name in lists.system_binaries and exe and _dir(exe) not in lists.system_dirs:
            cands.append((1.0, f"{p.name} is running from {p.exe}, not the Windows system folder (masquerading)"))
        if name in lists.script_hosts:
            bad_parent = next((q for q in parents[:2] if q in lists.suspicious_parents), None)
            if bad_parent:
                cands.append((1.0, f"{chain}: a document/browser process spawned a script host that went online"))
            else:
                cands.append((0.5, f"script host {p.name} made a network connection ({chain})"))
        if exe and any(s in exe for s in lists.staging_paths):
            cands.append((0.6, f"running from a user-writable staging folder: {p.exe}"))
        s, ev = best(cands)
        return self.result(ctx, s, ev)
