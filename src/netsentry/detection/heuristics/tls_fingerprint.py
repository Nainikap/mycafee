"""H8 · TLS client fingerprint (JA3/JA3N) novelty or known-bad match (full mode only)."""

from __future__ import annotations

from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from .base import BaseHeuristic, HeuristicContext


class TlsFingerprint(BaseHeuristic):
    name, code = "tls_fingerprint", "H8"

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult:
        if not ctx.full_mode:
            return self.result(ctx, None, "n/a (standard mode: no TLS visibility)")
        seen = win.ja3()
        for ja3n, ja3 in seen.items():
            if ja3n in ctx.lists.bad_ja3 or ja3 in ctx.lists.bad_ja3:
                return self.result(ctx, 1.0, f"TLS fingerprint {ja3} is on the known-bad JA3 list")
        if ctx.app_mature(base) and base is not None and base.known_ja3n:
            new = [j for j in seen if j not in base.known_ja3n]
            if new:
                return self.result(ctx, 0.5, f"new TLS client fingerprint {new[0][:12]}…; this app's TLS stack "
                                             f"changed (known fingerprints: {len(base.known_ja3n)})")
        return self.result(ctx, 0.0)
