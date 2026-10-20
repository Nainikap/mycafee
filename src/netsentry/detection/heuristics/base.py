"""Shared types for heuristics. Every heuristic is pure: (window, baseline, ctx) -> HeuristicResult."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from ...config import Config, HCfg, StaticLists
from ...models import HeuristicResult
from ..baseline import Baseline
from ..features import AppWindow
from ..policy import AppPolicy


@dataclass(frozen=True, slots=True)
class HeuristicContext:
    now: float
    full_mode: bool
    system_mature: bool
    system_matured_at: float  # wall time at which the system finished (or will finish) learning
    idle_s: float
    lists: StaticLists
    cfg: Config
    policy: AppPolicy

    @property
    def hour(self) -> int:
        return datetime.fromtimestamp(self.now).hour

    def app_mature(self, base: Baseline | None) -> bool:
        return base is not None and base.mature(self.now, self.cfg.engine)

    def app_is_new(self, base: Baseline | None) -> bool:
        """First seen after NetSentry finished learning, and not yet mature itself (doc 4.2)."""
        return (self.system_mature and base is not None and base.first_seen >= self.system_matured_at
                and not self.app_mature(base))


class Heuristic(Protocol):
    name: str
    code: str

    def evaluate(self, win: AppWindow, base: Baseline | None, ctx: HeuristicContext) -> HeuristicResult: ...


class BaseHeuristic:
    name = ""
    code = ""

    def hcfg(self, ctx: HeuristicContext) -> HCfg:
        return getattr(ctx.cfg.heuristics, self.name)

    def result(self, ctx: HeuristicContext, score: float | None, evidence: str = "", **data: object
               ) -> HeuristicResult:
        return HeuristicResult(self.name, self.code, self.hcfg(ctx).weight, score, evidence, dict(data))


def best(cands: list[tuple[float, str]]) -> tuple[float, str]:
    """Max over sub-rules; ties keep the first evidence."""
    return max(cands, key=lambda c: c[0]) if cands else (0.0, "")


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} GB"
