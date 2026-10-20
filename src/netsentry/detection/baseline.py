"""Per-app behavioural baselines: EWMA of bucket features plus known destinations/ports/JA3 (doc 4.2)."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from ..config import BaselineCfg, EngineCfg
from .features import Bucket

EWMA_FEATURES = ("new_flows", "unique_dests", "bytes_out")


def clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


@dataclass(slots=True)
class Baseline:
    app_id: str
    first_seen: float
    n_buckets: int = 0
    ewma: dict[str, list[float]] = field(default_factory=dict)  # feature -> [mean, var] of log1p(x)
    known_dests: dict[str, list[float]] = field(default_factory=dict)  # dest -> [first_seen, hits]
    known_ports: set[int] = field(default_factory=set)  # remote ports; local LISTEN ports stored negated
    known_ja3n: set[str] = field(default_factory=set)
    hour_hist: list[int] = field(default_factory=lambda: [0] * 24)
    talker: bool = True
    updated_at: float = 0.0
    dirty: bool = True

    def mature(self, now: float, eng: EngineCfg) -> bool:
        return self.n_buckets >= eng.min_buckets_mature and now - self.first_seen >= eng.learning_period_h * 3600

    def has(self, feature: str) -> bool:
        return feature in self.ewma

    def z(self, feature: str, x: float, cfg: BaselineCfg) -> float:
        mean, var = self.ewma.get(feature, (0.0, 0.0))
        return (math.log1p(x) - mean) / max(math.sqrt(var), cfg.min_std)

    def dev(self, feature: str, x: float, cfg: BaselineCfg) -> tuple[float, float]:
        """(score 0..1, z) — 0 at z <= z_lo, 1 at z >= z_hi, linear between."""
        z = self.z(feature, x, cfg)
        return clamp01((z - cfg.z_lo) / (cfg.z_hi - cfg.z_lo)), z

    def typical(self, feature: str) -> float:
        """Back-transformed EWMA mean, for evidence strings."""
        return math.expm1(self.ewma.get(feature, (0.0, 0.0))[0])

    def fold(self, b: Bucket, alpha: float, hour: int, full_mode: bool, now: float | None = None) -> None:
        """Fold one closed bucket into the baseline."""
        if b.folded or not b.active:
            return
        b.folded = True
        values = {"new_flows": b.new_flows, "unique_dests": len(b.dests)}
        if full_mode:
            values["bytes_out"] = b.bytes_out
        for feat, x in values.items():
            v = math.log1p(x)
            cur = self.ewma.get(feat)
            if cur is None:
                self.ewma[feat] = [v, 0.0]
            else:
                mean, var = cur
                diff = v - mean
                mean += alpha * diff
                var = (1 - alpha) * (var + alpha * diff * diff)
                self.ewma[feat] = [mean, var]
        self.n_buckets += 1
        self.hour_hist[hour] += 1
        self.add_known(b, now if now is not None else b.minute_ts)
        self.updated_at = now if now is not None else time.time()
        self.dirty = True

    def add_known(self, b: Bucket, ts: float) -> None:
        for d, n in b.dests.items():
            e = self.known_dests.get(d)
            if e is None:
                self.known_dests[d] = [ts, n]
            else:
                e[1] += n
        self.known_ports.update(p for (_proto, p) in b.rports)
        self.known_ports.update(-p for p in b.listen_ports)
        self.known_ja3n.update(b.ja3)
        self.dirty = True

    @classmethod
    def from_row(cls, r: dict[str, Any]) -> Baseline:
        return cls(r["app_id"], r["first_seen"], r["n_buckets"], r["ewma"], r["known_dests"], r["known_ports"],
                   r["known_ja3n"], r["hour_hist"], r["talker"], r["updated_at"], dirty=False)
