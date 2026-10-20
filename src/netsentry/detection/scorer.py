"""Noisy-OR combination of heuristic scores plus policy overrides (doc 4.4).

    S = 1 - prod(1 - w_i * s_i)   over available heuristics;   score = round(100 * S)

A weight is "the most this signal alone can contribute"; independent signals reinforce each other.
"""

from __future__ import annotations

import math

from ..config import Config
from ..models import HeuristicResult, Verdict
from .policy import AppPolicy


def combine(results: list[HeuristicResult]) -> float:
    return 1.0 - math.prod(1.0 - min(max(r.contribution, 0.0), 1.0) for r in results)


def score(app_id: str, ts: float, results: list[HeuristicResult], pol: AppPolicy, cfg: Config,
          dest_denied: str | None = None) -> Verdict:
    s = round(100 * combine(results))
    policy: str | None = None
    blocklisted = any(r.name == "blocklist" and (r.score or 0) > 0 for r in results)
    bl_cfg = cfg.heuristics.blocklist

    # 1. deny rule
    if pol.app_action == "deny" or dest_denied:
        s, policy = max(s, 90), "denied"
    # 2. blocklist hit (user allow caps it instead of hiding it)
    elif blocklisted:
        if pol.app_action == "allow":
            s, policy = min(max(s, int(bl_cfg.get("override_min_score", 80))), int(bl_cfg.get("allowed_cap", 60))), \
                "allowed-but-blocklisted"
        else:
            s = max(s, int(bl_cfg.get("override_min_score", 80)))
    # 3. whole-app allow
    elif pol.app_action == "allow":
        s, policy = 0, "allowed"
    # 4. mute: scored and shown, but AlertManager will not open alerts
    if pol.app_action == "mute" and policy is None:
        policy = "muted"
    return Verdict(app_id, ts, s, cfg.severity.classify(s), results, policy)
