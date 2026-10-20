"""Builders for synthetic windows, baselines and contexts used across the unit tests."""

from __future__ import annotations

from collections import deque

from netsentry.config import DEFAULT_CONFIG_DIR, Config, StaticLists, load_config
from netsentry.detection.baseline import Baseline
from netsentry.detection.features import AppWindow, Bucket, DestInfo
from netsentry.detection.heuristics import HeuristicContext
from netsentry.detection.policy import AppPolicy
from netsentry.models import ProcessInfo

NOW = 1_760_000_000.0  # a weekday afternoon (local time varies; tests that need an hour set it explicitly)
CFG: Config = load_config(DEFAULT_CONFIG_DIR)
LISTS = StaticLists(DEFAULT_CONFIG_DIR)


def proc(name: str = "app.exe", exe: str = "C:\\Program Files\\App\\app.exe",
         parents: tuple[tuple[str, str], ...] = (("explorer.exe", "C:\\Windows\\explorer.exe"),)) -> ProcessInfo:
    return ProcessInfo(100, 1.0, name, exe, exe.lower(), "u", exe, parents)


def bucket(minute_offset: int = 0, **kw) -> Bucket:  # noqa: ANN003
    b = Bucket("app", int(NOW // 60 * 60) + 60 * minute_offset)
    for k, v in kw.items():
        setattr(b, k, v)
    return b


def add_dest(b: Bucket, dest: str, ip: str, port: int = 443, domain: str | None = None, cls: str = "public",
             proto: str = "tcp") -> Bucket:
    b.dests[dest] += 1
    b.remotes[ip] = domain
    b.ip_dest[ip] = dest
    b.rports.setdefault((proto, port), set()).add(ip)
    b.dest_info[dest] = DestInfo(cls, domain is not None, domain, f"{domain or ip}:{port}")
    return b


def window(*buckets: Bucket, process: ProcessInfo | None = None, starts: dict | None = None,
           now: float = NOW) -> AppWindow:
    bs = list(buckets) or [bucket()]
    return AppWindow("app", bs, process or proc(), {k: deque(v) for k, v in (starts or {}).items()}, now)


def mature_baseline(**kw) -> Baseline:  # noqa: ANN003
    b = Baseline("app", NOW - 7 * 86400, n_buckets=500)
    b.ewma = {"new_flows": [0.7, 0.04], "unique_dests": [0.7, 0.04], "bytes_out": [11.0, 0.5]}  # ~60 KB/min
    b.known_dests = {"example.com": [NOW - 86400, 50]}
    b.known_ports = {443}
    for k, v in kw.items():
        setattr(b, k, v)
    return b


def ctx(full_mode: bool = True, system_mature: bool = True, idle_s: float = 0.0, now: float = NOW,
        policy: AppPolicy | None = None, cfg: Config = CFG) -> HeuristicContext:
    matured_at = now - 86400 if system_mature else now + 3600
    return HeuristicContext(now, full_mode, system_mature, matured_at, idle_s, LISTS, cfg, policy or AppPolicy())
