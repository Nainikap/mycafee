"""Loads and validates config/rules.yaml plus the static lists (ports, lolbins, blocklists)."""

from __future__ import annotations

import ipaddress
import os
from datetime import time as dtime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import Severity

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    d = Path(base) / "NetSentry"
    d.mkdir(parents=True, exist_ok=True)
    return d


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EngineCfg(_M):
    poll_interval_s: float = 2
    bucket_s: int = 60
    window_buckets: int = 5
    learning_period_h: float = 24
    min_buckets_mature: int = 30
    include_lan: bool = True
    ignore_loopback: bool = True
    retention_days: int = 7


class BaselineCfg(_M):
    ewma_alpha: float = Field(0.02, gt=0, le=1)
    min_std: float = Field(0.5, gt=0)
    z_lo: float = 3
    z_hi: float = 6


class SeverityCfg(_M):
    low: int = 25
    medium: int = 50
    high: int = 75
    alert_min: str = "medium"
    resolve_after_s: float = 300
    dedupe_cooldown_s: float = 900

    def classify(self, score: int) -> Severity:
        if score >= self.high:
            return Severity.HIGH
        if score >= self.medium:
            return Severity.MEDIUM
        if score >= self.low:
            return Severity.LOW
        return Severity.NONE

    @property
    def alert_min_severity(self) -> Severity:
        return Severity.parse(self.alert_min)


class HCfg(BaseModel):
    """One heuristic's settings: ``enabled``, ``weight`` and any heuristic-specific extras."""

    model_config = ConfigDict(extra="allow")
    enabled: bool = True
    weight: float = Field(ge=0, le=1)

    def get(self, key: str, default: Any = None) -> Any:
        return (self.model_extra or {}).get(key, default)


class HeuristicsCfg(_M):
    unusual_port: HCfg = HCfg(weight=0.45)
    frequency: HCfg = HCfg(weight=0.55)
    new_destination: HCfg = HCfg(weight=0.35)
    volume: HCfg = HCfg(weight=0.60)
    blocklist: HCfg = HCfg(weight=0.95)
    off_hours: HCfg = HCfg(weight=0.25)
    lineage: HCfg = HCfg(weight=0.60)
    tls_fingerprint: HCfg = HCfg(weight=0.35)


class Config(_M):
    version: int = 1
    engine: EngineCfg = EngineCfg()
    baseline: BaselineCfg = BaselineCfg()
    severity: SeverityCfg = SeverityCfg()
    heuristics: HeuristicsCfg = HeuristicsCfg()
    profiles: dict[str, dict[str, Any]] = {}

    @field_validator("version")
    @classmethod
    def _v(cls, v: int) -> int:
        if v != 1:
            raise ValueError("only rules.yaml version 1 is supported")
        return v


def _deep_merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(config_dir: Path = DEFAULT_CONFIG_DIR, profile: str = "default") -> Config:
    path = config_dir / "rules.yaml"
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    if profile != "default":
        override = (raw.get("profiles") or {}).get(profile)
        if override is None:
            raise ValueError(f"profile {profile!r} not found in {path}")
        raw = _deep_merge(raw, override)
    return Config.model_validate(raw)


# ---------------------------------------------------------------- static lists


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


class StaticLists:
    """ports.yaml, lolbins.yaml and blocklists/*.txt, re-read when a file changes."""

    def __init__(self, config_dir: Path = DEFAULT_CONFIG_DIR) -> None:
        self.dir = config_dir
        self._mtimes: dict[Path, float] = {}
        self.common_ports: set[int] = set()
        self.suspicious_ports: dict[int, str] = {}
        self.script_hosts: set[str] = set()
        self.suspicious_parents: set[str] = set()
        self.system_binaries: set[str] = set()
        self.system_dirs: list[str] = []
        self.staging_paths: list[str] = []
        self.bad_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.bad_domains: set[str] = set()
        self.bad_ja3: set[str] = set()
        self.reload()

    def _files(self) -> list[Path]:
        bl = self.dir / "blocklists"
        return [self.dir / "ports.yaml", self.dir / "lolbins.yaml", bl / "ips.txt", bl / "domains.txt",
                bl / "ja3.txt"]

    def changed(self) -> bool:
        return any(self._mtime(p) != self._mtimes.get(p) for p in self._files())

    @staticmethod
    def _mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return -1.0

    def reload(self) -> None:
        ports = self._yaml("ports.yaml")
        self.common_ports = {int(p) for p in ports.get("common_ports", [])}
        self.suspicious_ports = {int(k): str(v) for k, v in (ports.get("suspicious_ports") or {}).items()}
        lol = self._yaml("lolbins.yaml")
        self.script_hosts = {s.lower() for s in lol.get("script_hosts", [])}
        self.suspicious_parents = {s.lower() for s in lol.get("suspicious_parents", [])}
        self.system_binaries = {s.lower() for s in lol.get("system_binaries", [])}
        self.system_dirs = [s.lower() for s in lol.get("system_dirs", [])]
        self.staging_paths = [s.lower() for s in lol.get("staging_paths", [])]
        bl = self.dir / "blocklists"
        nets = []
        for line in _read_lines(bl / "ips.txt"):
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
        self.bad_nets = nets
        self.bad_domains = {d.lower().strip(".") for d in _read_lines(bl / "domains.txt")}
        self.bad_ja3 = {h.split()[0].lower() for h in _read_lines(bl / "ja3.txt")}
        self._mtimes = {p: self._mtime(p) for p in self._files()}

    def reload_if_changed(self) -> bool:
        if self.changed():
            self.reload()
            return True
        return False

    def _yaml(self, name: str) -> dict[str, Any]:
        p = self.dir / name
        return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}

    # -- lookups
    def ip_blocked(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self.bad_nets)

    def domain_blocked(self, domain: str | None) -> str | None:
        if not domain:
            return None
        parts = domain.lower().strip(".").split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.bad_domains:
                return cand
        return None


def parse_hhmm(s: str) -> dtime:
    h, m = s.split(":")
    return dtime(int(h), int(m))
