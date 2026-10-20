"""Per-app 1-minute buckets and the 5-minute sliding window the heuristics look at (doc 4.1)."""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..models import Flow, ProcessInfo, Severity


@dataclass(slots=True)
class DestInfo:
    ip_class: str
    has_name: bool
    domain: str | None
    example: str  # "domain (ip:port)" for evidence strings


@dataclass(slots=True)
class Bucket:
    app_id: str
    minute_ts: int
    new_flows: int = 0
    dests: Counter[str] = field(default_factory=Counter)
    dest_info: dict[str, DestInfo] = field(default_factory=dict)
    remotes: dict[str, str | None] = field(default_factory=dict)  # raddr -> domain
    ip_dest: dict[str, str] = field(default_factory=dict)  # raddr -> dest key
    rports: dict[tuple[str, int], set[str]] = field(default_factory=dict)  # (proto, port) -> raddrs
    listen_ports: set[int] = field(default_factory=set)
    ip_bytes_out: Counter[str] = field(default_factory=Counter)
    bytes_out: int = 0
    bytes_in: int = 0
    ja3: dict[str, str] = field(default_factory=dict)  # ja3n -> ja3
    idle_max: float = 0.0
    max_score: int = 0
    max_severity: Severity = Severity.NONE
    marked_normal: bool = False
    folded: bool = False  # already folded into the baseline

    @property
    def active(self) -> bool:
        return bool(self.new_flows or self.dests or self.bytes_out or self.bytes_in or self.remotes)

    def bytes_out_excluding(self, skip_ip: set[str]) -> int:
        if not skip_ip:
            return self.bytes_out
        return self.bytes_out - sum(v for ip, v in self.ip_bytes_out.items() if ip in skip_ip)


@dataclass(slots=True)
class AppState:
    app_id: str
    current: Bucket
    closed: deque[Bucket]
    process: ProcessInfo | None = None
    starts: dict[tuple[str, int], deque[float]] = field(default_factory=dict)  # (raddr, rport) -> starts
    last_activity: float = 0.0


@dataclass(slots=True)
class AppWindow:
    """What a heuristic sees: the last N closed buckets plus the current partial one."""

    app_id: str
    buckets: list[Bucket]  # oldest first, current last
    process: ProcessInfo | None
    starts: dict[tuple[str, int], deque[float]]
    now: float

    @property
    def current(self) -> Bucket:
        return self.buckets[-1]

    @property
    def last_closed(self) -> Bucket | None:
        return self.buckets[-2] if len(self.buckets) > 1 else None

    def dests(self) -> dict[str, DestInfo]:
        out: dict[str, DestInfo] = {}
        for b in self.buckets:
            out.update(b.dest_info)
        return out

    def remotes(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for b in self.buckets:
            for ip, d in b.remotes.items():
                if d or ip not in out:
                    out[ip] = d
        return out

    def ip_dest(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for b in self.buckets:
            out.update(b.ip_dest)
        return out

    def rports(self) -> dict[tuple[str, int], set[str]]:
        out: dict[tuple[str, int], set[str]] = {}
        for b in self.buckets:
            for k, ips in b.rports.items():
                out.setdefault(k, set()).update(ips)
        return out

    def listen_ports(self) -> set[int]:
        return set().union(*(b.listen_ports for b in self.buckets))

    def ja3(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for b in self.buckets:
            out.update(b.ja3)
        return out


class FeatureExtractor:
    def __init__(self, bucket_s: int = 60, window_buckets: int = 5, max_starts: int = 20) -> None:
        self.bucket_s = bucket_s
        self.window_buckets = window_buckets
        self.max_starts = max_starts
        self.apps: dict[str, AppState] = {}
        self.dirty: set[str] = set()

    def _minute(self, ts: float) -> int:
        return int(ts // self.bucket_s * self.bucket_s)

    def state(self, app_id: str, now: float) -> AppState:
        st = self.apps.get(app_id)
        if st is None:
            st = AppState(app_id, Bucket(app_id, self._minute(now)), deque(maxlen=self.window_buckets))
            self.apps[app_id] = st
        return st

    def roll(self, now: float) -> list[Bucket]:
        """Close every bucket whose minute has passed. Returns the closed buckets (for baselines + history)."""
        m = self._minute(now)
        closed: list[Bucket] = []
        for app_id, st in list(self.apps.items()):
            if st.current.minute_ts >= m:
                continue
            closed.append(st.current)
            st.closed.append(st.current)
            st.current = Bucket(app_id, m)
            idle_for = now - st.last_activity
            if idle_for > self.bucket_s * (self.window_buckets + 1) and not any(b.active for b in st.closed):
                del self.apps[app_id]  # baseline survives in BaselineStore; window state is not needed
        return closed

    # -- ingestion -------------------------------------------------------------
    def on_open(self, f: Flow, proc: ProcessInfo | None, start: float, count: bool = True) -> None:
        st = self.state(f.app_id, start)
        if proc is not None:
            st.process = proc
        b = st.current
        b.remotes.setdefault(f.raddr, f.domain)
        if f.inbound:  # we are the server: the remote port is the client's ephemeral port, not a service
            st.last_activity = max(st.last_activity, start)
            self.dirty.add(f.app_id)
            return
        b.rports.setdefault((f.proto, f.rport), set()).add(f.raddr)
        if count:
            b.new_flows += 1
            key = (f.raddr, f.rport)
            q = st.starts.get(key)
            if q is None:
                q = st.starts[key] = deque(maxlen=self.max_starts)
            q.append(start)
        st.last_activity = max(st.last_activity, start)
        self.dirty.add(f.app_id)

    def on_dest(self, f: Flow, now: float) -> None:
        st = self.state(f.app_id, now)
        b = st.current
        assert f.dest is not None
        b.dests[f.dest] += 1
        b.remotes[f.raddr] = f.domain
        b.ip_dest[f.raddr] = f.dest
        if f.dest not in b.dest_info:
            where = f"{f.raddr}:{f.rport}"
            b.dest_info[f.dest] = DestInfo(f.ip_class, f.has_name, f.domain,
                                           f"{f.domain} ({where})" if f.domain else where)
        st.last_activity = now
        self.dirty.add(f.app_id)

    def on_bytes(self, f: Flow, d_out: int, d_in: int, now: float) -> None:
        st = self.state(f.app_id, now)
        b = st.current
        b.bytes_out += d_out
        b.bytes_in += d_in
        b.ip_bytes_out[f.raddr] += d_out
        b.remotes.setdefault(f.raddr, f.domain)
        st.last_activity = now
        self.dirty.add(f.app_id)

    def on_tls(self, f: Flow, ja3: str, ja3n: str, now: float) -> None:
        st = self.state(f.app_id, now)
        st.current.ja3[ja3n] = ja3
        self.dirty.add(f.app_id)

    def on_listen(self, app_id: str, ports: Iterable[int], now: float) -> None:
        st = self.apps.get(app_id)
        if st is not None:
            st.current.listen_ports.update(ports)

    def on_idle(self, idle_s: float) -> None:
        for st in self.apps.values():
            st.current.idle_max = max(st.current.idle_max, idle_s)

    # -- views ------------------------------------------------------------------
    def window(self, app_id: str, now: float) -> AppWindow | None:
        st = self.apps.get(app_id)
        if st is None:
            return None
        oldest = self._minute(now) - self.bucket_s * self.window_buckets
        buckets = [b for b in st.closed if b.minute_ts >= oldest] + [st.current]
        return AppWindow(app_id, buckets, st.process, st.starts, now)

    def take_dirty(self) -> set[str]:
        d, self.dirty = self.dirty, set()
        return d
