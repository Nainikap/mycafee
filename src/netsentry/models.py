"""Domain objects shared by every layer (see docs/03-data-model.md)."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any

# (proto, local ip, local port, remote ip, remote port), always oriented from this machine's side.
FlowKey = tuple[str, str, int, str, int]
ProcKey = tuple[int, float]

UNKNOWN_APP = "unknown"


class Severity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.capitalize() if self else "None"

    @classmethod
    def parse(cls, s: str) -> Severity:
        return cls[s.upper()]


def normalize_ip(ip: str) -> str:
    """Strip IPv6 zone ids and unwrap IPv4-mapped IPv6 (``::ffff:1.2.3.4`` -> ``1.2.3.4``)."""
    ip = ip.split("%", 1)[0]
    if ip.lower().startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


# "LAN" in the networking sense. ipaddress.is_private also covers documentation/benchmark ranges,
# which would wrongly make e.g. 203.0.113.0/24 look like a LAN address.
_LAN_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def ip_class(ip: str) -> str:
    """public | private | loopback | multicast | unspecified"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "public"
    if a.is_loopback:
        return "loopback"
    if a.is_multicast or (a.version == 4 and ip.endswith(".255")):
        return "multicast"
    if a.is_unspecified:
        return "unspecified"
    if any(a.version == n.version and a in n for n in _LAN_NETS):
        return "private"
    return "public"


def ip_prefix(ip: str) -> str:
    """Destination key for a bare IP: its /24 (IPv4) or /48 (IPv6)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    plen = 24 if a.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))


# ---------------------------------------------------------------- capture layer


@dataclass(frozen=True, slots=True)
class SocketEntry:
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    pid: int

    @property
    def key(self) -> FlowKey:
        return (self.proto, self.laddr, self.lport, self.raddr, self.rport)


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    create_time: float
    name: str
    exe: str
    app_id: str
    username: str = ""
    cmdline: str = ""
    parents: tuple[tuple[str, str], ...] = ()  # (name, exe) from direct parent upwards

    @property
    def key(self) -> ProcKey:
        return (self.pid, self.create_time)


@dataclass(slots=True)
class PacketStat:
    bytes_out: int = 0
    bytes_in: int = 0
    pkts_out: int = 0
    pkts_in: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn_ts: list[float] = field(default_factory=list)

    def merge(self, other: PacketStat) -> None:
        self.bytes_out += other.bytes_out
        self.bytes_in += other.bytes_in
        self.pkts_out += other.pkts_out
        self.pkts_in += other.pkts_in
        self.first_ts = min(self.first_ts or other.first_ts, other.first_ts or self.first_ts)
        self.last_ts = max(self.last_ts, other.last_ts)
        self.syn_ts.extend(other.syn_ts)
        del self.syn_ts[:-20]


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    ip: str
    qname: str
    ttl: int
    ts: float


@dataclass(frozen=True, slots=True)
class TlsHello:
    key: FlowKey
    sni: str
    ja3: str
    ja3n: str
    ts: float


@dataclass(slots=True)
class RawTick:
    """Everything the capture layer saw in one poll. Also the unit of record/replay."""

    ts: float
    full_mode: bool
    sockets: list[SocketEntry]
    listens: list[SocketEntry]
    processes: dict[int, ProcessInfo]
    packets: dict[FlowKey, PacketStat] = field(default_factory=dict)
    dns: list[DnsAnswer] = field(default_factory=list)
    tls: list[TlsHello] = field(default_factory=list)
    idle_s: float = 0.0
    pcap_recv: int = 0
    pcap_drop: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "full_mode": self.full_mode,
            "sockets": [list(asdict(s).values()) for s in self.sockets],
            "listens": [list(asdict(s).values()) for s in self.listens],
            "processes": {str(p): asdict(i) for p, i in self.processes.items()},
            "packets": [[list(k), asdict(v)] for k, v in self.packets.items()],
            "dns": [asdict(d) for d in self.dns],
            "tls": [asdict(t) for t in self.tls],
            "idle_s": self.idle_s,
            "pcap_recv": self.pcap_recv,
            "pcap_drop": self.pcap_drop,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> RawTick:
        def proc(x: dict[str, Any]) -> ProcessInfo:
            x = dict(x)
            x["parents"] = tuple(tuple(p) for p in x.get("parents", ()))
            return ProcessInfo(**x)

        return cls(
            ts=d["ts"],
            full_mode=d["full_mode"],
            sockets=[SocketEntry(*s) for s in d["sockets"]],
            listens=[SocketEntry(*s) for s in d.get("listens", [])],
            processes={int(p): proc(i) for p, i in d["processes"].items()},
            packets={tuple(k): PacketStat(**v) for k, v in d.get("packets", [])},  # type: ignore[misc]
            dns=[DnsAnswer(**x) for x in d.get("dns", [])],
            tls=[TlsHello(**{**x, "key": tuple(x["key"])}) for x in d.get("tls", [])],
            idle_s=d.get("idle_s", 0.0),
            pcap_recv=d.get("pcap_recv", 0),
            pcap_drop=d.get("pcap_drop", 0),
        )


# ---------------------------------------------------------------- correlation layer


@dataclass(slots=True)
class Flow:
    key: FlowKey
    pid: int
    app_id: str
    opened_at: float
    last_seen: float
    ip_class: str
    source: str = "socket"  # socket | packet
    domain: str | None = None
    sni: str | None = None
    dest: str | None = None  # registrable domain or IP prefix, set once naming is settled
    has_name: bool = False
    ja3n: str | None = None
    closed_at: float | None = None
    bytes_out: int = 0
    bytes_in: int = 0
    misses: int = 0
    db_id: int | None = None
    counted_open: bool = False
    counted_dest: bool = False
    persisted_out: int = 0
    persisted_in: int = 0

    @property
    def proto(self) -> str:
        return self.key[0]

    @property
    def raddr(self) -> str:
        return self.key[3]

    @property
    def rport(self) -> int:
        return self.key[4]


# ---------------------------------------------------------------- analysis layer


@dataclass(slots=True)
class HeuristicResult:
    name: str
    code: str
    weight: float
    score: float | None  # None = unavailable
    evidence: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def contribution(self) -> float:
        return 0.0 if self.score is None else self.weight * self.score

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "code": self.code, "weight": self.weight, "score": self.score,
                "evidence": self.evidence}


@dataclass(slots=True)
class Verdict:
    app_id: str
    ts: float
    score: int
    severity: Severity
    results: list[HeuristicResult]
    policy: str | None = None  # allowed | denied | muted | allowed-but-blocklisted

    @property
    def top(self) -> HeuristicResult | None:
        firing = [r for r in self.results if r.contribution > 0]
        return max(firing, key=lambda r: r.contribution) if firing else None

    def firing(self, min_contribution: float = 0.05) -> list[HeuristicResult]:
        return sorted((r for r in self.results if r.contribution >= min_contribution),
                      key=lambda r: -r.contribution)


@dataclass(slots=True)
class Alert:
    id: int | None
    app_id: str
    opened_at: float
    updated_at: float
    status: str  # open | acked | resolved | false_positive
    severity: Severity
    peak_score: int
    top_heuristic: str
    summary: str
    evidence: list[dict[str, Any]]
    resolved_at: float | None = None


@dataclass(slots=True)
class PolicyRule:
    id: int | None
    scope: str  # app | dest | app+dest
    action: str  # allow | deny | mute
    app_id: str | None = None
    dest: str | None = None
    created_at: float = 0.0
    expires_at: float | None = None
    note: str = ""
