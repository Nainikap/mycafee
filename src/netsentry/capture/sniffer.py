"""Optional packet capture (Scapy on Npcap): per-flow bytes, DNS answers, TLS ClientHello -> SNI/JA3.

Runs in Scapy's own thread. The callback only updates counters under a lock; the engine swaps the
whole dict out once per tick (``drain``), so engine state is never touched from this thread.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import psutil

from ..models import DnsAnswer, FlowKey, PacketStat, TlsHello, normalize_ip
from .tls import parse_client_hello, record_length

log = logging.getLogger(__name__)

_TLS_INSPECT_PACKETS = 3
_TLS_MAX_BUFFER = 16_384


def local_addresses() -> set[str]:
    out = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family.name in ("AF_INET", "AF_INET6"):
                out.add(normalize_ip(a.address))
    return out


class PacketSniffer:
    def __init__(self, iface: str | None = None) -> None:
        self.iface = iface
        self.error: str | None = None
        self._lock = threading.Lock()
        self._counters: dict[FlowKey, PacketStat] = {}
        self._dns: list[DnsAnswer] = []
        self._tls: list[TlsHello] = []
        self._tls_buf: dict[FlowKey, bytearray] = {}
        self._tls_seen: dict[FlowKey, int] = {}
        self._local = local_addresses()
        self._local_refreshed = time.time()
        self._recv = 0
        self._sniffer: Any = None
        self._layers: Any = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> bool:
        try:
            from scapy.all import AsyncSniffer, conf  # noqa: F401  (import is slow; only in full mode)
            from scapy.layers.dns import DNS
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
        except Exception as e:  # pragma: no cover - depends on the machine
            self.error = f"scapy unavailable: {e}"
            return False
        self._layers = (IP, IPv6, TCP, UDP, DNS)
        try:
            self._sniffer = AsyncSniffer(iface=self.iface, filter="ip or ip6", prn=self._on_pkt, store=False)
            self._sniffer.start()
            time.sleep(0.7)
            exc = getattr(self._sniffer, "exception", None)
            if exc is not None or not getattr(self._sniffer, "running", False):
                self.error = f"capture failed to start: {exc or 'sniffer not running'}"
                return False
        except Exception as e:  # pragma: no cover
            self.error = f"capture failed to start: {e}"
            return False
        return True

    def stop(self) -> None:
        if self._sniffer is not None and getattr(self._sniffer, "running", False):
            try:
                self._sniffer.stop()
            except Exception:  # pragma: no cover
                pass

    def drain(self) -> tuple[dict[FlowKey, PacketStat], list[DnsAnswer], list[TlsHello], int]:
        with self._lock:
            c, d, t = self._counters, self._dns, self._tls
            self._counters, self._dns, self._tls = {}, [], []
            recv = self._recv
        if time.time() - self._local_refreshed > 30:
            self._local = local_addresses()
            self._local_refreshed = time.time()
        return c, d, t, recv

    # ------------------------------------------------------------ hot path
    def _on_pkt(self, pkt: Any) -> None:
        IP, IPv6, TCP, UDP, DNS = self._layers
        ip = pkt.getlayer(IP)
        if ip is None:
            ip = pkt.getlayer(IPv6)
            if ip is None:
                return
            size = int(ip.plen) + 40
        else:
            size = int(ip.len)
        l4 = ip.payload
        if isinstance(l4, TCP):
            proto = "tcp"
        elif isinstance(l4, UDP):
            proto = "udp"
        else:
            return
        src, dst = normalize_ip(ip.src), normalize_ip(ip.dst)
        sport, dport = int(l4.sport), int(l4.dport)
        if src in self._local:
            out, key = True, (proto, src, sport, dst, dport)
        elif dst in self._local:
            out, key = False, (proto, dst, dport, src, sport)
        else:
            return
        ts = float(pkt.time)
        with self._lock:
            self._recv += 1
            st = self._counters.get(key)
            if st is None:
                st = self._counters[key] = PacketStat(first_ts=ts)
            st.last_ts = ts
            if out:
                st.bytes_out += size
                st.pkts_out += 1
                if proto == "tcp" and (int(l4.flags) & 0x12) == 0x02 and len(st.syn_ts) < 20:  # SYN, not SYN-ACK
                    st.syn_ts.append(ts)
            else:
                st.bytes_in += size
                st.pkts_in += 1

        if proto == "udp" and not out and sport == 53:
            dns = pkt.getlayer(DNS)
            if dns is not None:
                answers = parse_dns(dns, ts)
                if answers:
                    with self._lock:
                        self._dns.extend(answers)
        elif proto == "tcp" and out:
            payload = bytes(l4.payload)
            if payload:
                self._inspect_tls(key, payload, ts)

    def _inspect_tls(self, key: FlowKey, payload: bytes, ts: float) -> None:
        seen = self._tls_seen.get(key, 0)
        if seen >= _TLS_INSPECT_PACKETS:
            return
        self._tls_seen[key] = seen + 1
        if len(self._tls_seen) > 50_000:
            self._tls_seen.clear()
        buf = self._tls_buf.get(key)
        if buf is None:
            if record_length(payload) is None:
                self._tls_seen[key] = _TLS_INSPECT_PACKETS
                return
            buf = self._tls_buf[key] = bytearray()
        buf += payload
        need = record_length(bytes(buf[:6]))
        if need is None or len(buf) > _TLS_MAX_BUFFER:
            self._tls_buf.pop(key, None)
            return
        if len(buf) < need and seen + 1 < _TLS_INSPECT_PACKETS:
            return  # ClientHello split across segments (e.g. post-quantum key shares); wait for more
        self._tls_buf.pop(key, None)
        self._tls_seen[key] = _TLS_INSPECT_PACKETS
        hello = parse_client_hello(bytes(buf))
        if hello is not None:
            with self._lock:
                self._tls.append(TlsHello(key, hello.sni, hello.ja3, hello.ja3n, ts))


def parse_dns(dns: Any, ts: float) -> list[DnsAnswer]:
    """Map every A/AAAA answer back to the name that was originally asked for (follows CNAMEs)."""
    try:
        qd = dns.qd
        q = qd[0] if isinstance(qd, list) else qd
        if q is None:
            return []
        qname = q.qname.decode("ascii", "replace").rstrip(".").lower()
        out = []
        an = dns.an or []
        for rr in (an if isinstance(an, list) else _iter_legacy(an)):
            if rr.type in (1, 28):
                out.append(DnsAnswer(normalize_ip(str(rr.rdata)), qname, int(rr.ttl), ts))
        return out
    except Exception:
        return []


def _iter_legacy(rr: Any):  # scapy < 2.6 chained answers through .payload
    while rr is not None and rr.__class__.__name__ != "NoPayload":
        yield rr
        rr = rr.payload
