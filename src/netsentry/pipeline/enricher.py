"""Names for remote IPs: DNS answers seen on the wire, then TLS SNI, then reverse DNS (doc 2.4)."""

from __future__ import annotations

import asyncio
import logging
import socket
import time

import tldextract

from ..models import DnsAnswer, Flow, ip_prefix

log = logging.getLogger(__name__)

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled snapshot, never fetches


def registrable(name: str) -> str:
    """eTLD+1: ``a1.cdn.example.co.uk`` -> ``example.co.uk``."""
    name = name.lower().rstrip(".")
    ext = _extract(name)
    reg = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", "")
    return reg or name


class Enricher:
    def __init__(self, rdns: bool = True, rdns_wait_s: float = 4.0, max_concurrency: int = 4) -> None:
        self.rdns_enabled = rdns
        self.rdns_wait_s = rdns_wait_s
        self._dns: dict[str, tuple[str, float]] = {}  # ip -> (name, expires_at)
        self._rdns: dict[str, tuple[str | None, float]] = {}  # ip -> (name | None, fetched_at)
        self._inflight: set[str] = set()
        self._sem = asyncio.Semaphore(max_concurrency)
        self._tasks: set[asyncio.Task[None]] = set()

    def ingest_dns(self, answers: list[DnsAnswer]) -> None:
        for a in answers:
            self._dns[a.ip] = (a.qname, a.ts + max(a.ttl, 300))

    def name_for(self, ip: str, sni: str | None, now: float) -> str | None:
        hit = self._dns.get(ip)
        if hit and hit[1] >= now:
            return hit[0]
        if sni:
            return sni
        r = self._rdns.get(ip)
        return r[0] if r else None

    def settle(self, f: Flow, now: float) -> bool:
        """Fill ``f.domain``/``f.dest``. Returns True once the flow's destination key is final."""
        name = self.name_for(f.raddr, f.sni, now)
        if name:
            f.domain, f.dest, f.has_name = name, registrable(name), True
            return True
        lookup_done = f.raddr in self._rdns
        if not self.rdns_enabled or lookup_done or now - f.opened_at >= self.rdns_wait_s:
            f.dest, f.has_name = ip_prefix(f.raddr), False
            return True
        self._schedule(f.raddr)
        return False

    def refresh(self, f: Flow, now: float) -> None:
        """Late names (rDNS finishing after the flow settled) only update what's displayed."""
        if f.domain is None:
            f.domain = self.name_for(f.raddr, f.sni, now)

    def _schedule(self, ip: str) -> None:
        if ip in self._inflight or ip in self._rdns:
            return
        self._inflight.add(ip)
        t = asyncio.get_running_loop().create_task(self._lookup(ip))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _lookup(self, ip: str) -> None:
        async with self._sem:
            loop = asyncio.get_running_loop()
            try:
                host = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 3.0)
                name: str | None = host[0].lower()
            except (OSError, TimeoutError):
                name = None
            self._rdns[ip] = (name, time.time())
            self._inflight.discard(ip)

    def prune(self, now: float) -> None:
        self._dns = {k: v for k, v in self._dns.items() if v[1] >= now}
        self._rdns = {k: v for k, v in self._rdns.items() if now - v[1] < 3600}
