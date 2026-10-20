"""Capture sources: live OS capture, or a JSONL recording replayed through a fake clock."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import IO, Protocol

from ..clock import FakeClock
from ..models import ProcessInfo, RawTick
from .idle import idle_seconds, is_admin
from .process_resolver import ProcessResolver
from .socket_poller import SocketPoller

log = logging.getLogger(__name__)


class CaptureSource(Protocol):
    full_mode: bool
    mode_reason: str

    async def start(self) -> None: ...
    async def sample(self) -> RawTick | None: ...  # None = no more data (end of a replay)
    async def stop(self) -> None: ...


class LiveSource:
    def __init__(self, sniff: bool = True, iface: str | None = None, ignore_loopback: bool = True) -> None:
        self.poller = SocketPoller(ignore_loopback)
        self.resolver = ProcessResolver()
        self._want_sniff = sniff
        self._iface = iface
        self.sniffer = None
        self.full_mode = False
        self.mode_reason = ""

    async def start(self) -> None:
        if not self._want_sniff:
            self.mode_reason = "packet capture disabled (--no-sniff)"
        elif not is_admin():
            self.mode_reason = "not running as administrator — bytes, DNS, SNI and JA3 unavailable"
        else:
            from .sniffer import PacketSniffer

            sn = PacketSniffer(self._iface)
            ok = await asyncio.get_running_loop().run_in_executor(None, sn.start)
            if ok:
                self.sniffer, self.full_mode, self.mode_reason = sn, True, "packet capture active (Npcap)"
            else:
                self.mode_reason = sn.error or "packet capture failed"
        log.info("capture mode: %s (%s)", "FULL" if self.full_mode else "STANDARD", self.mode_reason)

    async def sample(self) -> RawTick:
        loop = asyncio.get_running_loop()
        ts = time.time()
        sockets, listens = await loop.run_in_executor(None, self.poller.poll)
        pids = {s.pid for s in sockets} | {s.pid for s in listens}
        processes: dict[int, ProcessInfo] = await loop.run_in_executor(
            None, self.resolver.resolve_many, pids)
        tick = RawTick(ts=ts, full_mode=self.full_mode, sockets=sockets, listens=listens,
                       processes=processes, idle_s=idle_seconds())
        if self.sniffer is not None:
            tick.packets, tick.dns, tick.tls, tick.pcap_recv = self.sniffer.drain()
        return tick

    async def stop(self) -> None:
        if self.sniffer is not None:
            self.sniffer.stop()


class ReplaySource:
    def __init__(self, path: Path, clock: FakeClock) -> None:
        self.path = path
        self.clock = clock
        self._fh: IO[str] | None = None
        self.full_mode = False
        self.mode_reason = f"replay of {path.name}"

    async def start(self) -> None:
        self._fh = self.path.open(encoding="utf-8")

    async def sample(self) -> RawTick | None:
        assert self._fh is not None
        line = self._fh.readline()
        while line and not line.strip():
            line = self._fh.readline()
        if not line:
            return None
        tick = RawTick.from_json(json.loads(line))
        self.full_mode = tick.full_mode
        self.clock.set(tick.ts)
        return tick

    async def stop(self) -> None:
        if self._fh:
            self._fh.close()


class ListSource:
    """In-memory ticks; used by tests and the synthetic demo generator."""

    def __init__(self, ticks: list[RawTick], clock: FakeClock | None = None) -> None:
        self._ticks = list(ticks)
        self._i = 0
        self.clock = clock
        self.full_mode = bool(ticks and ticks[0].full_mode)
        self.mode_reason = "in-memory ticks"

    async def start(self) -> None: ...

    async def sample(self) -> RawTick | None:
        if self._i >= len(self._ticks):
            return None
        t = self._ticks[self._i]
        self._i += 1
        if self.clock:
            self.clock.set(t.ts)
        return t

    async def stop(self) -> None: ...


class Recorder:
    def __init__(self, path: Path) -> None:
        self._fh = path.open("w", encoding="utf-8")

    def write(self, tick: RawTick) -> None:
        self._fh.write(json.dumps(tick.to_json(), separators=(",", ":")) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
