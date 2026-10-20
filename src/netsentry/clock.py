"""Injectable clock so replay and tests are deterministic."""

from __future__ import annotations

import asyncio
import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float: ...
    async def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def now(self) -> float:
        return time.time()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class FakeClock:
    """Time only moves when someone calls ``set``/``advance``; ``sleep`` advances instantly."""

    def __init__(self, start: float = 1_700_000_000.0, speed: float | None = None) -> None:
        self._now = start
        self.speed = speed  # None = don't really sleep; N = sleep seconds/N for watchable replays

    def now(self) -> float:
        return self._now

    def set(self, ts: float) -> None:
        self._now = ts

    def advance(self, seconds: float) -> None:
        self._now += seconds

    async def sleep(self, seconds: float) -> None:
        if self.speed:
            await asyncio.sleep(seconds / self.speed)
        else:
            await asyncio.sleep(0)
