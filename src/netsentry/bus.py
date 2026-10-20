"""In-process async pub/sub between the engine and any number of UIs."""

from __future__ import annotations

import asyncio
from typing import Any


class EventBus:
    def __init__(self, maxsize: int = 256) -> None:
        self._subs: list[asyncio.Queue[Any]] = []
        self._maxsize = maxsize

    def subscribe(self) -> asyncio.Queue[Any]:
        q: asyncio.Queue[Any] = asyncio.Queue(self._maxsize)
        self._subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Any]) -> None:
        if q in self._subs:
            self._subs.remove(q)

    def publish(self, event: Any) -> None:
        for q in self._subs:
            if q.full():  # a slow UI loses old frames, never blocks the engine
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(event)
