"""Joins the sniffer's packet counters to the socket table to find which PID owns each flow."""

from __future__ import annotations

from collections.abc import Callable

from ..models import FlowKey, PacketStat, RawTick


class Attributor:
    """TCP: exact 5-tuple match. UDP: match on the local port (Windows UDP sockets have no remote end).

    Packets that match nothing wait in ``pending`` for ``pending_ticks`` polls (the socket often shows up
    one poll after the first packet), then are handed out with pid ``None`` -> app "unknown".
    """

    def __init__(self, pending_ticks: int = 2) -> None:
        self.pending_ticks = pending_ticks
        self.pending: dict[FlowKey, tuple[PacketStat, int]] = {}

    def attribute(self, tick: RawTick, known_pid: Callable[[FlowKey], int | None]
                  ) -> list[tuple[FlowKey, int | None, PacketStat]]:
        sock_pid = {s.key: s.pid for s in tick.sockets}
        udp_port: dict[int, int] = {}
        for s in tick.listens:
            if s.proto == "udp" and s.pid:
                udp_port.setdefault(s.lport, s.pid)

        stats: dict[FlowKey, PacketStat] = {}
        ages: dict[FlowKey, int] = {}
        for k, (st, age) in self.pending.items():
            stats[k] = st
            ages[k] = age
        for k, st in tick.packets.items():
            if k in stats:
                stats[k].merge(st)
            else:
                stats[k] = st
                ages[k] = 0
        self.pending = {}

        out: list[tuple[FlowKey, int | None, PacketStat]] = []
        for k, st in stats.items():
            pid = sock_pid.get(k) or known_pid(k)
            if pid is None and k[0] == "udp":
                pid = udp_port.get(k[2])
            if pid is not None:
                out.append((k, pid, st))
            elif ages[k] + 1 > self.pending_ticks:
                out.append((k, None, st))
            else:
                self.pending[k] = (st, ages[k] + 1)
        return out
