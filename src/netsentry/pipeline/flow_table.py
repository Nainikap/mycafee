"""Live flows: open when first seen, update every poll, close after two polls without the socket."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import UNKNOWN_APP, Flow, FlowKey, PacketStat, ProcessInfo, RawTick, ip_class

PACKET_FLOW_IDLE_S = 30.0


@dataclass(slots=True)
class FlowChanges:
    opened: list[Flow] = field(default_factory=list)
    closed: list[Flow] = field(default_factory=list)
    bytes: list[tuple[Flow, int, int]] = field(default_factory=list)  # (flow, delta_out, delta_in)
    starts: dict[FlowKey, float] = field(default_factory=dict)  # precise start (first SYN) for new flows


class FlowTable:
    def __init__(self, close_after_misses: int = 2, ignore_loopback: bool = True) -> None:
        self.flows: dict[FlowKey, Flow] = {}
        self.close_after = close_after_misses
        self.ignore_loopback = ignore_loopback
        self._listening: set[tuple[str, int]] = set()

    def pid_of(self, key: FlowKey) -> int | None:
        f = self.flows.get(key)
        return f.pid if f else None

    def get(self, key: FlowKey) -> Flow | None:
        return self.flows.get(key)

    def apply(self, tick: RawTick, attributed: list[tuple[FlowKey, int | None, PacketStat]]) -> FlowChanges:
        now = tick.ts
        ch = FlowChanges()
        seen: set[FlowKey] = set()
        opened: set[FlowKey] = set()
        self._listening = {(s.proto, s.lport) for s in tick.listens if s.proto == "udp" or s.status == "LISTEN"}

        for s in tick.sockets:
            k = s.key
            seen.add(k)
            f = self.flows.get(k)
            if f is None:
                f = self._open(k, s.pid, tick.processes.get(s.pid), now, "socket")
                if f is None:
                    continue
                ch.opened.append(f)
                opened.add(k)
            f.last_seen = now
            f.misses = 0

        for k, pid, st in attributed:
            f = self.flows.get(k)
            if f is None:
                proc = tick.processes.get(pid) if pid is not None else None
                f = self._open(k, pid or 0, proc, st.first_ts or now, "packet", unknown=pid is None)
                if f is None:
                    continue
                ch.opened.append(f)
                opened.add(k)
            if k in opened:
                start = st.syn_ts[0] if st.syn_ts else st.first_ts
                if start:
                    ch.starts[k] = start
            if st.bytes_out or st.bytes_in:
                f.bytes_out += st.bytes_out
                f.bytes_in += st.bytes_in
                ch.bytes.append((f, st.bytes_out, st.bytes_in))
            f.last_seen = max(f.last_seen, st.last_ts or now)

        for k, f in list(self.flows.items()):
            if f.source == "socket":
                if k in seen:
                    continue
                f.misses += 1
                if f.misses >= self.close_after:
                    self._close(k, f, now, ch)
            elif now - f.last_seen > PACKET_FLOW_IDLE_S:
                self._close(k, f, now, ch)
        return ch

    def _open(self, k: FlowKey, pid: int, proc: ProcessInfo | None, now: float, source: str,
              unknown: bool = False) -> Flow | None:
        cls = ip_class(k[3])
        if cls == "unspecified" or (self.ignore_loopback and cls == "loopback"):
            return None
        app = UNKNOWN_APP if unknown else (proc.app_id if proc else f"pid:{pid}")
        inbound = k[0] == "tcp" and (k[0], k[2]) in self._listening
        f = Flow(key=k, pid=pid, app_id=app, opened_at=now, last_seen=now, ip_class=cls, source=source,
                 inbound=inbound)
        self.flows[k] = f
        return f

    def _close(self, k: FlowKey, f: Flow, now: float, ch: FlowChanges) -> None:
        f.closed_at = now
        del self.flows[k]
        ch.closed.append(f)

    def open_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.flows.values():
            out[f.app_id] = out.get(f.app_id, 0) + 1
        return out
