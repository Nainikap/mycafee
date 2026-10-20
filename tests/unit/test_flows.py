"""Attribution (packets -> PID) and flow lifecycle (open -> closing -> closed)."""

from netsentry.models import UNKNOWN_APP, PacketStat, ProcessInfo, RawTick, SocketEntry
from netsentry.pipeline.attributor import Attributor
from netsentry.pipeline.flow_table import FlowTable

P = ProcessInfo(10, 1.0, "app.exe", "c:\\app.exe", "c:\\app.exe")
TCP = ("tcp", "192.168.1.2", 50001, "8.8.8.8", 443)
UDP = ("udp", "192.168.1.2", 50002, "8.8.4.4", 3478)


def tick(ts: float, sockets=(), listens=(), packets=None) -> RawTick:  # noqa: ANN001
    return RawTick(ts, True, list(sockets), list(listens), {10: P}, dict(packets or {}))


def sock(key=TCP) -> SocketEntry:  # noqa: ANN001
    return SocketEntry(*key, "ESTABLISHED", 10)


def step(ft: FlowTable, at: Attributor, t: RawTick):  # noqa: ANN201
    return ft.apply(t, at.attribute(t, ft.pid_of))


def test_socket_flow_lifecycle() -> None:
    ft, at = FlowTable(), Attributor()
    ch = step(ft, at, tick(0, [sock()]))
    assert [f.app_id for f in ch.opened] == ["c:\\app.exe"]
    assert not step(ft, at, tick(2, [])).closed  # one miss: closing, not closed
    ch = step(ft, at, tick(4, []))
    assert len(ch.closed) == 1 and ch.closed[0].closed_at == 4


def test_flow_survives_a_single_missed_poll() -> None:
    ft, at = FlowTable(), Attributor()
    step(ft, at, tick(0, [sock()]))
    step(ft, at, tick(2, []))
    ch = step(ft, at, tick(4, [sock()]))
    assert not ch.opened and not ch.closed and ft.get(TCP).misses == 0


def test_packet_bytes_attributed_to_socket_owner() -> None:
    ft, at = FlowTable(), Attributor()
    ch = step(ft, at, tick(0, [sock()], packets={TCP: PacketStat(1000, 5000, 3, 4, 0.1, 0.5, [0.1])}))
    f = ft.get(TCP)
    assert f.bytes_out == 1000 and f.bytes_in == 5000 and ch.starts[TCP] == 0.1


def test_udp_attributed_by_local_port() -> None:
    ft, at = FlowTable(), Attributor()
    listen = SocketEntry("udp", "0.0.0.0", 50002, "", 0, "NONE", 10)
    step(ft, at, tick(0, listens=[listen], packets={UDP: PacketStat(200, 300, 1, 1, 0.1, 0.1)}))
    assert ft.get(UDP).app_id == "c:\\app.exe"


def test_unmatched_packets_wait_then_become_unknown() -> None:
    ft, at = FlowTable(), Attributor()
    ch = step(ft, at, tick(0, packets={TCP: PacketStat(10, 10, 1, 1, 0.1, 0.1)}))
    assert not ch.opened and TCP in at.pending
    ch = step(ft, at, tick(2, [sock()]))  # socket shows up one poll later -> attributed, bytes kept
    assert ft.get(TCP).app_id == "c:\\app.exe" and ft.get(TCP).bytes_out == 10
    other = ("tcp", "192.168.1.2", 50009, "1.1.1.1", 443)
    step(ft, at, tick(4, [sock()], packets={other: PacketStat(5, 5, 1, 1, 3.9, 3.9)}))
    step(ft, at, tick(6, [sock()]))
    ch = step(ft, at, tick(8, [sock()]))
    assert ft.get(other).app_id == UNKNOWN_APP


def test_accepted_connection_is_inbound() -> None:
    ft, at = FlowTable(), Attributor()
    listen = SocketEntry("tcp", "0.0.0.0", 4444, "", 0, "LISTEN", 10)
    accepted = SocketEntry("tcp", "192.168.1.2", 4444, "192.168.1.9", 51515, "ESTABLISHED", 10)
    step(ft, at, tick(0, [accepted, sock()], listens=[listen]))
    assert ft.get(accepted.key).inbound and not ft.get(TCP).inbound


def test_loopback_ignored() -> None:
    ft, at = FlowTable(), Attributor()
    ch = step(ft, at, tick(0, [sock(("tcp", "127.0.0.1", 5000, "127.0.0.1", 6000))]))
    assert not ch.opened
