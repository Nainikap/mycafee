"""Reads the OS connection table (GetExtendedTcpTable/UdpTable on Windows) through psutil."""

from __future__ import annotations

import socket

import psutil

from ..models import SocketEntry, ip_class, normalize_ip

# Sockets in these states have no live owner worth attributing (Windows reports PID 0 for TIME_WAIT).
_SKIP_STATES = {psutil.CONN_TIME_WAIT, psutil.CONN_CLOSE}


class SocketPoller:
    def __init__(self, ignore_loopback: bool = True) -> None:
        self.ignore_loopback = ignore_loopback

    def poll(self) -> tuple[list[SocketEntry], list[SocketEntry]]:
        """Returns (connections with a remote end, listening sockets)."""
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return [], []
        out: list[SocketEntry] = []
        listens: list[SocketEntry] = []
        for c in conns:
            if not c.laddr:
                continue
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            laddr = normalize_ip(c.laddr.ip)
            pid = c.pid or 0
            if c.raddr:
                raddr = normalize_ip(c.raddr.ip)
                if c.status in _SKIP_STATES or pid == 0:
                    continue
                if self.ignore_loopback and ip_class(raddr) == "loopback":
                    continue
                out.append(SocketEntry(proto, laddr, c.laddr.port, raddr, c.raddr.port, c.status, pid))
            elif proto == "udp" or c.status == psutil.CONN_LISTEN:
                listens.append(SocketEntry(proto, laddr, c.laddr.port, "", 0, c.status or "NONE", pid))
        return out, listens
