"""Synthetic scenario generator: a quiet baseline period, then a beacon, an exfiltration and a blocklist hit.

Produces RawTicks (the same format `netsentry record` writes), so the whole pipeline runs exactly as it
does live. Used by `netsentry demo`, the integration tests, and as a fallback for presentations.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .models import PacketStat, ProcessInfo, RawTick, SocketEntry

LOCAL = "192.168.1.20"
SYS32 = "c:\\windows\\system32\\"


def _proc(pid: int, name: str, exe: str, parents: tuple[tuple[str, str], ...] = ()) -> ProcessInfo:
    return ProcessInfo(pid, 1_000.0 + pid, name, exe, exe.lower(), "user", exe, parents)


EXPLORER = ("explorer.exe", "C:\\Windows\\explorer.exe")
CHROME = _proc(1220, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", (EXPLORER,))
TEAMS = _proc(2040, "ms-teams.exe", "C:\\Program Files\\WindowsApps\\MSTeams\\ms-teams.exe", (EXPLORER,))
ONEDRIVE = _proc(4400, "OneDrive.exe", "C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
                 (EXPLORER,))
BEACON = _proc(9120, "updater.exe", "C:\\Users\\user\\AppData\\Local\\Temp\\updater.exe", (EXPLORER,))
WORD = ("WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
PWSH = _proc(7764, "powershell.exe", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", (WORD, EXPLORER))


@dataclass
class _Conn:
    proc: ProcessInfo
    raddr: str
    rport: int
    until: float
    lport: int
    out_per_tick: int = 0
    in_per_tick: int = 0


@dataclass
class Scenario:
    start: float = 1_760_000_000.0  # fixed epoch so runs are reproducible
    poll: float = 2.0
    learn_minutes: int = 12
    full_mode: bool = True
    seed: int = 7
    ticks: list[RawTick] = field(default_factory=list)

    def build(self) -> list[RawTick]:
        rnd = random.Random(self.seed)
        conns: list[_Conn] = []
        lport = [50000]

        def open_conn(p: ProcessInfo, ip: str, port: int, now: float, dur: float, out: int = 0, inb: int = 0) -> None:
            lport[0] += 1
            conns.append(_Conn(p, ip, port, now + dur, lport[0], out, inb))

        t = self.start
        end_learn = self.start + self.learn_minutes * 60
        beacon_start = end_learn + 60
        exfil_start = end_learn + 6 * 60
        block_at = end_learn + 9 * 60
        pwsh_at = end_learn + 10 * 60
        end = end_learn + 13 * 60
        chrome_sites = [f"142.250.{i}.10" for i in range(1, 7)] + ["151.101.1.69", "104.16.132.229"]
        next_beacon = beacon_start
        while t < end:
            # normal background: chrome browsing, teams heartbeat, onedrive small sync
            if rnd.random() < 0.35:
                open_conn(CHROME, rnd.choice(chrome_sites), 443, t, rnd.uniform(4, 30), 2_000, 40_000)
            if int(t - self.start) % 60 < self.poll:
                open_conn(TEAMS, "52.123.164.123", 443, t, 50, 500, 800)
            if rnd.random() < 0.08:
                open_conn(ONEDRIVE, "13.107.42.12", 443, t, 6, 20_000, 3_000)
            # attack 1: beacon every 30 s to a bare IP on 4444
            if t >= next_beacon and t < exfil_start + 300:
                open_conn(BEACON, "198.51.100.23", 4444, t, 1.5, 300, 200)
                next_beacon += 30 + rnd.uniform(-0.6, 0.6)
            # attack 2: OneDrive-like process uploads ~200 MB in one minute to a new bare IP (exfil look-alike)
            if abs(t - exfil_start) < self.poll / 2:
                open_conn(ONEDRIVE, "185.199.110.153", 443, t, 60, 6_800_000, 10_000)
            # attack 3: blocklisted destination
            if abs(t - block_at) < self.poll / 2:
                open_conn(CHROME, "203.0.113.66", 443, t, 6, 1_000, 1_000)
            # attack 4: Word -> PowerShell downloading from a new domain
            if abs(t - pwsh_at) < self.poll / 2:
                open_conn(PWSH, "93.184.215.14", 443, t, 8, 2_000, 400_000)

            live = [c for c in conns if c.until >= t]
            conns[:] = live
            sockets = [SocketEntry("tcp", LOCAL, c.lport, c.raddr, c.rport, "ESTABLISHED", c.proc.pid) for c in live]
            procs = {c.proc.pid: c.proc for c in live}
            packets = {}
            if self.full_mode:
                for c in live:
                    jitter = rnd.uniform(0.8, 1.2)
                    packets[("tcp", LOCAL, c.lport, c.raddr, c.rport)] = PacketStat(
                        int(c.out_per_tick * jitter), int(c.in_per_tick * jitter), 10, 10, t, t)
            self.ticks.append(RawTick(t, self.full_mode, sockets, [], procs, packets, idle_s=5.0))
            t += self.poll
        return self.ticks
