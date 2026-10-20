"""Harmless attack simulators for validating NetSentry (docs/07-validation.md).

They only open ordinary TCP connections to hosts you choose and send junk bytes. Nothing is installed,
persisted or exfiltrated. Each connection is held open for a few seconds so the 2 s socket poll sees it.

  python tools/simulate/sim.py sink --ports 4444 9000            # run on a second machine (or this one)
  python tools/simulate/sim.py beacon --host <sink-ip> --port 4444 --interval 30
  python tools/simulate/sim.py exfil  --host <sink-ip> --port 9000 --mb 200
  python tools/simulate/sim.py oddport --host portquiz.net --port 31337
  python tools/simulate/sim.py office                              # "WINWORD.EXE" -> powershell -> internet
  python tools/simulate/sim.py masquerade                          # %TEMP%\\...\\svchost.exe (renamed curl)
  python tools/simulate/sim.py blocklist --host portquiz.net       # adds the host's IP to blocklists/ips.txt

Note: your antivirus may (correctly!) block `office` or `masquerade`. That is itself a valid result.
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")
SIM_DIR = Path(tempfile.gettempdir()) / "netsentry-sim"


def hold_connection(host: str, port: int, seconds: float, payload: bytes = b"") -> bool:
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            if payload:
                s.sendall(payload)
            time.sleep(seconds)
        return True
    except OSError as e:
        print(f"  connect {host}:{port} failed: {e}")
        return False


def cmd_sink(a: argparse.Namespace) -> None:
    def serve(port: int) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(16)
        print(f"sink listening on 0.0.0.0:{port}")
        while True:
            c, addr = srv.accept()
            threading.Thread(target=drain, args=(c, addr, port), daemon=True).start()

    def drain(c: socket.socket, addr: tuple, port: int) -> None:
        n = 0
        with c:
            while chunk := c.recv(65536):
                n += len(chunk)
        print(f"  {addr[0]} → :{port}  {n / 1e6:.1f} MB")

    for p in a.ports:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def cmd_beacon(a: argparse.Namespace) -> None:
    print(f"beacon → {a.host}:{a.port} every {a.interval}s ± {a.jitter}s, {a.count} times")
    for i in range(a.count):
        t0 = time.time()
        hold_connection(a.host, a.port, 3, b"ping")
        print(f"  beacon {i + 1}/{a.count}")
        time.sleep(max(0, a.interval + random.uniform(-a.jitter, a.jitter) - (time.time() - t0)))


def cmd_exfil(a: argparse.Namespace) -> None:
    total = int(a.mb * 1e6)
    chunk = os.urandom(65536)
    print(f"exfil {a.mb} MB → {a.host}:{a.port}")
    sent, t0 = 0, time.time()
    with socket.create_connection((a.host, a.port), timeout=10) as s:
        while sent < total:
            s.sendall(chunk)
            sent += len(chunk)
        time.sleep(3)
    print(f"  sent {sent / 1e6:.0f} MB in {time.time() - t0:.1f}s")


def cmd_oddport(a: argparse.Namespace) -> None:
    print(f"connecting to {a.host}:{a.port} (held {a.hold}s)")
    hold_connection(a.host, a.port, a.hold, b"hello\r\n")


def _staged_copy(src: Path, name: str) -> Path:
    SIM_DIR.mkdir(exist_ok=True)
    dst = SIM_DIR / name
    shutil.copy2(src, dst)
    return dst


def cmd_office(a: argparse.Namespace) -> None:
    winword = _staged_copy(Path(os.environ["WINDIR"]) / "System32" / "cmd.exe", "WINWORD.EXE")
    ps = ("$c = New-Object Net.Sockets.TcpClient('example.com', 443); Start-Sleep 8; $c.Close()")
    print(f"{winword} → powershell.exe → example.com:443")
    subprocess.run([str(winword), "/c", "powershell", "-NoProfile", "-Command", ps], check=False)


def cmd_masquerade(a: argparse.Namespace) -> None:
    svchost = _staged_copy(Path(os.environ["WINDIR"]) / "System32" / "curl.exe", "svchost.exe")
    print(f"{svchost} downloading slowly from speed.cloudflare.com")
    subprocess.run([str(svchost), "-s", "-o", os.devnull, "--limit-rate", "4k",
                    "https://speed.cloudflare.com/__down?bytes=40000"], check=False)


def cmd_blocklist(a: argparse.Namespace) -> None:
    ip = socket.gethostbyname(a.host)
    path = ROOT / "config" / "blocklists" / "ips.txt"
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{ip}  # {a.host}, added by sim.py blocklist — remove after the demo\n")
    print(f"added {ip} ({a.host}) to {path}; waiting 12 s for the engine to reload lists…")
    time.sleep(12)
    hold_connection(ip, a.port, 5, b"hello\r\n")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sink")
    s.add_argument("--ports", type=int, nargs="+", default=[4444, 9000])
    s = sub.add_parser("beacon")
    s.add_argument("--host", required=True)
    s.add_argument("--port", type=int, default=4444)
    s.add_argument("--interval", type=float, default=30)
    s.add_argument("--jitter", type=float, default=1.0)
    s.add_argument("--count", type=int, default=10)
    s = sub.add_parser("exfil")
    s.add_argument("--host", required=True)
    s.add_argument("--port", type=int, default=9000)
    s.add_argument("--mb", type=float, default=200)
    s = sub.add_parser("oddport")
    s.add_argument("--host", default="portquiz.net")
    s.add_argument("--port", type=int, default=31337)
    s.add_argument("--hold", type=float, default=6)
    sub.add_parser("office")
    sub.add_parser("masquerade")
    s = sub.add_parser("blocklist")
    s.add_argument("--host", default="portquiz.net")
    s.add_argument("--port", type=int, default=80)
    a = p.parse_args()
    if a.cmd in ("office", "masquerade") and sys.platform != "win32":
        sys.exit("office/masquerade simulations are Windows-only")
    globals()[f"cmd_{a.cmd}"](a)


if __name__ == "__main__":
    main()
