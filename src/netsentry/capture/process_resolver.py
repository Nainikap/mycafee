"""PID -> ProcessInfo (name, exe, parent chain), cached by (pid, create_time) because PIDs get reused."""

from __future__ import annotations

import time

import psutil

from ..models import ProcessInfo

REVALIDATE_S = 15.0  # how often a cached PID is checked for reuse (the check costs ~10 ms on Windows)

_SPECIAL = {0: "system idle", 4: "system"}


def _ppid_map() -> dict[int, int]:
    """One snapshot of pid -> parent pid. On Windows Process.ppid() snapshots *all* processes (~30 ms)
    each call, so walking a parent chain per process would cost ~150 ms; this costs one snapshot."""
    try:
        return dict(psutil._psplatform.ppid_map())  # type: ignore[attr-defined]
    except Exception:
        return {p.pid: p.info["ppid"] for p in psutil.process_iter(["ppid"]) if p.info["ppid"] is not None}


def app_id_for(pid: int, name: str, exe: str) -> str:
    if exe:
        return exe.lower()
    if name:
        return f"name:{name.lower()}"
    return _SPECIAL.get(pid, f"pid:{pid}")


class ProcessResolver:
    def __init__(self, max_parents: int = 4) -> None:
        self.max_parents = max_parents
        self._cache: dict[int, ProcessInfo] = {}
        self._checked: dict[int, float] = {}
        self._ppids: dict[int, int] | None = None

    def resolve_many(self, pids: set[int]) -> dict[int, ProcessInfo]:
        self._ppids = _ppid_map() if any(p not in self._cache for p in pids) else None
        try:
            return {pid: self.resolve(pid) for pid in pids}
        finally:
            self._ppids = None

    def resolve(self, pid: int) -> ProcessInfo:
        cached = self._cache.get(pid)
        now = time.monotonic()
        if cached is not None:
            if not cached.create_time or now - self._checked.get(pid, 0.0) < REVALIDATE_S:
                return cached
            self._checked[pid] = now
            try:
                if psutil.Process(pid).create_time() == cached.create_time:
                    return cached
            except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
                return cached  # it just died; the last known identity is the best we have
        info = self._read(pid)
        self._cache[pid] = info
        self._checked[pid] = now
        return info

    def gc(self) -> None:
        live = set(psutil.pids())
        for pid in [p for p in self._cache if p not in live]:
            del self._cache[pid]
            self._checked.pop(pid, None)

    def _read(self, pid: int) -> ProcessInfo:
        if pid in _SPECIAL:
            name = _SPECIAL[pid]
            return ProcessInfo(pid, 0.0, name, "", name)
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                d = p.as_dict(attrs=["name", "exe", "username", "cmdline", "create_time"], ad_value=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
            return ProcessInfo(pid, 0.0, f"pid:{pid}", "", f"pid:{pid}")
        name = d.get("name") or ""
        exe = d.get("exe") or ""
        ctime = d.get("create_time") or 0.0
        cmd = " ".join(d.get("cmdline") or [])[:500]
        return ProcessInfo(pid, ctime, name, exe, app_id_for(pid, name, exe), d.get("username") or "", cmd,
                           self._parents(self._ppid(pid), ctime))

    def _ppid(self, pid: int) -> int | None:
        if self._ppids is not None:
            return self._ppids.get(pid)
        try:
            return psutil.Process(pid).ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
            return None

    def _parents(self, ppid: int | None, child_ctime: float) -> tuple[tuple[str, str], ...]:
        chain: list[tuple[str, str]] = []
        while ppid and len(chain) < self.max_parents:
            try:
                pp = psutil.Process(ppid)
                pctime = pp.create_time()
                if child_ctime and pctime > child_ctime:
                    break  # PID was reused by a younger process: the real parent is gone
                try:
                    exe = pp.exe()
                except (psutil.AccessDenied, OSError):
                    exe = ""
                chain.append((pp.name(), exe))
                ppid, child_ctime = self._ppid(ppid), pctime
            except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
                break
        return tuple(chain)
