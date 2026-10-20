"""TLS ClientHello parsing: SNI, JA3 and normalised JA3 (JA3N, extensions sorted).

Chrome randomises the order of its TLS extensions, so raw JA3 changes on every connection.
JA3N sorts the extension list, which keeps the fingerprint stable per TLS client stack.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass(frozen=True, slots=True)
class ClientHello:
    version: int
    ciphers: tuple[int, ...]
    extensions: tuple[int, ...]
    groups: tuple[int, ...]
    point_formats: tuple[int, ...]
    sni: str

    def ja3_string(self, sort_extensions: bool = False) -> str:
        exts = sorted(self.extensions) if sort_extensions else self.extensions
        return ",".join([
            str(self.version),
            "-".join(map(str, self.ciphers)),
            "-".join(map(str, exts)),
            "-".join(map(str, self.groups)),
            "-".join(map(str, self.point_formats)),
        ])

    @property
    def ja3(self) -> str:
        return hashlib.md5(self.ja3_string().encode()).hexdigest()

    @property
    def ja3n(self) -> str:
        return hashlib.md5(self.ja3_string(sort_extensions=True).encode()).hexdigest()


def record_length(data: bytes) -> int | None:
    """Total bytes needed for the first TLS handshake record, or None if this isn't a ClientHello start."""
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return None
    return 5 + struct.unpack(">H", data[3:5])[0]


def parse_client_hello(data: bytes) -> ClientHello | None:
    """Parse a TLS record containing a ClientHello. Returns None for anything else or truncated data."""
    try:
        if record_length(data) is None:
            return None
        p = 5
        hs_len = int.from_bytes(data[p + 1:p + 4], "big")
        body = data[p + 4:p + 4 + hs_len]
        i = 0
        version = struct.unpack(">H", body[i:i + 2])[0]
        i += 2 + 32  # version + random
        i += 1 + body[i]  # session id
        (cs_len,) = struct.unpack(">H", body[i:i + 2])
        i += 2
        ciphers = tuple(v for v in struct.unpack(f">{cs_len // 2}H", body[i:i + cs_len]) if not is_grease(v))
        i += cs_len
        i += 1 + body[i]  # compression methods
        exts: list[int] = []
        groups: tuple[int, ...] = ()
        fmts: tuple[int, ...] = ()
        sni = ""
        if i + 2 <= len(body):
            (ext_total,) = struct.unpack(">H", body[i:i + 2])
            i += 2
            end = i + ext_total
            if end > len(body):
                return None
            while i + 4 <= end:
                etype, elen = struct.unpack(">HH", body[i:i + 4])
                ed = body[i + 4:i + 4 + elen]
                i += 4 + elen
                if is_grease(etype):
                    continue
                exts.append(etype)
                if etype == 0 and len(ed) >= 5:  # server_name
                    nlen = struct.unpack(">H", ed[3:5])[0]
                    sni = ed[5:5 + nlen].decode("ascii", "replace")
                elif etype == 10 and len(ed) >= 2:  # supported_groups
                    glen = struct.unpack(">H", ed[:2])[0]
                    groups = tuple(g for g in struct.unpack(f">{glen // 2}H", ed[2:2 + glen]) if not is_grease(g))
                elif etype == 11 and ed:  # ec_point_formats
                    fmts = tuple(ed[1:1 + ed[0]])
        return ClientHello(version, ciphers, tuple(exts), groups, fmts, sni)
    except (struct.error, IndexError):
        return None


def build_client_hello(sni: str, ciphers: list[int], extensions: list[tuple[int, bytes]],
                       version: int = 0x0303) -> bytes:
    """Builds a minimal ClientHello record. Used by tests and the simulators, not by the sniffer."""
    exts = b""
    for etype, edata in extensions:
        exts += struct.pack(">HH", etype, len(edata)) + edata
    body = struct.pack(">H", version) + b"\x00" * 32 + b"\x00"
    body += struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)
    body += b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def sni_ext(name: str) -> tuple[int, bytes]:
    n = name.encode()
    entry = b"\x00" + struct.pack(">H", len(n)) + n
    return 0, struct.pack(">H", len(entry)) + entry


def groups_ext(groups: list[int]) -> tuple[int, bytes]:
    return 10, struct.pack(">H", len(groups) * 2) + b"".join(struct.pack(">H", g) for g in groups)


def point_formats_ext(fmts: list[int]) -> tuple[int, bytes]:
    return 11, bytes([len(fmts), *fmts])
