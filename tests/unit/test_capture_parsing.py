"""TLS ClientHello parsing (SNI, JA3, JA3N), DNS answers, and IP helpers."""

import hashlib

from netsentry.capture.tls import (
    build_client_hello,
    groups_ext,
    is_grease,
    parse_client_hello,
    point_formats_ext,
    record_length,
    sni_ext,
)
from netsentry.models import ip_class, ip_prefix, normalize_ip


def _hello(ext_order: list[int]) -> bytes:
    exts = {0: sni_ext("www.example.com"), 10: groups_ext([0x2A2A, 29, 23, 24]), 11: point_formats_ext([0]),
            23: (23, b""), 0x1A1A: (0x1A1A, b""), 65281: (65281, b"\x00")}
    return build_client_hello("www.example.com", [0x0A0A, 4865, 4866, 49195], [exts[e] for e in ext_order])


def test_parses_sni_and_strips_grease() -> None:
    h = parse_client_hello(_hello([0x1A1A, 0, 23, 65281, 10, 11]))
    assert h is not None
    assert h.sni == "www.example.com"
    assert h.ciphers == (4865, 4866, 49195)
    assert h.extensions == (0, 23, 65281, 10, 11)
    assert h.groups == (29, 23, 24)
    assert h.point_formats == (0,)
    assert h.ja3_string() == "771,4865-4866-49195,0-23-65281-10-11,29-23-24,0"
    assert h.ja3 == hashlib.md5(b"771,4865-4866-49195,0-23-65281-10-11,29-23-24,0").hexdigest()


def test_ja3n_is_stable_under_extension_shuffling() -> None:
    a = parse_client_hello(_hello([0, 23, 65281, 10, 11]))
    b = parse_client_hello(_hello([11, 65281, 0, 10, 23]))
    assert a and b
    assert a.ja3 != b.ja3
    assert a.ja3n == b.ja3n


def test_rejects_non_hello_and_truncation() -> None:
    assert parse_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None
    data = _hello([0, 10, 11])
    assert record_length(data) == len(data)
    assert parse_client_hello(data[:40]) is None


def test_grease_detection() -> None:
    assert is_grease(0x0A0A) and is_grease(0xFAFA) and not is_grease(0x0A0B) and not is_grease(4865)


def test_dns_answers_map_to_question() -> None:
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    from netsentry.capture.sniffer import parse_dns

    pkt = DNS(id=1, qr=1, qd=DNSQR(qname="www.example.com"),
              an=[DNSRR(rrname="www.example.com", type="CNAME", rdata="edge.cdn.net", ttl=60),
                  DNSRR(rrname="edge.cdn.net", type="A", rdata="93.184.215.14", ttl=120)])
    ans = parse_dns(DNS(bytes(pkt)), 5.0)
    assert [(a.ip, a.qname, a.ttl) for a in ans] == [("93.184.215.14", "www.example.com", 120)]


def test_ip_helpers() -> None:
    assert normalize_ip("::ffff:10.0.0.1") == "10.0.0.1"
    assert normalize_ip("fe80::1%12") == "fe80::1"
    assert ip_class("192.168.1.4") == "private"
    assert ip_class("203.0.113.66") == "public"  # documentation range is not LAN
    assert ip_class("127.0.0.1") == "loopback"
    assert ip_class("8.8.8.8") == "public"
    assert ip_prefix("8.8.8.8") == "8.8.8.0/24"
