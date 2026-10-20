"""Each heuristic's sub-rules, at and around their boundaries (docs/04-detection-engine.md §4.3)."""

from datetime import datetime

from factories import NOW, add_dest, bucket, ctx, mature_baseline, proc, window
from netsentry.detection.baseline import Baseline
from netsentry.detection.heuristics.blocklist import Blocklist
from netsentry.detection.heuristics.frequency import Frequency
from netsentry.detection.heuristics.lineage import Lineage
from netsentry.detection.heuristics.new_destination import NewDestination
from netsentry.detection.heuristics.off_hours import OffHours, in_quiet_hours
from netsentry.detection.heuristics.tls_fingerprint import TlsFingerprint
from netsentry.detection.heuristics.unusual_port import UnusualPort
from netsentry.detection.heuristics.volume import Volume
from netsentry.detection.policy import AppPolicy
from netsentry.models import PolicyRule

# ---------------------------------------------------------------- H1


def test_h1_suspicious_port() -> None:
    w = window(add_dest(bucket(), "1.2.3.0/24", "1.2.3.4", 4444))
    r = UnusualPort().evaluate(w, mature_baseline(), ctx())
    assert r.score == 1.0 and "Metasploit" in r.evidence


def test_h1_new_nonstandard_port_only_when_mature() -> None:
    w = window(add_dest(bucket(), "example.com", "1.2.3.4", 8888, "example.com"))
    assert UnusualPort().evaluate(w, mature_baseline(), ctx()).score == 0.5
    assert UnusualPort().evaluate(w, Baseline("app", NOW), ctx()).score == 0.0
    w = window(add_dest(bucket(), "example.com", "1.2.3.4", 50123, "example.com"))
    assert UnusualPort().evaluate(w, mature_baseline(), ctx()).score == 0.6


def test_h1_udp_high_ports_are_not_flagged() -> None:
    w = window(add_dest(bucket(), "example.com", "1.2.3.4", 50123, "example.com", proto="udp"))
    assert UnusualPort().evaluate(w, mature_baseline(), ctx()).score == 0.0


def test_h1_allowed_destination_skipped() -> None:
    w = window(add_dest(bucket(), "1.2.3.0/24", "1.2.3.4", 4444))
    pol = AppPolicy(dest_rules=[PolicyRule(1, "app+dest", "allow", "app", "1.2.3.4")])
    assert UnusualPort().evaluate(w, mature_baseline(), ctx(policy=pol)).score == 0.0


# ---------------------------------------------------------------- H2


def test_h2_regular_beacon() -> None:
    starts = {("9.9.9.9", 443): [NOW - 30 * i for i in range(7, -1, -1)]}
    w = window(add_dest(bucket(), "9.9.9.0/24", "9.9.9.9", 443), starts=starts)
    r = Frequency().evaluate(w, mature_baseline(), ctx())
    assert r.score == 1.0 and "every 30.0 s" in r.evidence


def test_h2_irregular_traffic_is_not_a_beacon() -> None:
    gaps = [5, 61, 12, 140, 33, 7, 90]
    ts, t = [], NOW - sum(gaps)
    for g in gaps:
        ts.append(t)
        t += g
    ts.append(t)
    w = window(add_dest(bucket(), "9.9.9.0/24", "9.9.9.9"), starts={("9.9.9.9", 443): ts})
    assert Frequency().evaluate(w, mature_baseline(), ctx()).score == 0.0


def test_h2_known_destination_is_damped() -> None:
    starts = {("9.9.9.9", 443): [NOW - 60 * i for i in range(7, -1, -1)]}
    w = window(add_dest(bucket(), "example.com", "9.9.9.9", 443, "example.com"), starts=starts)
    r = Frequency().evaluate(w, mature_baseline(), ctx())
    assert abs(r.score - 0.3) < 1e-9 and "known destination" in r.evidence


def test_h2_needs_enough_events() -> None:
    starts = {("9.9.9.9", 443): [NOW - 30 * i for i in range(4, -1, -1)]}
    w = window(add_dest(bucket(), "9.9.9.0/24", "9.9.9.9"), starts=starts)
    assert Frequency().evaluate(w, mature_baseline(), ctx()).score == 0.0


def test_h2_rate_spike() -> None:
    w = window(bucket(new_flows=60))
    r = Frequency().evaluate(w, mature_baseline(), ctx())
    assert r.score == 1.0 and "60 new connections" in r.evidence


# ---------------------------------------------------------------- H3


def test_h3_learning_is_unavailable() -> None:
    w = window(add_dest(bucket(), "new.com", "5.5.5.5", 443, "new.com"))
    assert NewDestination().evaluate(w, mature_baseline(), ctx(system_mature=False)).score is None


def test_h3_new_named_and_bare_ip() -> None:
    w = window(add_dest(bucket(), "new.com", "5.5.5.5", 443, "new.com"))
    assert NewDestination().evaluate(w, mature_baseline(), ctx()).score == 0.5
    w = window(add_dest(bucket(), "5.5.5.0/24", "5.5.5.5"))
    assert abs(NewDestination().evaluate(w, mature_baseline(), ctx()).score - 0.7) < 1e-9


def test_h3_lan_is_halved_and_known_is_quiet() -> None:
    w = window(add_dest(bucket(), "nas.local", "192.168.1.5", 445, "nas.local", cls="private"))
    assert NewDestination().evaluate(w, mature_baseline(), ctx()).score == 0.25
    w = window(add_dest(bucket(), "example.com", "1.1.1.1", 443, "example.com"))
    assert NewDestination().evaluate(w, mature_baseline(), ctx()).score == 0.0


def test_h3_new_app_after_maturity() -> None:
    w = window(add_dest(bucket(), "x.com", "5.5.5.5", 443, "x.com"))
    r = NewDestination().evaluate(w, Baseline("app", NOW - 60), ctx())
    assert r.score == 0.5 and "first time this app" in r.evidence


# ---------------------------------------------------------------- H4


def test_h4_standard_mode_unavailable() -> None:
    assert Volume().evaluate(window(), mature_baseline(), ctx(full_mode=False)).score is None


def test_h4_big_upload_vs_floor() -> None:
    b = bucket(bytes_out=200_000_000)
    b.ip_bytes_out["7.7.7.7"] = 200_000_000
    r = Volume().evaluate(window(b), mature_baseline(), ctx())
    assert r.score == 1.0 and "200.0 MB" in r.evidence
    assert Volume().evaluate(window(bucket(bytes_out=4_000_000)), mature_baseline(), ctx()).score == 0.0


def test_h4_new_app_absolute_rule() -> None:
    w = window(bucket(bytes_out=60_000_000))
    assert Volume().evaluate(w, Baseline("app", NOW - 60), ctx()).score == 0.7


# ---------------------------------------------------------------- H5


def test_h5_ip_and_domain_lists() -> None:
    w = window(add_dest(bucket(), "203.0.113.0/24", "203.0.113.66"))
    assert Blocklist().evaluate(w, None, ctx()).score == 1.0
    w = window(add_dest(bucket(), "malware-c2.invalid", "5.5.5.5", 443, "cdn.malware-c2.invalid"))
    assert Blocklist().evaluate(w, None, ctx()).score == 1.0
    w = window(add_dest(bucket(), "example.com", "5.5.5.5", 443, "example.com"))
    assert Blocklist().evaluate(w, None, ctx()).score == 0.0


# ---------------------------------------------------------------- H6


def _at_hour(h: int) -> float:
    d = datetime.fromtimestamp(NOW)
    return d.replace(hour=h, minute=30).timestamp()


def test_quiet_hours_wraparound() -> None:
    assert in_quiet_hours(2, ["01:00", "06:00"]) and not in_quiet_hours(6, ["01:00", "06:00"])
    assert in_quiet_hours(23, ["22:00", "06:00"]) and in_quiet_hours(3, ["22:00", "06:00"])


def test_h6_idle_and_quiet_hours() -> None:
    w = window(bucket(new_flows=5))
    assert OffHours().evaluate(w, mature_baseline(), ctx(now=_at_hour(14))).score == 0.0
    assert OffHours().evaluate(w, mature_baseline(), ctx(now=_at_hour(14), idle_s=900)).score == 0.6
    assert OffHours().evaluate(w, mature_baseline(), ctx(now=_at_hour(3), idle_s=900)).score == 1.0


def test_h6_insignificant_activity_ignored() -> None:
    w = window(bucket(new_flows=1))
    assert OffHours().evaluate(w, mature_baseline(), ctx(now=_at_hour(3), idle_s=900)).score == 0.0


# ---------------------------------------------------------------- H7

WORD = ("WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\WINWORD.EXE")


def _w(p):  # noqa: ANN001, ANN202
    return window(add_dest(bucket(), "x.com", "5.5.5.5", 443, "x.com"), process=p)


def test_h7_office_spawns_powershell() -> None:
    p = proc("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", (WORD,))
    assert Lineage().evaluate(_w(p), None, ctx()).score == 1.0


def test_h7_plain_script_host_and_staging() -> None:
    p = proc("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert Lineage().evaluate(_w(p), None, ctx()).score == 0.5
    p = proc("tool.exe", "C:\\Users\\me\\Downloads\\tool.exe")
    assert Lineage().evaluate(_w(p), None, ctx()).score == 0.6


def test_h7_masquerading_svchost() -> None:
    assert Lineage().evaluate(_w(proc("svchost.exe", "C:\\Users\\me\\AppData\\Local\\Temp\\svchost.exe")),
                              None, ctx()).score == 1.0
    assert Lineage().evaluate(_w(proc("svchost.exe", "C:\\Windows\\System32\\svchost.exe")),
                              None, ctx()).score == 0.0
    assert Lineage().evaluate(_w(proc("explorer.exe", "C:\\Windows\\explorer.exe")), None, ctx()).score == 0.0


# ---------------------------------------------------------------- H8


def test_h8_new_fingerprint_and_bad_list() -> None:
    b = bucket()
    b.ja3["n" * 32] = "r" * 32
    base = mature_baseline(known_ja3n={"k" * 32})
    assert TlsFingerprint().evaluate(window(b), base, ctx()).score == 0.5
    c = ctx()
    c.lists.bad_ja3.add("r" * 32)
    try:
        assert TlsFingerprint().evaluate(window(b), base, c).score == 1.0
    finally:
        c.lists.bad_ja3.discard("r" * 32)
    assert TlsFingerprint().evaluate(window(b), base, ctx(full_mode=False)).score is None
