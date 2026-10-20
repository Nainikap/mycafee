"""The worked examples from docs/04-detection-engine.md §4.4, plus properties of the noisy-OR combination."""

from hypothesis import given
from hypothesis import strategies as st

from factories import CFG
from netsentry.detection.policy import AppPolicy
from netsentry.detection.scorer import combine, score
from netsentry.models import HeuristicResult, Severity

W = {"unusual_port": 0.45, "frequency": 0.55, "new_destination": 0.35, "volume": 0.60, "blocklist": 0.95,
     "off_hours": 0.25, "lineage": 0.60, "tls_fingerprint": 0.35}


def R(name: str, s: float | None) -> HeuristicResult:  # noqa: N802
    return HeuristicResult(name, name[:2], W[name], s)


def verdict(*results: HeuristicResult, pol: AppPolicy | None = None, denied: str | None = None):  # noqa: ANN201
    return score("app", 0.0, list(results), pol or AppPolicy(), CFG, denied)


def test_exfil_at_3am_is_high() -> None:
    v = verdict(R("volume", 1.0), R("new_destination", 0.7), R("off_hours", 1.0))
    assert v.score == 77 and v.severity == Severity.HIGH


def test_c2_beacon_is_high() -> None:
    v = verdict(R("frequency", 1.0), R("unusual_port", 1.0), R("new_destination", 0.7))
    assert v.score == 81 and v.severity == Severity.HIGH


def test_word_spawning_powershell_is_medium() -> None:
    v = verdict(R("lineage", 1.0), R("new_destination", 0.5))
    assert v.score == 67 and v.severity == Severity.MEDIUM


def test_chrome_new_site_is_quiet() -> None:
    v = verdict(R("new_destination", 0.5))
    assert v.score == 18 and v.severity == Severity.NONE


def test_backup_upload_is_medium_false_positive() -> None:
    assert verdict(R("volume", 1.0)).score == 60


def test_blocklist_overrides_to_high() -> None:
    v = verdict(R("blocklist", 1.0))
    assert v.score >= 80 and v.severity == Severity.HIGH


def test_unavailable_heuristics_are_skipped() -> None:
    assert verdict(R("volume", None), R("tls_fingerprint", None), R("new_destination", 0.5)).score == 18


def test_deny_forces_high() -> None:
    assert verdict(R("new_destination", 0.0), pol=AppPolicy(app_action="deny")).score == 90
    assert verdict(denied="evil.example").policy == "denied"


def test_allow_zeroes_but_not_blocklist() -> None:
    v = verdict(R("volume", 1.0), pol=AppPolicy(app_action="allow"))
    assert v.score == 0 and v.policy == "allowed"
    v = verdict(R("blocklist", 1.0), pol=AppPolicy(app_action="allow"))
    assert v.score == 60 and v.policy == "allowed-but-blocklisted"


def test_mute_keeps_score() -> None:
    v = verdict(R("volume", 1.0), pol=AppPolicy(app_action="mute"))
    assert v.score == 60 and v.policy == "muted"


scores = st.lists(st.tuples(st.sampled_from(sorted(W)), st.floats(0, 1)), max_size=8)


@given(scores)
def test_score_in_range(items: list[tuple[str, float]]) -> None:
    v = verdict(*(R(n, s) for n, s in items))
    assert 0 <= v.score <= 100


@given(scores, st.sampled_from(sorted(W)), st.floats(0, 1))
def test_adding_a_signal_never_lowers_the_score(items: list[tuple[str, float]], name: str, s: float) -> None:
    base = [R(n, x) for n, x in items]
    assert combine(base + [R(name, s)]) >= combine(base) - 1e-12
