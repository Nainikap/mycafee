"""The eight heuristics (docs/04-detection-engine.md §4.3)."""

from .base import BaseHeuristic, HeuristicContext
from .blocklist import Blocklist
from .frequency import Frequency
from .lineage import Lineage
from .new_destination import NewDestination
from .off_hours import OffHours
from .tls_fingerprint import TlsFingerprint
from .unusual_port import UnusualPort
from .volume import Volume

ALL: list[BaseHeuristic] = [UnusualPort(), Frequency(), NewDestination(), Volume(), Blocklist(), OffHours(),
                            Lineage(), TlsFingerprint()]

__all__ = ["ALL", "BaseHeuristic", "HeuristicContext"]
