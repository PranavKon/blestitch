"""Top-level v1 pipeline: capture -> packets -> epochs -> stitched trails.

This is the single entrypoint the FastAPI backend calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from blestitch.dissect.epoch import DEFAULT_MAX_GAP_US, segment_epochs
from blestitch.dissect.profile import EpochProfile, build_profile
from blestitch.io.pcap_reader import read_capture
from blestitch.link.heuristic import MatcherConfig
from blestitch.link.solver import StitchResult, stitch
from blestitch.records import AddressEpoch
from blestitch.results.artifact import AnalysisResult


@dataclass(slots=True)
class Analysis:
    """A finished run: the artifact plus the engine objects behind it, kept so
    packet-level drilldown can be answered without re-parsing the capture.
    `epochs[i]` and `profiles[i]` belong to `result.epochs[i]`."""

    result: AnalysisResult
    epochs: list[AddressEpoch]
    profiles: list[EpochProfile]
    stitched: StitchResult


def analyze_bytes(
    data: bytes,
    *,
    source: str = "pcap",
    max_gap_us: int = DEFAULT_MAX_GAP_US,
    matcher: MatcherConfig | None = None,
) -> Analysis:
    matcher = matcher or MatcherConfig()
    packets, stats = read_capture(data, source=source)
    epochs = segment_epochs(packets, max_gap_us=max_gap_us)
    profiles = [build_profile(e) for e in epochs]
    stitched = stitch(epochs, profiles, matcher)
    result = AnalysisResult.from_epochs(
        epochs,
        source=source,
        n_packets=len(packets),
        profiles=profiles,
        capture=stats,
        stitched=stitched,
        matcher=matcher,
    )
    return Analysis(result=result, epochs=epochs, profiles=profiles, stitched=stitched)


def analyze_pcap(
    path: str | Path, *, max_gap_us: int = DEFAULT_MAX_GAP_US
) -> AnalysisResult:
    path = Path(path)
    return analyze_bytes(
        path.read_bytes(), source=f"pcap:{path.name}", max_gap_us=max_gap_us
    ).result
