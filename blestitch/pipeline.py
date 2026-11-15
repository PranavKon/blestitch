"""Top-level v1 pipeline: capture -> packets -> epochs -> results artifact.

This is the single entrypoint the FastAPI backend calls. Linking/stitching is
layered on top at M3; today the pipeline stops at profiled address epochs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from blestitch.dissect.epoch import DEFAULT_MAX_GAP_US, segment_epochs
from blestitch.dissect.profile import EpochProfile, build_profile
from blestitch.io.pcap_reader import read_capture
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


def analyze_bytes(
    data: bytes, *, source: str = "pcap", max_gap_us: int = DEFAULT_MAX_GAP_US
) -> Analysis:
    packets, stats = read_capture(data, source=source)
    epochs = segment_epochs(packets, max_gap_us=max_gap_us)
    profiles = [build_profile(e) for e in epochs]
    result = AnalysisResult.from_epochs(
        epochs,
        source=source,
        n_packets=len(packets),
        profiles=profiles,
        capture=stats,
    )
    return Analysis(result=result, epochs=epochs, profiles=profiles)


def analyze_pcap(
    path: str | Path, *, max_gap_us: int = DEFAULT_MAX_GAP_US
) -> AnalysisResult:
    path = Path(path)
    return analyze_bytes(
        path.read_bytes(), source=f"pcap:{path.name}", max_gap_us=max_gap_us
    ).result
