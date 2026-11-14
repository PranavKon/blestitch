"""Top-level v1 pipeline: PCAP -> epochs -> results artifact.

This is the single entrypoint the FastAPI backend calls. Linking/stitching is
layered on top at M3; for the M1 vertical slice it stops at epoch segmentation
so the whole engine -> artifact -> GUI seam can be proven end to end.
"""

from __future__ import annotations

from pathlib import Path

from blestitch.dissect.epoch import DEFAULT_MAX_GAP_US, segment_epochs
from blestitch.io.pcap_reader import read_pcap
from blestitch.results.artifact import AnalysisResult


def analyze_pcap(
    path: str | Path, *, max_gap_us: int = DEFAULT_MAX_GAP_US
) -> AnalysisResult:
    trace = read_pcap(path)
    epochs = segment_epochs(trace.packets, max_gap_us=max_gap_us)
    return AnalysisResult.from_epochs(
        epochs, source=trace.source, n_packets=len(trace.packets)
    )
