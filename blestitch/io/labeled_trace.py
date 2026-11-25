"""The data-source seam.

Every capture source (nRF Sniffer PCAP today; the "Learning to Link" dataset,
SimBle, or post-hardware self-captures later) is adapted into a `LabeledTrace`.
Nothing downstream of this module knows or cares where the packets came from —
that is what lets us swap data sources in v2 with no change to the engine.

`labels` is populated only for ground-truth/benchmark data (via IRK resolution in
v2). For blind v1 analysis it stays None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from blestitch.records import Packet


@dataclass(slots=True)
class CaptureStats:
    """What the reader did with every record in a capture file.

    Anything not turned into a `Packet` is counted here rather than silently
    dropped, so the GUI can show how much of the capture was usable.
    """

    n_records: int = 0          # records in the file, on any interface
    n_packets: int = 0          # advertising PDUs kept
    n_bad_crc: int = 0          # failed the sniffer's CRC check (dropped)
    n_data_channel: int = 0     # connection traffic, not advertising (dropped)
    n_unattributed: int = 0     # extended adv with no advertiser address
    n_malformed: int = 0        # too short / truncated to parse
    n_unsupported_link: int = 0  # records on a link type we do not read
    link_types: list[str] = field(default_factory=list)
    # "firmware": sniffer hardware clock; "capture": host/record timestamps.
    time_source: str = "capture"


@dataclass(slots=True)
class LabeledTrace:
    """A time-ordered set of packets plus optional ground-truth labels."""

    packets: list[Packet] = field(default_factory=list)
    source: str = ""
    # address (int) -> true device id. None => blind / unlabeled.
    labels: dict[int, int] | None = None
    stats: CaptureStats = field(default_factory=CaptureStats)

    def __len__(self) -> int:
        return len(self.packets)

    @property
    def is_labeled(self) -> bool:
        return self.labels is not None

    def sorted_by_time(self) -> list[Packet]:
        return sorted(self.packets, key=lambda p: p.t_hw_us)


@runtime_checkable
class TraceSource(Protocol):
    """Anything that can produce a LabeledTrace."""

    def load(self) -> LabeledTrace: ...
