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
class LabeledTrace:
    """A time-ordered set of packets plus optional ground-truth labels."""

    packets: list[Packet] = field(default_factory=list)
    source: str = ""
    # address (int) -> true device id. None => blind / unlabeled.
    labels: dict[int, int] | None = None

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
