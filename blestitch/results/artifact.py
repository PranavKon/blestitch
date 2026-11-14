"""The structured results artifact — the seam between engine and GUI.

The engine produces an :class:`AnalysisResult`; the FastAPI backend serializes
it to JSON and the React GUI renders it. Nothing in the engine depends on the
GUI. In v1 this holds packets and epochs; v2 adds device tracks, per-link
evidence, confidence and metrics.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from blestitch.records import AddressEpoch, AddrType, Packet


def _addr_hex(addr: int) -> str:
    """Render a 48-bit address as the familiar colon-separated form."""
    b = addr.to_bytes(6, "big")
    return ":".join(f"{x:02x}" for x in b)


@dataclass(slots=True)
class EpochView:
    """A GUI-ready summary of one Address Epoch."""

    address: str
    addr_type: str
    t_start_us: int
    t_end_us: int
    duration_us: int
    n_packets: int
    channels: list[int]
    rssi_mean: float
    true_device_id: int | None = None

    @classmethod
    def from_epoch(cls, e: AddressEpoch) -> "EpochView":
        rssis = [p.rssi for p in e.packets]
        return cls(
            address=_addr_hex(e.address),
            addr_type=e.addr_type.value,
            t_start_us=e.t_start_us,
            t_end_us=e.t_end_us,
            duration_us=e.duration_us,
            n_packets=e.n_packets,
            channels=sorted({p.channel for p in e.packets}),
            rssi_mean=round(sum(rssis) / len(rssis), 1) if rssis else 0.0,
            true_device_id=e.true_device_id,
        )


@dataclass(slots=True)
class AnalysisResult:
    source: str
    n_packets: int
    n_epochs: int
    epochs: list[EpochView] = field(default_factory=list)
    # address-type histogram, e.g. {"resolvable": 812, "public": 3}
    addr_type_counts: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_epochs(
        cls, epochs: list[AddressEpoch], *, source: str, n_packets: int
    ) -> "AnalysisResult":
        counts: dict[str, int] = {}
        for e in epochs:
            counts[e.addr_type.value] = counts.get(e.addr_type.value, 0) + 1
        return cls(
            source=source,
            n_packets=n_packets,
            n_epochs=len(epochs),
            epochs=[EpochView.from_epoch(e) for e in epochs],
            addr_type_counts=counts,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)
