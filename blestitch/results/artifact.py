"""The structured results artifact — the seam between engine and GUI.

The engine produces an :class:`AnalysisResult`; the FastAPI backend serializes
it to JSON and the React GUI renders it. Nothing in the engine depends on the
GUI.

The top-level result carries one compact :class:`EpochView` per epoch — enough
to draw the timeline and the epoch table for a capture with thousands of
epochs. Packet-level detail is produced on demand by :func:`epoch_detail` and
:func:`packet_rows`, so a large capture never has to ship every packet to the
browser at once. M3 adds device tracks and per-link evidence.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from blestitch.dissect.ad import decode_ad
from blestitch.dissect.pdu import pdu_type_name
from blestitch.dissect.profile import EpochProfile, build_profile
from blestitch.io.labeled_trace import CaptureStats
from blestitch.records import AddressEpoch, Packet

SCHEMA_VERSION = 2


def addr_hex(addr: int) -> str:
    """Render a 48-bit address as the familiar colon-separated form."""
    b = addr.to_bytes(6, "big")
    return ":".join(f"{x:02x}" for x in b)


@dataclass(slots=True)
class EpochView:
    """A GUI-ready summary of one Address Epoch."""

    id: int
    address: str
    addr_type: str
    t_start_us: int
    t_end_us: int
    duration_us: int
    n_packets: int
    channels: list[int]
    rssi_mean: float | None
    rssi_min: int | None
    rssi_max: int | None
    label: str
    vendor: str | None
    company_id: int | None
    local_name: str | None
    tags: list[str]
    service_uuids: list[str]
    appearance: str | None
    tx_power: int | None
    pdu_counts: dict[str, int]
    channel_counts: dict[int, int]
    n_events: int
    adv_interval_ms: float | None
    adv_interval_jitter_ms: float | None
    ad_signature: str
    n_signatures: int
    n_payload_variants: int
    connectable: bool
    scannable: bool
    has_scan_rsp: bool
    n_scan_req: int
    n_connect_ind: int
    true_device_id: int | None = None

    @classmethod
    def from_epoch(
        cls, e: AddressEpoch, epoch_id: int = 0, profile: EpochProfile | None = None
    ) -> EpochView:
        p = profile or build_profile(e)
        return cls(
            id=epoch_id,
            address=addr_hex(e.address),
            addr_type=e.addr_type.value,
            t_start_us=e.t_start_us,
            t_end_us=e.t_end_us,
            duration_us=e.duration_us,
            n_packets=e.n_packets,
            channels=sorted(p.channel_counts),
            rssi_mean=p.rssi_mean,
            rssi_min=p.rssi_min,
            rssi_max=p.rssi_max,
            label=p.label,
            vendor=p.vendor,
            company_id=p.company_id,
            local_name=p.local_name,
            tags=p.tags,
            service_uuids=p.service_uuids,
            appearance=p.appearance,
            tx_power=p.tx_power,
            pdu_counts=p.pdu_counts,
            channel_counts=p.channel_counts,
            n_events=p.n_events,
            adv_interval_ms=p.adv_interval_ms,
            adv_interval_jitter_ms=p.adv_interval_jitter_ms,
            ad_signature=p.ad_signature,
            n_signatures=p.n_signatures,
            n_payload_variants=len(p.variants),
            connectable=p.connectable,
            scannable=p.scannable,
            has_scan_rsp=p.has_scan_rsp,
            n_scan_req=p.n_scan_req,
            n_connect_ind=p.n_connect_ind,
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
    t_min_us: int = 0
    t_max_us: int = 0
    capture: CaptureStats = field(default_factory=CaptureStats)
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def from_epochs(
        cls,
        epochs: list[AddressEpoch],
        *,
        source: str,
        n_packets: int,
        profiles: list[EpochProfile] | None = None,
        capture: CaptureStats | None = None,
    ) -> AnalysisResult:
        if profiles is None:
            profiles = [build_profile(e) for e in epochs]
        counts: dict[str, int] = {}
        for e in epochs:
            counts[e.addr_type.value] = counts.get(e.addr_type.value, 0) + 1
        return cls(
            source=source,
            n_packets=n_packets,
            n_epochs=len(epochs),
            epochs=[
                EpochView.from_epoch(e, i, p)
                for i, (e, p) in enumerate(zip(epochs, profiles))
            ],
            addr_type_counts=counts,
            t_min_us=min((e.t_start_us for e in epochs), default=0),
            t_max_us=max((e.t_end_us for e in epochs), default=0),
            capture=capture or CaptureStats(n_packets=n_packets),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# --------------------------------------------------------------------------
# On-demand drilldown
# --------------------------------------------------------------------------


def epoch_detail(
    epoch: AddressEpoch, profile: EpochProfile, *, variant_limit: int = 200
) -> dict[str, Any]:
    """Every distinct payload the epoch sent, decoded field by field.

    Variants are in order of first appearance, which is what makes a rolling
    counter or a changing token visible at a glance.
    """
    variants = []
    for i, v in enumerate(profile.variants[:variant_limit]):
        variants.append(
            {
                "index": i,
                "pdu": pdu_type_name(v.pdu_type),
                "count": v.count,
                "t_first_us": v.t_first_us,
                "t_last_us": v.t_last_us,
                "hex": v.payload.hex(),
                "fields": [f.to_dict() for f in decode_ad(v.payload)],
            }
        )
    return {
        "n_variants": len(profile.variants),
        "variants": variants,
        "n_rows": len(epoch.packets) + len(epoch.interactions),
    }


def packet_rows(
    epoch: AddressEpoch,
    profile: EpochProfile,
    *,
    offset: int = 0,
    limit: int = 500,
) -> dict[str, Any]:
    """A page of the epoch's packets (its own PDUs and the SCAN_REQ /
    CONNECT_IND aimed at it), in time order."""
    variant_index = {
        (v.pdu_type, v.payload): i for i, v in enumerate(profile.variants)
    }
    merged: list[Packet] = sorted(
        [*epoch.packets, *epoch.interactions], key=lambda p: p.t_hw_us
    )
    rows = []
    for p in merged[offset : offset + limit]:
        rows.append(
            {
                "t_us": p.t_hw_us,
                "channel": p.channel,
                "rssi": p.rssi,
                "pdu": pdu_type_name(p.pdu_type, p.channel),
                "from_advertiser": p.from_advertiser,
                "peer": addr_hex(p.peer_address) if p.peer_address is not None else None,
                "variant": variant_index.get((p.pdu_type, p.payload))
                if p.from_advertiser
                else None,
                "length": len(p.payload),
            }
        )
    return {"total": len(merged), "offset": offset, "rows": rows}
