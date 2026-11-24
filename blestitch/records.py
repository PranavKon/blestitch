"""Core shared record types for the BLE linkage pipeline.

These dataclasses are the typed contract passed between stages. Keeping them in
one place means every stage (ingestion, dissection, features, linking, eval)
agrees on the same shape, and new data sources only have to produce `Packet`s.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AddrType(str, Enum):
    """BLE advertising address type, decided by the two most-significant bits
    of the 48-bit address (Core Spec, Vol 6, Part B, 1.3.2).

    Only RESOLVABLE and NON_RESOLVABLE epochs are candidates for cross-rotation
    linking; PUBLIC and STATIC addresses do not rotate the same way.
    """

    PUBLIC = "public"            # IEEE-assigned, does not rotate
    STATIC = "static"            # top 2 bits = 0b11; stable for a power cycle
    RESOLVABLE = "resolvable"    # top 2 bits = 0b01; RPA, resolvable with IRK
    NON_RESOLVABLE = "nrpa"      # top 2 bits = 0b00; rotates, not IRK-resolvable
    UNKNOWN = "unknown"


def classify_address(addr: int, *, random: bool) -> AddrType:
    """Classify a 48-bit advertising address.

    `random` is the link-layer TxAdd/RxAdd flag: False => public address,
    True => one of the random subtypes, decided by the top two bits.
    """
    if not random:
        return AddrType.PUBLIC
    top2 = (addr >> 46) & 0b11
    if top2 == 0b01:
        return AddrType.RESOLVABLE
    if top2 == 0b00:
        return AddrType.NON_RESOLVABLE
    if top2 == 0b11:
        return AddrType.STATIC
    return AddrType.UNKNOWN  # 0b10 is reserved


# Link-layer advertising PDU types (Core Spec, Vol 6, Part B §2.3).
PDU_ADV_IND = 0x0
PDU_ADV_DIRECT_IND = 0x1
PDU_ADV_NONCONN_IND = 0x2
PDU_SCAN_REQ = 0x3
PDU_SCAN_RSP = 0x4
PDU_CONNECT_IND = 0x5
PDU_ADV_SCAN_IND = 0x6
PDU_ADV_EXT = 0x7          # ADV_EXT_IND on primary channels, AUX_* on secondary
PDU_AUX_CONNECT_RSP = 0x8

# PDUs transmitted *to* an advertiser by some other device (a scanner or an
# initiator). They tell us something happened to the advertiser, but their
# RSSI/timing belong to the other device, so they never shape an epoch.
INTERACTION_PDUS = frozenset({PDU_SCAN_REQ, PDU_CONNECT_IND})


@dataclass(slots=True)
class Packet:
    """One received BLE advertising-channel PDU, normalized across sources.

    `address` is always the **advertiser** the PDU concerns (AdvA). For PDUs
    the advertiser transmitted itself that is the sender; for SCAN_REQ and
    CONNECT_IND it is the target, and `peer_address` holds the sender.

    `t_hw_us` is the sniffer's hardware microsecond timestamp — the field the
    clock-skew feature depends on and the exact thing OS-level scanners lose.
    """

    t_hw_us: int                 # hardware arrival timestamp, microseconds
    channel: int                 # channel index: 37/38/39 primary, 0-36 secondary
    rssi: int | None             # dBm; None if the capture has no signal power
    address: int                 # 48-bit advertiser address (AdvA)
    addr_random: bool            # True if the advertiser address is random
    addr_type: AddrType
    pdu_type: int                # LL advertising PDU type
    chsel: bool                  # Channel Selection Algorithm #2 supported
    tx_power: int | None         # dBm, if advertised
    ad_structure: tuple[tuple[int, int], ...] = ()   # ordered (AD type, length)
    payload: bytes = b""         # raw AdvData / ScanRspData bytes
    source: str = ""             # capture provenance (e.g. "pcap:foo.pcapng")
    peer_address: int | None = None   # TargetA, or ScanA/InitA for interactions
    peer_random: bool = False
    ext_sid: int | None = None   # extended advertising: Advertising Set ID
    ext_did: int | None = None   # extended advertising: Advertising Data ID

    @property
    def from_advertiser(self) -> bool:
        """True when the advertiser itself transmitted this PDU."""
        return self.pdu_type not in INTERACTION_PDUS


@dataclass(slots=True)
class AddressEpoch:
    """All contiguous packets sharing one temporary address — the unit we link.

    `packets` holds only PDUs the advertiser transmitted, so every statistic
    derived from them (RSSI, cadence, payload) describes that one device.

    Built in Stage 2. `true_device_id` is filled only for ground-truth/benchmark
    data (via IRK resolution); it is None for blind analysis.
    """

    address: int
    addr_type: AddrType
    t_start_us: int
    t_end_us: int
    packets: list[Packet] = field(default_factory=list)
    # SCAN_REQ / CONNECT_IND aimed at this address while it was on air.
    interactions: list[Packet] = field(default_factory=list)
    true_device_id: int | None = None   # ground-truth label, when available

    @property
    def n_packets(self) -> int:
        return len(self.packets)

    @property
    def duration_us(self) -> int:
        return self.t_end_us - self.t_start_us

    @property
    def timestamps_us(self) -> list[int]:
        return [p.t_hw_us for p in self.packets]


@dataclass(slots=True)
class Clue:
    """One piece of evidence for or against "these two epochs are one device".

    `evidence` runs from -1 (contradicts) through 0 (says nothing) to +1
    (supports); `weight` is how much the matcher trusts this kind of clue.
    `detail` is a short human-readable account shown in the GUI.
    """

    name: str
    evidence: float
    weight: float
    detail: str

    @property
    def contribution(self) -> float:
        return self.evidence * self.weight


@dataclass(slots=True)
class Link:
    """A scored claim that epoch `a` is followed by epoch `b` on one device.

    kind "rotation": the device changed address between the two epochs.
    kind "same_address": the same address was simply seen again after a gap.
    """

    a: int                       # epoch id of the earlier epoch
    b: int                       # epoch id of the later epoch
    kind: str
    gap_us: int
    total: float = 0.0           # sum of clue contributions
    score: float = 1.0           # total squashed to 0..1; 0.5 is the accept line
    clues: list[Clue] = field(default_factory=list)
    # How far ahead of the best competing link for either epoch (None: unrivalled).
    margin: float | None = None


@dataclass(slots=True)
class DeviceTrack:
    """One stitched device trail: its epochs in time order."""

    id: int
    epoch_ids: list[int] = field(default_factory=list)
