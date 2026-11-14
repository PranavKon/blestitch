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


@dataclass(slots=True)
class Packet:
    """One received BLE advertising PDU, normalized across capture sources.

    `t_hw_us` is the sniffer's hardware microsecond timestamp — the field the
    clock-skew feature depends on and the exact thing OS-level scanners lose.
    """

    t_hw_us: int                 # hardware arrival timestamp, microseconds
    channel: int                 # advertising channel: 37, 38, or 39
    rssi: int                    # dBm
    address: int                 # 48-bit advertiser address
    addr_random: bool            # True if TxAdd=random
    addr_type: AddrType
    pdu_type: int                # LL advertising PDU type
    chsel: bool                  # Channel Selection Algorithm #2 supported
    tx_power: int | None         # dBm, if advertised
    ad_structure: tuple[tuple[int, int], ...] = ()   # ordered (AD type, length)
    payload: bytes = b""         # raw AdvData payload bytes
    source: str = ""             # capture provenance (e.g. "nrf", "simble")


@dataclass(slots=True)
class AddressEpoch:
    """All contiguous packets sharing one temporary address — the unit we link.

    Built in Stage 2. `true_device_id` is filled only for ground-truth/benchmark
    data (via IRK resolution); it is None for blind analysis.
    """

    address: int
    addr_type: AddrType
    t_start_us: int
    t_end_us: int
    packets: list[Packet] = field(default_factory=list)
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
