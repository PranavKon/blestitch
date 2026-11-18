"""Stage 2: group packets into Address Epochs.

An *epoch* is every packet sharing one temporary advertising address, in a
contiguous stretch of time. It is the unit the stitcher links across rotations.

Grouping is by address, then split on long silences: if the same address
reappears after a gap larger than ``max_gap_us`` it is treated as a new epoch
(an address can, rarely, be reused much later). Resolvable private addresses are
effectively unique per rotation, so in practice each address yields one epoch.
"""

from __future__ import annotations

from collections import defaultdict

from blestitch.records import AddressEpoch, Packet

# Default: a silence longer than this starts a new epoch for the same address.
DEFAULT_MAX_GAP_US = 5_000_000  # 5 s


def segment_epochs(
    packets: list[Packet], *, max_gap_us: int = DEFAULT_MAX_GAP_US
) -> list[AddressEpoch]:
    """Return epochs sorted by start time."""
    by_addr: dict[int, list[Packet]] = defaultdict(list)
    for p in packets:
        by_addr[p.address].append(p)

    epochs: list[AddressEpoch] = []
    for addr, pkts in by_addr.items():
        pkts.sort(key=lambda p: p.t_hw_us)
        run: list[Packet] = [pkts[0]]
        for prev, cur in zip(pkts, pkts[1:]):
            if cur.t_hw_us - prev.t_hw_us > max_gap_us:
                epochs.append(_build_epoch(addr, run))
                run = [cur]
            else:
                run.append(cur)
        epochs.append(_build_epoch(addr, run))

    epochs.sort(key=lambda e: e.t_start_us)
    return epochs


def _build_epoch(address: int, pkts: list[Packet]) -> AddressEpoch:
    return AddressEpoch(
        address=address,
        addr_type=pkts[0].addr_type,
        t_start_us=pkts[0].t_hw_us,
        t_end_us=pkts[-1].t_hw_us,
        packets=pkts,
    )
