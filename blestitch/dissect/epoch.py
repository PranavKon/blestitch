"""Stage 2: group packets into Address Epochs.

An *epoch* is every packet one advertiser sent under one temporary address, in
a contiguous stretch of time. It is the unit the stitcher links across
rotations.

Grouping is by (address, public/random), then split on long silences: if the
same address reappears after a gap larger than ``max_gap_us`` it becomes a new
epoch, so a device that walked out of range and back shows up as two visits.
Resolvable private addresses are effectively unique per rotation, so each
address normally yields one epoch per visit.

SCAN_REQ and CONNECT_IND PDUs are sent *to* an advertiser by another device.
They never start or extend an epoch; they are attached to the epoch they were
aimed at as `interactions`.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from itertools import pairwise

from blestitch.records import AddressEpoch, Packet

# Default: a silence longer than this starts a new epoch for the same address.
# Generous on purpose — slow advertisers (trackers at ~2 s) seen through a
# channel-hopping sniffer routinely go many seconds between captured packets.
DEFAULT_MAX_GAP_US = 30_000_000  # 30 s


def segment_epochs(
    packets: list[Packet], *, max_gap_us: int = DEFAULT_MAX_GAP_US
) -> list[AddressEpoch]:
    """Return epochs sorted by start time."""
    own: dict[tuple[int, bool], list[Packet]] = defaultdict(list)
    aimed: dict[tuple[int, bool], list[Packet]] = defaultdict(list)
    for p in packets:
        bucket = own if p.from_advertiser else aimed
        bucket[(p.address, p.addr_random)].append(p)

    epochs: list[AddressEpoch] = []
    for key, pkts in own.items():
        pkts.sort(key=lambda p: p.t_hw_us)
        runs: list[AddressEpoch] = []
        run: list[Packet] = [pkts[0]]
        for prev, cur in pairwise(pkts):
            if cur.t_hw_us - prev.t_hw_us > max_gap_us:
                runs.append(_build_epoch(run))
                run = [cur]
            else:
                run.append(cur)
        runs.append(_build_epoch(run))
        _attach_interactions(runs, aimed.get(key, ()), max_gap_us)
        epochs.extend(runs)

    epochs.sort(key=lambda e: e.t_start_us)
    return epochs


def _build_epoch(pkts: list[Packet]) -> AddressEpoch:
    return AddressEpoch(
        address=pkts[0].address,
        addr_type=pkts[0].addr_type,
        t_start_us=pkts[0].t_hw_us,
        t_end_us=pkts[-1].t_hw_us,
        packets=pkts,
    )


def _attach_interactions(
    runs: list[AddressEpoch], interactions, max_gap_us: int
) -> None:
    """Give each interaction to the epoch of its target address that was on
    air at the time (or within `max_gap_us` of it). `runs` is time-ordered."""
    if not interactions:
        return
    starts = [e.t_start_us for e in runs]
    for p in sorted(interactions, key=lambda p: p.t_hw_us):
        i = bisect_right(starts, p.t_hw_us) - 1
        candidates = [runs[j] for j in (i, i + 1) if 0 <= j < len(runs)]
        for e in candidates:
            if e.t_start_us - max_gap_us <= p.t_hw_us <= e.t_end_us + max_gap_us:
                e.interactions.append(p)
                break
