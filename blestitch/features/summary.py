"""Per-epoch features the pairwise clues compare.

Everything here is derived once per epoch from its packets and profile, so
scoring a candidate pair is cheap no matter how many packets each side has.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median

from blestitch.dissect.ad import ad_signature, ad_structure
from blestitch.dissect.profile import EpochProfile
from blestitch.features.counters import CounterKind, extract_counters
from blestitch.features.tokens import NAME, Token, extract_tokens
from blestitch.records import PDU_SCAN_RSP, AddressEpoch

# RSSI is compared at the seam: the end of one epoch against the start of the
# next, not epoch averages, because people carry devices around.
_EDGE_PACKETS = 30
_EDGE_WINDOW_US = 20_000_000
# Payload variants examined per epoch (earliest and latest), to bound the work
# on epochs whose payload changes constantly.
_EDGE_VARIANTS = 40


@dataclass(slots=True)
class EpochFeatures:
    rssi_head: float | None = None      # median RSSI of the first packets
    rssi_tail: float | None = None      # median RSSI of the last packets
    interval_ms: float | None = None
    observed_gap_us: float = 0.0        # typical time between packets we heard
    signatures: frozenset[str] = frozenset()       # payload shapes used
    type_sequences: frozenset[tuple[int, ...]] = frozenset()
    tokens: frozenset[Token] = frozenset()
    name: bytes | None = None
    # Per counter kind: value at the start and at the end of the epoch.
    counters: dict[CounterKind, tuple[bytes, bytes]] = field(default_factory=dict)


def build_features(epoch: AddressEpoch, profile: EpochProfile) -> EpochFeatures:
    f = EpochFeatures(interval_ms=profile.adv_interval_ms)
    pkts = epoch.packets

    head = [p for p in pkts[:_EDGE_PACKETS] if p.t_hw_us - epoch.t_start_us <= _EDGE_WINDOW_US]
    tail = [p for p in pkts[-_EDGE_PACKETS:] if epoch.t_end_us - p.t_hw_us <= _EDGE_WINDOW_US]
    f.rssi_head = _median_rssi(head)
    f.rssi_tail = _median_rssi(tail)

    if profile.n_events > 1:
        f.observed_gap_us = epoch.duration_us / (profile.n_events - 1)

    variants = profile.variants
    if len(variants) > 2 * _EDGE_VARIANTS:
        variants = variants[:_EDGE_VARIANTS] + variants[-_EDGE_VARIANTS:]

    signatures: set[str] = set()
    sequences: set[tuple[int, ...]] = set()
    tokens: set[Token] = set()
    for v in variants:
        if v.pdu_type != PDU_SCAN_RSP:
            structure = ad_structure(v.payload)
            signatures.add(ad_signature(structure))
            sequences.add(tuple(t for t, _ in structure))
        tokens |= extract_tokens(v.payload)
        for kind, value in extract_counters(v.payload).items():
            first, _ = f.counters.get(kind, (value, value))
            f.counters[kind] = (first, value)
    f.signatures = frozenset(signatures)
    f.type_sequences = frozenset(sequences)
    f.tokens = frozenset(tokens)

    names = [value for kind, value in tokens if kind == NAME]
    f.name = max(names, key=len) if names else None
    return f


def _median_rssi(pkts) -> float | None:
    values = [p.rssi for p in pkts if p.rssi is not None]
    return float(median(values)) if values else None
