"""Per-epoch profile: everything observable about one address epoch.

The profile is what a human reads in the GUI and what the M3 clue features
compare between epochs: how the device advertises (PDU mix, cadence, payload
shape), what it says about itself (vendor, name, services, protocols) and how
its payload changes over the epoch.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from statistics import median

from blestitch.dissect import vendors
from blestitch.dissect.ad import AdSummary, ad_signature, summarize_ad
from blestitch.dissect.pdu import pdu_type_name
from blestitch.records import (
    PDU_ADV_DIRECT_IND,
    PDU_ADV_IND,
    PDU_ADV_SCAN_IND,
    PDU_CONNECT_IND,
    PDU_SCAN_REQ,
    PDU_SCAN_RSP,
    AddressEpoch,
    Packet,
)

# PDUs of one advertising event are at most 10 ms apart (Vol 6, Part B §4.4.2).
_EVENT_SPAN_US = 10_000
_MIN_INTERVAL_SAMPLES = 3
_MAX_PERIOD_DIVISOR = 6
_MIN_PERIOD_US = 20_000       # the shortest legal advertising interval
_PERIOD_TOLERANCE = 0.12      # how far from a whole multiple a gap may sit
_PERIOD_GOOD_FIT = 0.85


@dataclass(slots=True)
class PayloadVariant:
    """One distinct (PDU type, payload) an epoch transmitted."""

    pdu_type: int
    payload: bytes
    count: int
    t_first_us: int
    t_last_us: int


@dataclass(slots=True)
class EpochProfile:
    pdu_counts: dict[str, int] = field(default_factory=dict)
    channel_counts: dict[int, int] = field(default_factory=dict)
    rssi_min: int | None = None
    rssi_mean: float | None = None
    rssi_max: int | None = None
    n_events: int = 0                        # advertising events observed
    adv_interval_ms: float | None = None     # estimated advertising interval
    adv_interval_jitter_ms: float | None = None
    ad_signature: str = ""                   # shape of the dominant adv payload
    n_signatures: int = 0                    # distinct payload shapes
    variants: list[PayloadVariant] = field(default_factory=list)
    company_id: int | None = None
    vendor: str | None = None
    local_name: str | None = None
    service_uuids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    appearance: str | None = None
    tx_power: int | None = None
    connectable: bool = False
    scannable: bool = False
    has_scan_rsp: bool = False
    n_scan_req: int = 0
    n_connect_ind: int = 0
    label: str = ""                          # one-line human description


def build_profile(epoch: AddressEpoch) -> EpochProfile:
    pkts = epoch.packets
    prof = EpochProfile()

    prof.pdu_counts = dict(
        Counter(pdu_type_name(p.pdu_type, p.channel) for p in pkts)
    )
    prof.channel_counts = dict(sorted(Counter(p.channel for p in pkts).items()))

    rssis = [p.rssi for p in pkts if p.rssi is not None]
    if rssis:
        prof.rssi_min, prof.rssi_max = min(rssis), max(rssis)
        prof.rssi_mean = round(sum(rssis) / len(rssis), 1)

    types = {p.pdu_type for p in pkts}
    prof.connectable = bool(types & {PDU_ADV_IND, PDU_ADV_DIRECT_IND})
    prof.scannable = bool(types & {PDU_ADV_IND, PDU_ADV_SCAN_IND})
    prof.has_scan_rsp = PDU_SCAN_RSP in types
    prof.n_scan_req = sum(p.pdu_type == PDU_SCAN_REQ for p in epoch.interactions)
    prof.n_connect_ind = sum(
        p.pdu_type == PDU_CONNECT_IND for p in epoch.interactions
    )

    prof.n_events, prof.adv_interval_ms, prof.adv_interval_jitter_ms = (
        estimate_adv_interval(pkts)
    )

    prof.variants = _payload_variants(pkts)
    _describe(prof, pkts)
    prof.label = _label(prof)
    return prof


def estimate_adv_interval(
    pkts: list[Packet],
) -> tuple[int, float | None, float | None]:
    """Return (events seen, advertising interval ms, jitter ms).

    The interval is estimated from gaps between consecutive packets *on the
    same channel*, so it does not matter which of the three channels the
    sniffer happened to catch. Missed events show up as gaps near 2x, 3x, …
    the interval; the fundamental period is found first, then each gap is
    divided by its nearest multiple before taking the median. Jitter is the median absolute deviation of single-interval
    gaps, which for a compliant advertiser reflects its 0–10 ms advDelay.
    """
    adv = [p for p in pkts if p.pdu_type != PDU_SCAN_RSP and p.channel >= 37]

    n_events = 0
    last_t: int | None = None
    seen: set[int] = set()
    gaps: list[int] = []
    last_on_channel: dict[int, int] = {}
    for p in adv:
        if last_t is None or p.t_hw_us - last_t > _EVENT_SPAN_US or p.channel in seen:
            n_events += 1
            seen = set()
        seen.add(p.channel)
        last_t = p.t_hw_us
        prev = last_on_channel.get(p.channel)
        if prev is not None and p.t_hw_us > prev:
            gaps.append(p.t_hw_us - prev)
        last_on_channel[p.channel] = p.t_hw_us

    if len(gaps) < _MIN_INTERVAL_SAMPLES:
        return n_events, None, None

    period = _fundamental_period(sorted(gaps))
    multiples = [max(1, round(g / period)) for g in gaps]
    interval = median(g / k for g, k in zip(gaps, multiples))
    singles = [g for g, k in zip(gaps, multiples) if k == 1]
    jitter = median(abs(g - interval) for g in singles) if singles else None
    return (
        n_events,
        round(interval / 1000, 2),
        round(jitter / 1000, 2) if jitter is not None else None,
    )


def _fundamental_period(gaps: list[int]) -> float:
    """The advertising interval that best explains sorted `gaps`.

    With light loss the lower-quartile gap is one interval. With heavy loss
    (a weak device heard on one channel) even the small gaps span several
    intervals, so the quartile is tried divided by 1, 2, 3, …: the first
    divisor under which nearly every gap is a whole number of periods wins.
    """
    base = gaps[len(gaps) // 4]
    best, best_fit = float(base), -1.0
    for divisor in range(1, _MAX_PERIOD_DIVISOR + 1):
        period = base / divisor
        if period < _MIN_PERIOD_US:
            break
        fit = sum(
            abs(g / period - round(g / period)) <= _PERIOD_TOLERANCE for g in gaps
        ) / len(gaps)
        if fit >= _PERIOD_GOOD_FIT:
            return period
        if fit > best_fit:
            best, best_fit = period, fit
    return best


def _payload_variants(pkts: list[Packet]) -> list[PayloadVariant]:
    by_key: dict[tuple[int, bytes], PayloadVariant] = {}
    for p in pkts:
        key = (p.pdu_type, p.payload)
        v = by_key.get(key)
        if v is None:
            by_key[key] = PayloadVariant(
                p.pdu_type, p.payload, 1, p.t_hw_us, p.t_hw_us
            )
        else:
            v.count += 1
            v.t_last_us = p.t_hw_us
    return sorted(by_key.values(), key=lambda v: v.t_first_us)


def _describe(prof: EpochProfile, pkts: list[Packet]) -> None:
    """Fill the identity fields by merging every distinct payload's summary."""
    merged = AdSummary()
    for v in prof.variants:
        s = summarize_ad(v.payload)
        if merged.company_id is None:
            merged.company_id = s.company_id
        if s.local_name and (
            merged.local_name is None or len(s.local_name) > len(merged.local_name)
        ):
            merged.local_name = s.local_name
        for u in s.service_uuids:
            if u not in merged.service_uuids:
                merged.service_uuids.append(u)
        for tag in s.tags:
            merged.add_tag(tag)
        merged.appearance = merged.appearance or s.appearance

    prof.company_id = merged.company_id
    if merged.company_id is not None:
        prof.vendor = vendors.short_company_name(merged.company_id)
    prof.local_name = merged.local_name
    prof.service_uuids = merged.service_uuids
    prof.tags = merged.tags
    prof.appearance = merged.appearance
    prof.tx_power = next((p.tx_power for p in pkts if p.tx_power is not None), None)

    # Payload shape: the signature of the most-transmitted non-scan-response
    # payload, plus how many distinct shapes the epoch used.
    shapes = Counter(
        ad_signature(p.ad_structure) for p in pkts if p.pdu_type != PDU_SCAN_RSP
    )
    if not shapes:
        shapes = Counter(ad_signature(p.ad_structure) for p in pkts)
    prof.ad_signature = shapes.most_common(1)[0][0]
    prof.n_signatures = len(shapes)


def _label(prof: EpochProfile) -> str:
    parts: list[str] = []
    if prof.local_name:
        parts.append(f"“{prof.local_name}”")
    if prof.vendor:
        parts.append(prof.vendor)
    if prof.tags:
        parts.append(", ".join(prof.tags[:3]))
    elif not parts:
        named = [vendors.service_name(u) for u in prof.service_uuids if len(u) == 4]
        named = [n for n in named if n]
        if named:
            parts.append(named[0])
        elif prof.appearance:
            parts.append(prof.appearance)
    return " · ".join(parts)
