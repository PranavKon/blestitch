"""Rolling counters: fields that tick upward and keep ticking across a rotation.

Only fields known to be counters are read. Each is reported as raw bytes plus
the rule for deciding whether a later value plausibly continues an earlier one.
"""

from __future__ import annotations

from dataclasses import dataclass

from blestitch.dissect import continuity
from blestitch.dissect.ad import AD_MANUFACTURER, AD_SERVICE_DATA_16, iter_ad_fields


@dataclass(frozen=True, slots=True)
class CounterKind:
    name: str
    label: str
    max_step: int          # largest forward jump still called "continuing"
    strength: float        # how much a continuation proves (1 = decisive)
    either_endian: bool = False   # byte order undocumented: accept either


HANDOFF = CounterKind("handoff", "Handoff sequence number", 8, 1.0, either_endian=True)
EDDYSTONE_TLM = CounterKind("eddystone-tlm", "Eddystone-TLM advertisement count", 20_000, 1.0)
# One byte wraps quickly, so a match is weaker evidence.
MIBEACON = CounterKind("mibeacon", "MiBeacon frame counter", 16, 0.5)


def extract_counters(advdata: bytes) -> dict[CounterKind, bytes]:
    """Known counter fields present in one payload, as transmitted bytes."""
    out: dict[CounterKind, bytes] = {}
    for ad_type, data in iter_ad_fields(advdata):
        if ad_type == AD_MANUFACTURER and data[:2] == b"\x4c\x00":
            for msg in continuity.parse_continuity(data[2:]):
                if msg.type == continuity.HANDOFF and len(msg.data) >= 3:
                    out[HANDOFF] = msg.data[1:3]
        elif ad_type == AD_SERVICE_DATA_16 and len(data) >= 2:
            uuid, body = (data[1] << 8) | data[0], data[2:]
            if uuid == 0xFEAA and len(body) >= 10 and body[0] == 0x20:
                out[EDDYSTONE_TLM] = body[6:10]
            elif uuid == 0xFE95 and len(body) >= 5:
                out[MIBEACON] = body[4:5]
    return out


def continues(kind: CounterKind, earlier: bytes, later: bytes) -> bool:
    """True if `later` could be `earlier` after a few more ticks."""
    if len(earlier) != len(later):
        return False
    modulus = 1 << (8 * len(earlier))
    orders = ("big", "little") if kind.either_endian else ("big",)
    return any(
        (int.from_bytes(later, o) - int.from_bytes(earlier, o)) % modulus <= kind.max_step
        for o in orders
    )
