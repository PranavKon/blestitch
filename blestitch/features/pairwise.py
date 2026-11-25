"""The clues: what two epochs have in common across a possible handoff.

Each clue looks at one aspect of an earlier epoch A and a later epoch B and
returns evidence between -1 (this contradicts "same device") and +1 (this
supports it), or None when it has nothing to say. The matcher weighs and sums
them; nothing here decides anything on its own.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from blestitch.features.counters import continues
from blestitch.features.summary import EpochFeatures
from blestitch.features.tokens import Token, describe_token, token_strength

# Evidence shape parameters. These are judgement calls, tuned against the
# rotation fixture and a real household capture; M4 exposes the important
# ones as run controls.
_MIN_TIMING_SCALE_US = 2_000_000
_CADENCE_ZERO_AT = 0.025      # relative interval difference giving no evidence
_RSSI_ZERO_AT_DB = 8.0        # seam RSSI jump giving no evidence
_CARRYOVER_FLOOR = 0.2        # weaker shared content is treated as none


@dataclass(slots=True)
class Evidence:
    value: float
    detail: str


def timing(gap_us: int, a: EpochFeatures, b: EpochFeatures) -> Evidence:
    """A rotation is a clean cut: the new address appears as soon as the old
    one stops. How soon we *hear* it depends on how often we were hearing the
    device at all, so the gap is judged against that."""
    scale = max(_MIN_TIMING_SCALE_US, 3 * max(a.observed_gap_us, b.observed_gap_us))
    value = math.exp(-max(0, gap_us) / scale)
    return Evidence(value, f"new address heard {gap_us / 1e6:.2f} s after the old one went quiet")


def structure(a: EpochFeatures, b: EpochFeatures) -> Evidence | None:
    """Firmware lays its advertisement out the same way before and after."""
    if not a.signatures or not b.signatures:
        return None
    shared = a.signatures & b.signatures
    if shared:
        share = len(shared) / len(a.signatures | b.signatures)
        value = 0.7 + 0.3 * share
        return Evidence(value, f"same payload layout ({min(shared) or 'empty'})")
    if a.type_sequences & b.type_sequences:
        return Evidence(0.2, "same fields in the same order, different lengths")
    return Evidence(-1.0, "different payload layouts")


def cadence(a: EpochFeatures, b: EpochFeatures) -> Evidence | None:
    """The advertising interval is a firmware setting and does not rotate."""
    if a.interval_ms is None or b.interval_ms is None:
        return None
    rel = abs(a.interval_ms - b.interval_ms) / max(a.interval_ms, b.interval_ms)
    value = max(-1.0, 1.0 - rel / _CADENCE_ZERO_AT)
    return Evidence(value, f"advertising interval {a.interval_ms:g} ms → {b.interval_ms:g} ms")


def rssi(a: EpochFeatures, b: EpochFeatures) -> Evidence | None:
    """Signal strength just before and just after: a device does not teleport."""
    if a.rssi_tail is None or b.rssi_head is None:
        return None
    jump = abs(a.rssi_tail - b.rssi_head)
    value = max(-1.0, 1.0 - jump / _RSSI_ZERO_AT_DB)
    return Evidence(value, f"signal {a.rssi_tail:g} dBm → {b.rssi_head:g} dBm")


def carryover(
    a: EpochFeatures, b: EpochFeatures, rarity: dict[Token, int]
) -> Evidence | None:
    """Payload content that stayed the same when the address changed.

    `rarity[token]` is the largest number of addresses seen sending that token
    at the same moment — a floor on how many devices share it. A token only
    one device ever sends at a time is close to an identifier; one that ten
    devices send at once (a flags byte) says almost nothing.
    """
    if a.name is not None and b.name is not None and a.name != b.name:
        return Evidence(-1.0, "different device names")
    shared = a.tokens & b.tokens
    if not shared:
        return None
    strength = {t: token_strength(t, rarity.get(t, 1)) for t in shared}
    # Name the strongest token; break ties the same way every run (shortest
    # value first, so a bare address is named rather than the blob around it).
    best = min(strength, key=lambda t: (-strength[t], len(t[1]), t))
    miss = 1.0
    for s in strength.values():
        miss *= 1.0 - s
    value = 1.0 - miss
    if value < _CARRYOVER_FLOOR:
        return None  # only boilerplate in common: not worth reporting
    sharers = rarity.get(best, 1)
    uniqueness = (
        "sent by no other address at the same time"
        if sharers <= 1
        else f"also sent by up to {sharers} addresses at once"
    )
    return Evidence(value, f"unchanged {describe_token(best)}, {uniqueness}")


def counter(a: EpochFeatures, b: EpochFeatures) -> Evidence | None:
    """A rolling counter that picks up where it left off."""
    best: Evidence | None = None
    for kind, (_, last) in a.counters.items():
        if kind not in b.counters:
            continue
        first, _ = b.counters[kind]
        if continues(kind, last, first):
            ev = Evidence(kind.strength, f"{kind.label} continues: {last.hex()} → {first.hex()}")
        else:
            ev = Evidence(-0.5, f"{kind.label} does not continue: {last.hex()} → {first.hex()}")
        if best is None or ev.value > best.value:
            best = ev
    return best
