"""The v1 matcher: a transparent, rule-based score for one candidate handoff.

No model, no training data. Each clue contributes ``evidence x weight``; the
contributions are summed and squashed so that 0.5 is the accept line. The
score orders candidates and explains itself — it is **not** a calibrated
probability. An honest confidence meter needs ground truth and arrives in v2.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from blestitch.features import pairwise
from blestitch.features.summary import EpochFeatures
from blestitch.features.tokens import Token
from blestitch.records import Clue


@dataclass(slots=True)
class MatcherConfig:
    # Candidate gate: how long after epoch A ends may B first be heard.
    max_gap_us: int = 30_000_000
    # For devices we hear rarely, the gate stretches to this many typical
    # gaps between their packets, up to `max_gap_ceiling_us`.
    max_gap_in_observed_gaps: float = 4.0
    max_gap_ceiling_us: int = 120_000_000
    # B may start this much before A's last packet (timestamp slack only: a
    # device does not send under its old and new address at once).
    max_overlap_us: int = 50_000

    weight_timing: float = 1.0
    weight_structure: float = 2.0
    weight_cadence: float = 1.5
    weight_rssi: float = 1.5
    weight_carryover: float = 3.0
    weight_counter: float = 3.0

    # Sum of contributions at which a link is exactly on the accept line.
    accept_total: float = 4.0
    # A link this close to its best rival is flagged as ambiguous.
    ambiguous_margin: float = 1.0


def gap_allowed(gap_us: int, a: EpochFeatures, b: EpochFeatures, cfg: MatcherConfig) -> bool:
    if gap_us < -cfg.max_overlap_us:
        return False
    stretch = cfg.max_gap_in_observed_gaps * max(a.observed_gap_us, b.observed_gap_us)
    return gap_us <= max(cfg.max_gap_us, min(cfg.max_gap_ceiling_us, stretch))


def score_handoff(
    gap_us: int,
    a: EpochFeatures,
    b: EpochFeatures,
    rarity: dict[Token, int],
    cfg: MatcherConfig,
) -> tuple[float, list[Clue]]:
    """Return (sum of contributions, the clues that had something to say)."""
    results = (
        ("timing", cfg.weight_timing, pairwise.timing(gap_us, a, b)),
        ("structure", cfg.weight_structure, pairwise.structure(a, b)),
        ("cadence", cfg.weight_cadence, pairwise.cadence(a, b)),
        ("signal", cfg.weight_rssi, pairwise.rssi(a, b)),
        ("carryover", cfg.weight_carryover, pairwise.carryover(a, b, rarity)),
        ("counter", cfg.weight_counter, pairwise.counter(a, b)),
    )
    clues = [
        Clue(name=name, evidence=round(ev.value, 3), weight=weight, detail=ev.detail)
        for name, weight, ev in results
        if ev is not None
    ]
    return sum(c.contribution for c in clues), clues


def to_score(total: float, cfg: MatcherConfig) -> float:
    """Squash a contribution sum to 0..1 with the accept line at 0.5."""
    return 1.0 / (1.0 + math.exp(-(total - cfg.accept_total)))
