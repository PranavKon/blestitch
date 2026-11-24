"""The stitcher: choose the set of handoffs that best explains a capture.

Scoring pairs one at a time is not enough. When several devices rotate at the
same moment (the "elevator" case) each old address has several plausible
successors, and the best choice for one constrains the others. So the solver
picks links *jointly*: every address may have at most one successor and one
predecessor, and the chosen set maximizes the total score above the accept
line.

Epochs that share an address are the same device by definition and are merged
before any of this; what gets linked are *addresses*.

The candidate graph falls apart into small independent groups (only addresses
that were on air around the same moment compete), and each group is solved
exactly with the Hungarian algorithm, which keeps long captures cheap.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np
from scipy.optimize import linear_sum_assignment

from blestitch.dissect.profile import EpochProfile
from blestitch.features.summary import EpochFeatures, build_features
from blestitch.features.tokens import Token
from blestitch.link.heuristic import MatcherConfig, gap_allowed, score_handoff, to_score
from blestitch.records import AddressEpoch, AddrType, DeviceTrack, Link


@dataclass(slots=True)
class _Address:
    """All epochs of one address, in time order."""

    epoch_ids: list[int]
    addr_type: AddrType
    t_start_us: int
    t_end_us: int


@dataclass(slots=True)
class StitchResult:
    tracks: list[DeviceTrack] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    track_of_epoch: list[int] = field(default_factory=list)


def stitch(
    epochs: list[AddressEpoch],
    profiles: list[EpochProfile],
    cfg: MatcherConfig | None = None,
) -> StitchResult:
    cfg = cfg or MatcherConfig()
    features = [build_features(e, p) for e, p in zip(epochs, profiles)]
    addresses = _group_by_address(epochs)
    rarity = _token_rarity(addresses, features)

    candidates = _score_candidates(addresses, features, rarity, cfg)
    chosen = _solve(candidates, len(addresses))
    _set_margins(chosen, candidates)

    links = _same_address_links(addresses, epochs) + chosen
    links.sort(key=lambda link: epochs[link.b].t_start_us)

    # `chosen` links refer to address indices until here; rewrite to epoch ids.
    successor = {link.a: link.b for link in chosen}
    for link in chosen:
        link.a, link.b = addresses[link.a].epoch_ids[-1], addresses[link.b].epoch_ids[0]

    tracks = _build_tracks(addresses, successor)
    track_of_epoch = [0] * len(epochs)
    for track in tracks:
        for epoch_id in track.epoch_ids:
            track_of_epoch[epoch_id] = track.id
    return StitchResult(tracks=tracks, links=links, track_of_epoch=track_of_epoch)


def _group_by_address(epochs: list[AddressEpoch]) -> list[_Address]:
    by_key: dict[tuple[int, AddrType], list[int]] = defaultdict(list)
    for i, e in enumerate(epochs):
        by_key[(e.address, e.addr_type)].append(i)
    groups = [
        _Address(
            epoch_ids=ids,
            addr_type=epochs[ids[0]].addr_type,
            t_start_us=epochs[ids[0]].t_start_us,
            t_end_us=max(epochs[i].t_end_us for i in ids),
        )
        for ids in by_key.values()
    ]
    groups.sort(key=lambda g: g.t_start_us)
    return groups


def _token_rarity(
    addresses: list[_Address], features: list[EpochFeatures]
) -> dict[Token, int]:
    """For each token, the most addresses seen sending it at one moment."""
    spans: dict[Token, list[tuple[int, int]]] = defaultdict(list)
    for addr in addresses:
        tokens: set[Token] = set()
        for i in addr.epoch_ids:
            tokens |= features[i].tokens
        for token in tokens:
            spans[token].append((addr.t_start_us, addr.t_end_us))

    rarity: dict[Token, int] = {}
    for token, intervals in spans.items():
        if len(intervals) == 1:
            rarity[token] = 1
            continue
        # Sweep: +1 at each start, -1 just after each end.
        events = sorted(
            [(s, 1) for s, _ in intervals] + [(e + 1, -1) for _, e in intervals]
        )
        live = peak = 0
        for _, delta in events:
            live += delta
            peak = max(peak, live)
        rarity[token] = peak
    return rarity


def _score_candidates(
    addresses: list[_Address],
    features: list[EpochFeatures],
    rarity: dict[Token, int],
    cfg: MatcherConfig,
) -> list[Link]:
    """Every allowed (earlier address -> later address) pair, scored.
    `Link.a` / `Link.b` hold *address indices* at this stage."""
    out: list[Link] = []
    # Addresses are sorted by start; a successor starts no earlier than the
    # predecessor ends (minus slack), so scan forward from each one.
    by_start = sorted(range(len(addresses)), key=lambda i: addresses[i].t_start_us)
    for a_idx, a in enumerate(addresses):
        if a.addr_type is AddrType.PUBLIC:
            continue  # a public address never rotates
        fa = features[a.epoch_ids[-1]]
        for b_idx in by_start:
            b = addresses[b_idx]
            gap = b.t_start_us - a.t_end_us
            if gap > cfg.max_gap_ceiling_us:
                break
            if b_idx == a_idx or b.addr_type is not a.addr_type:
                continue
            fb = features[b.epoch_ids[0]]
            if not gap_allowed(gap, fa, fb, cfg):
                continue
            total, clues = score_handoff(gap, fa, fb, rarity, cfg)
            out.append(
                Link(
                    a=a_idx,
                    b=b_idx,
                    kind="rotation",
                    gap_us=gap,
                    total=round(total, 3),
                    score=round(to_score(total, cfg), 3),
                    clues=clues,
                )
            )
    return out


def _solve(candidates: list[Link], n_addresses: int) -> list[Link]:
    """Pick links maximizing total score above the accept line, with at most
    one successor and one predecessor per address."""
    viable = [c for c in candidates if c.score > 0.5]
    if not viable:
        return []

    # Split into independent groups of addresses connected by viable links.
    parent = list(range(n_addresses))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for c in viable:
        parent[find(c.a)] = find(c.b)
    groups: dict[int, list[Link]] = defaultdict(list)
    for c in viable:
        groups[find(c.a)].append(c)

    chosen: list[Link] = []
    for links in groups.values():
        if len(links) == 1:
            chosen.append(links[0])
            continue
        rows = sorted({c.a for c in links})
        cols = sorted({c.b for c in links})
        row_of = {a: i for i, a in enumerate(rows)}
        col_of = {b: j for j, b in enumerate(cols)}
        # Columns beyond `cols` are "no successor" slots, one per row, worth 0.
        gain = np.zeros((len(rows), len(cols) + len(rows)))
        gain[:, : len(cols)] = -1e9  # not a candidate
        by_cell: dict[tuple[int, int], Link] = {}
        for c in links:
            i, j = row_of[c.a], col_of[c.b]
            gain[i, j] = c.score - 0.5
            by_cell[(i, j)] = c
        for i, j in zip(*linear_sum_assignment(gain, maximize=True)):
            if (i, j) in by_cell:
                chosen.append(by_cell[(i, j)])
    return chosen


def _set_margins(chosen: list[Link], candidates: list[Link]) -> None:
    """How far each chosen link's total is ahead of its best rival: any other
    candidate that wanted the same predecessor or the same successor."""
    for link in chosen:
        rivals = [
            c.total
            for c in candidates
            if c is not link and (c.a == link.a or c.b == link.b)
        ]
        link.margin = round(link.total - max(rivals), 3) if rivals else None


def _same_address_links(addresses: list[_Address], epochs: list[AddressEpoch]) -> list[Link]:
    out: list[Link] = []
    for addr in addresses:
        for x, y in zip(addr.epoch_ids, addr.epoch_ids[1:]):
            out.append(
                Link(
                    a=x,
                    b=y,
                    kind="same_address",
                    gap_us=epochs[y].t_start_us - epochs[x].t_end_us,
                )
            )
    return out


def _build_tracks(addresses: list[_Address], successor: dict[int, int]) -> list[DeviceTrack]:
    has_predecessor = set(successor.values())
    tracks: list[DeviceTrack] = []
    for start in range(len(addresses)):  # already in order of first appearance
        if start in has_predecessor:
            continue
        epoch_ids: list[int] = []
        idx: int | None = start
        while idx is not None:
            epoch_ids += addresses[idx].epoch_ids
            idx = successor.get(idx)
        tracks.append(DeviceTrack(id=len(tracks), epoch_ids=epoch_ids))
    return tracks
