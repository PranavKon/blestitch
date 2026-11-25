"""Sibling trails: one device advertising under several addresses at once.

Rotation is not the only way a device ends up with more than one address.
Some devices run two advertising sets side by side, each with its own random
address, carrying the same content (seen in practice: Apple devices sending
identical Nearby Info under two addresses that also rotate together).

The evidence used here is deliberately narrow: two different random addresses
on air at the same moment, at the same signal strength, both sending the same
identifier-grade content that nobody else is sending. Trails joined this way
are *siblings* and form one device.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from blestitch.features.summary import EpochFeatures
from blestitch.features.tokens import NAME, Token, describe_token, token_strength
from blestitch.records import AddressEpoch, AddrType

# Siblings are the same radio, so their signal strength agrees closely.
_MAX_RSSI_DIFF_DB = 4.0
# A twin's content is sent by exactly its two addresses.
_TWIN_SHARERS = 2


@dataclass(slots=True)
class Sibling:
    track_a: int
    track_b: int
    n_shared: int      # distinct shared tokens seen across the two trails
    detail: str


def find_siblings(
    epochs: list[AddressEpoch],
    features: list[EpochFeatures],
    rarity: dict[Token, int],
    track_of_epoch: list[int],
) -> list[Sibling]:
    carriers: dict[Token, list[int]] = defaultdict(list)
    for i, (e, f) in enumerate(zip(epochs, features)):
        if e.addr_type is AddrType.PUBLIC:
            continue  # a public address is a device's one true address
        for token in f.tokens:
            # Two devices may share a name; they do not share a nonce.
            if token[0] != NAME and token_strength(token) >= 1.0:
                carriers[token].append(i)

    shared: dict[tuple[int, int], list[Token]] = defaultdict(list)
    for token, ids in carriers.items():
        if len(ids) < 2 or rarity.get(token, 1) != _TWIN_SHARERS:
            continue
        for x in range(len(ids)):
            for y in range(x + 1, len(ids)):
                i, j = ids[x], ids[y]
                pair = _sibling_pair(epochs, features, track_of_epoch, i, j)
                if pair is not None:
                    shared[pair].append(token)

    out = []
    for (a, b), tokens in sorted(shared.items()):
        distinct = sorted(set(tokens))  # sorted: the same wording every run
        out.append(
            Sibling(
                track_a=a,
                track_b=b,
                n_shared=len(distinct),
                detail=(
                    f"both sent the same {describe_token(distinct[0])} at the same time"
                    + (f", and {len(distinct) - 1} more shared values" if len(distinct) > 1 else "")
                ),
            )
        )
    return out


def _sibling_pair(epochs, features, track_of_epoch, i: int, j: int) -> tuple[int, int] | None:
    a, b = epochs[i], epochs[j]
    if a.address == b.address or track_of_epoch[i] == track_of_epoch[j]:
        return None
    if min(a.t_end_us, b.t_end_us) <= max(a.t_start_us, b.t_start_us):
        return None  # never on air together
    ra, rb = _mean_rssi(a), _mean_rssi(b)
    if ra is None or rb is None or abs(ra - rb) > _MAX_RSSI_DIFF_DB:
        return None
    ta, tb = track_of_epoch[i], track_of_epoch[j]
    return (min(ta, tb), max(ta, tb))


def _mean_rssi(e: AddressEpoch) -> float | None:
    values = [p.rssi for p in e.packets if p.rssi is not None]
    return sum(values) / len(values) if values else None


def group_devices(n_tracks: int, siblings: list[Sibling]) -> list[int]:
    """Device index for each track: siblings share one, numbered in track order."""
    parent = list(range(n_tracks))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for s in siblings:
        parent[find(s.track_b)] = find(s.track_a)
    device_of_root: dict[int, int] = {}
    out = []
    for t in range(n_tracks):
        out.append(device_of_root.setdefault(find(t), len(device_of_root)))
    return out
