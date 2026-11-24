import json

from fixtures import (
    ADDR_PUB,
    ADV_NONCONN_IND,
    apple_adv,
    build_scenario,
    find_my_adv,
    make_rotation_capture,
    rpa,
    static_addr,
)

from blestitch.link.heuristic import MatcherConfig
from blestitch.pipeline import analyze_bytes

NAMED = bytes([0x02, 0x01, 0x06, 0x08, 0x09]) + b"Band-42"
OTHER_NAME = bytes([0x02, 0x01, 0x06, 0x08, 0x09]) + b"Band-43"


def _trails(analysis) -> set[frozenset[int]]:
    """The stitched trails as sets of addresses."""
    return {
        frozenset(analysis.epochs[i].address for i in t.epoch_ids)
        for t in analysis.stitched.tracks
    }


def _rotations(analysis):
    return [link for link in analysis.result.links if link.kind == "rotation"]


def test_rotation_fixture_is_stitched_exactly():
    capture, truth = make_rotation_capture(minutes=12)
    analysis = analyze_bytes(capture, source="rotation")
    expected: dict[str, set[int]] = {}
    for address, device in truth.items():
        expected.setdefault(device, set()).add(address)
    assert _trails(analysis) == {frozenset(s) for s in expected.values()}

    # the phones are tied together by their Handoff counter
    counter_links = [
        link for link in _rotations(analysis) if any(c.name == "counter" for c in link.clues)
    ]
    assert len(counter_links) >= 4
    assert all(link.score > 0.9 for link in counter_links)


def test_simultaneous_rotation_is_resolved_jointly():
    # Four identical trackers rotate at the same instant. Only where each one
    # sits (its signal strength) tells them apart.
    key = bytes(22)
    segments = []
    for n, rssi in enumerate((-40, -52, -64, -76)):
        common = {"interval_ms": 1000, "rssi": rssi, "pdu": ADV_NONCONN_IND, "payload": find_my_adv(key)}
        segments.append(dict(address=static_addr(n), start_s=0, stop_s=60, **common))
        segments.append(dict(address=static_addr(10 + n), start_s=60.5, stop_s=120, **common))
    analysis = analyze_bytes(build_scenario(segments), source="elevator")
    assert _trails(analysis) == {
        frozenset({static_addr(n), static_addr(10 + n)}) for n in range(4)
    }


def test_counter_beats_signal_strength():
    # Two phones swap places during a simultaneous rotation: signal strength
    # points the wrong way, the Handoff counters point the right way.
    def phone(seq0):
        return lambda t: apple_adv(bytes([seq0 & 0xFF, 2, 3]), seq0 + t // 20_000_000)

    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 60, "rssi": -45, "payload": phone(0x1000)},
        {"address": rpa(2), "start_s": 0, "stop_s": 60, "rssi": -70, "payload": phone(0x8000)},
        {"address": rpa(3), "start_s": 60.4, "stop_s": 120, "rssi": -70,
             "payload": lambda t: apple_adv(bytes([9, 9, 9]), 0x1000 + t // 20_000_000)},
        {"address": rpa(4), "start_s": 60.4, "stop_s": 120, "rssi": -45,
             "payload": lambda t: apple_adv(bytes([8, 8, 8]), 0x8000 + t // 20_000_000)},
    ]
    analysis = analyze_bytes(build_scenario(segments), source="swap")
    assert _trails(analysis) == {
        frozenset({rpa(1), rpa(3)}),
        frozenset({rpa(2), rpa(4)}),
    }


def test_public_addresses_never_link():
    segments = [
        {"address": ADDR_PUB, "tx_add": 0, "start_s": 0, "stop_s": 30},
        {"address": ADDR_PUB + 1, "tx_add": 0, "start_s": 30.3, "stop_s": 60},
    ]
    analysis = analyze_bytes(build_scenario(segments), source="public")
    assert len(analysis.stitched.tracks) == 2
    assert _rotations(analysis) == []


def test_address_types_do_not_mix():
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 30},
        {"address": static_addr(1), "start_s": 30.3, "stop_s": 60},
    ]
    assert len(analyze_bytes(build_scenario(segments), source="t").stitched.tracks) == 2


def test_a_late_arrival_is_not_a_rotation():
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 30},
        {"address": rpa(2), "start_s": 90, "stop_s": 120},
    ]
    assert len(analyze_bytes(build_scenario(segments), source="t").stitched.tracks) == 2


def test_overlapping_addresses_are_different_devices():
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 40},
        {"address": rpa(2), "start_s": 30, "stop_s": 70},
    ]
    assert len(analyze_bytes(build_scenario(segments), source="t").stitched.tracks) == 2


def test_different_device_does_not_inherit_the_trail():
    # A phone leaves just as an unrelated wearable shows up.
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 30, "interval_ms": 180, "payload": apple_adv(bytes(3))},
        {"address": rpa(2), "start_s": 30.2, "stop_s": 60, "interval_ms": 100, "payload": NAMED},
    ]
    assert len(analyze_bytes(build_scenario(segments), source="t").stitched.tracks) == 2


def test_different_names_block_a_link():
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 30, "payload": NAMED},
        {"address": rpa(2), "start_s": 30.2, "stop_s": 60, "payload": OTHER_NAME},
    ]
    assert len(analyze_bytes(build_scenario(segments), source="t").stitched.tracks) == 2


def test_name_carries_a_link_across_a_longer_gap():
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 30, "payload": NAMED},
        {"address": rpa(2), "start_s": 45, "stop_s": 80, "payload": NAMED},
    ]
    analysis = analyze_bytes(build_scenario(segments), source="t")
    assert len(analysis.stitched.tracks) == 1
    (link,) = _rotations(analysis)
    carry = next(c for c in link.clues if c.name == "carryover")
    assert carry.evidence == 1.0 and "Band-42" in carry.detail


def test_same_address_seen_again_is_one_trail():
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 20},
        {"address": rpa(1), "start_s": 120, "stop_s": 140},
    ]
    analysis = analyze_bytes(build_scenario(segments), source="t")
    assert len(analysis.result.epochs) == 2
    (track,) = analysis.result.tracks
    assert (track.n_addresses, track.n_rotations, track.min_score) == (1, 0, None)
    (link,) = analysis.result.links
    assert link.kind == "same_address" and link.score == 1.0 and link.clues == []


def test_indistinguishable_twins_are_flagged_ambiguous():
    common = {"interval_ms": 300, "rssi": -60, "payload": apple_adv(bytes([1, 2, 3]))}
    segments = [
        dict(address=rpa(1), start_s=0, stop_s=40, **common),
        dict(address=rpa(2), start_s=0, stop_s=40, **common),
        dict(address=rpa(3), start_s=40.5, stop_s=80, **common),
        dict(address=rpa(4), start_s=40.5, stop_s=80, **common),
    ]
    analysis = analyze_bytes(build_scenario(segments), source="twins")
    links = _rotations(analysis)
    assert len(links) == 2                       # each old address gets one successor
    assert all(link.ambiguous for link in links)
    assert all(t.ambiguous for t in analysis.result.tracks)


def test_accept_line_is_configurable():
    segments = [
        {"address": static_addr(1), "start_s": 0, "stop_s": 30, "pdu": ADV_NONCONN_IND, "payload": find_my_adv(bytes(22))},
        {"address": static_addr(2), "start_s": 30.4, "stop_s": 60, "pdu": ADV_NONCONN_IND, "payload": find_my_adv(bytes(22))},
    ]
    cap = build_scenario(segments)
    assert len(analyze_bytes(cap, source="t").stitched.tracks) == 1
    strict = MatcherConfig(accept_total=99.0)
    assert len(analyze_bytes(cap, source="t", matcher=strict).stitched.tracks) == 2


def test_artifact_carries_trails_and_links():
    capture, _ = make_rotation_capture(minutes=6)
    result = analyze_bytes(capture, source="rotation").result
    assert [t.id for t in result.tracks] == list(range(len(result.tracks)))
    for track in result.tracks:
        assert all(result.epochs[i].track_id == track.id for i in track.epoch_ids)
        starts = [result.epochs[i].t_start_us for i in track.epoch_ids]
        assert starts == sorted(starts)
    assert sorted(i for t in result.tracks for i in t.epoch_ids) == list(range(result.n_epochs))

    phone = next(t for t in result.tracks if t.n_rotations >= 1 and "Handoff" in t.label)
    assert phone.n_addresses == phone.n_rotations + 1
    assert 0.5 < phone.min_score <= 1.0

    link = next(link for link in result.links if link.kind == "rotation")
    assert link.track_id == result.epochs[link.a].track_id == result.epochs[link.b].track_id
    assert result.epochs[link.a].t_end_us <= result.epochs[link.b].t_start_us
    assert {c.name for c in link.clues} >= {"timing", "structure", "cadence", "signal"}
    assert abs(sum(c.contribution for c in link.clues) - link.total) < 0.01
    json.dumps(result.to_dict())
