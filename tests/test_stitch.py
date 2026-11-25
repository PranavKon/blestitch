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


ANONYMOUS = bytes([0x02, 0x01, 0x06, 0x02, 0x0A, 0x04])   # flags + TX power: nothing identifying


def test_a_late_arrival_is_not_a_rotation():
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 30, "payload": ANONYMOUS},
        {"address": rpa(2), "start_s": 90, "stop_s": 120, "payload": ANONYMOUS},
    ]
    assert len(analyze_bytes(build_scenario(segments), source="t").stitched.tracks) == 2


def test_device_is_reidentified_after_a_long_silence():
    # A sleeping device wakes for a few seconds every few minutes, each time
    # under a new address, always announcing the same AirPlay address.
    def airplay(last_octet):
        mfr = bytes([0x4C, 0x00, 0x09, 0x06, 0x13, 0x95, 192, 168, 1, last_octet])
        return bytes([0x02, 0x01, 0x1A, len(mfr) + 1, 0xFF]) + mfr

    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 5, "payload": airplay(24)},
        {"address": rpa(2), "start_s": 200, "stop_s": 205, "payload": airplay(24)},
        {"address": rpa(3), "start_s": 900, "stop_s": 905, "payload": airplay(24)},
        # a different device, with a different address, in between
        {"address": rpa(4), "start_s": 400, "stop_s": 405, "payload": airplay(99)},
    ]
    analysis = analyze_bytes(build_scenario(segments), source="t")
    assert _trails(analysis) == {frozenset({rpa(1), rpa(2), rpa(3)}), frozenset({rpa(4)})}
    link = _rotations(analysis)[0]
    carry = next(c for c in link.clues if c.name == "carryover")
    assert carry.evidence == 1.0 and "192.168.1.24" in carry.detail
    assert next(c for c in link.clues if c.name == "timing").evidence < 0.01


def test_no_reidentification_on_content_two_devices_send_at_once():
    # The same blob from two addresses at the same time is not an identifier.
    blob = bytes([0x02, 0x01, 0x06, 0x09, 0x16, 0xED, 0xFE]) + bytes(range(1, 7))
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 20, "payload": blob, "rssi": -50},
        {"address": rpa(2), "start_s": 0, "stop_s": 20, "payload": blob, "rssi": -80},
        {"address": rpa(3), "start_s": 300, "stop_s": 320, "payload": blob, "rssi": -50},
    ]
    assert len(analyze_bytes(build_scenario(segments), source="t").stitched.tracks) == 3


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


def test_two_addresses_sending_the_same_content_at_once_are_one_device():
    # One device, two advertising sets: both addresses carry the same Nearby
    # Info at the same time and rotate together.
    def twin(tag):
        return {"interval_ms": 300, "rssi": -60, "payload": apple_adv(bytes(tag))}

    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 40, **twin([1, 2, 3])},
        {"address": rpa(2), "start_s": 0, "stop_s": 40, **twin([1, 2, 3])},
        {"address": rpa(3), "start_s": 40.5, "stop_s": 80, **twin([7, 8, 9])},
        {"address": rpa(4), "start_s": 40.5, "stop_s": 80, **twin([7, 8, 9])},
        # an unrelated phone elsewhere in the room
        {"address": rpa(5), "start_s": 0, "stop_s": 80, "interval_ms": 300, "rssi": -80,
         "payload": apple_adv(bytes([4, 4, 4]))},
    ]
    analysis = analyze_bytes(build_scenario(segments), source="twins")
    result = analysis.result
    assert len(result.tracks) == 3 and result.n_devices == 2

    twins = [t for t in result.tracks if t.n_addresses == 2]
    assert [t.name for t in twins] == ["D1a", "D1b"]
    assert twins[0].device_id == twins[1].device_id
    assert result.tracks[2].name == "D2"
    (sibling,) = result.siblings
    assert (sibling.track_a, sibling.track_b) == (0, 1)
    assert "Nearby Info" in sibling.detail

    # Which twin follows which is arbitrary, and does not matter: both
    # choices describe the same device, so neither link is ambiguous.
    links = _rotations(analysis)
    assert len(links) == 2
    assert not any(link.ambiguous for link in links)


def test_siblings_must_be_at_the_same_signal_strength():
    payload = apple_adv(bytes([1, 2, 3]))
    segments = [
        {"address": rpa(1), "start_s": 0, "stop_s": 40, "rssi": -45, "payload": payload},
        {"address": rpa(2), "start_s": 0, "stop_s": 40, "rssi": -75, "payload": payload},
    ]
    result = analyze_bytes(build_scenario(segments), source="t").result
    assert result.n_devices == 2 and result.siblings == []


def test_indistinguishable_devices_are_flagged_ambiguous():
    # Two trackers side by side with different keys rotate together: nothing
    # says which new address belongs to which.
    def tracker(key_byte):
        return {"interval_ms": 1000, "rssi": -60, "pdu": ADV_NONCONN_IND,
                "payload": find_my_adv(bytes([key_byte]) * 22)}

    segments = [
        {"address": static_addr(1), "start_s": 0, "stop_s": 60, **tracker(1)},
        {"address": static_addr(2), "start_s": 0, "stop_s": 60, **tracker(2)},
        {"address": static_addr(3), "start_s": 60.5, "stop_s": 120, **tracker(3)},
        {"address": static_addr(4), "start_s": 60.5, "stop_s": 120, **tracker(4)},
    ]
    analysis = analyze_bytes(build_scenario(segments), source="t")
    links = _rotations(analysis)
    assert len(links) == 2                       # each old address gets one successor
    assert all(link.ambiguous for link in links)
    assert all(t.ambiguous for t in analysis.result.tracks)
    assert analysis.result.n_devices == 2


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


def test_result_does_not_depend_on_hash_order():
    # Tokens live in sets, whose order changes from run to run. The result,
    # including the wording of each clue, must not change with it.
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = (
        "import hashlib, json, sys\n"
        "sys.path.insert(0, 'tests')\n"
        "import fixtures\n"
        "from blestitch.pipeline import analyze_bytes\n"
        "capture, _ = fixtures.make_rotation_capture(minutes=3)\n"
        "result = analyze_bytes(capture, source='t').result.to_dict()\n"
        "print(hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest())\n"
    )
    root = Path(__file__).resolve().parent.parent
    digests = {
        subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for seed in ("1", "2", "3")
    }
    assert len(digests) == 1
