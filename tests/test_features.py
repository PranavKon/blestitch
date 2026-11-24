from fixtures import ADV_DATA_B, apple_adv, find_my_adv

from blestitch.features import pairwise
from blestitch.features.counters import (
    EDDYSTONE_TLM,
    HANDOFF,
    MIBEACON,
    continues,
    extract_counters,
)
from blestitch.features.summary import EpochFeatures
from blestitch.features.tokens import NAME, describe_token, extract_tokens


def test_tokens_are_whole_fields_keyed_by_origin():
    adv = bytes([0x02, 0x01, 0x06, 0x05, 0x09]) + b"Band" + bytes([0x05, 0x16, 0xED, 0xFE, 0xAA, 0xBB])
    assert extract_tokens(adv) == {
        ("ad:01", b"\x06"),
        (NAME, b"Band"),
        ("svc:feed", b"\xaa\xbb"),
    }


def test_apple_tokens_split_per_message():
    tokens = extract_tokens(apple_adv(bytes([1, 2, 3]), handoff_seq=0x1234))
    kinds = {k for k, _ in tokens}
    assert {"apple:0c", "apple:10", "ad:01"} == kinds
    assert ("apple:10", bytes([0x07, 0x1C, 1, 2, 3])) in tokens


def test_airplay_ip_is_its_own_token():
    mfr = bytes([0x4C, 0x00, 0x09, 0x06, 0x13, 0x95, 192, 168, 1, 20])
    tokens = extract_tokens(bytes([len(mfr) + 1, 0xFF]) + mfr)
    assert ("apple:airplay-ip", bytes([192, 168, 1, 20])) in tokens
    assert describe_token(("apple:airplay-ip", bytes([192, 168, 1, 20]))) == "AirPlay address 192.168.1.20"


def test_counters_extracted():
    assert extract_counters(apple_adv(bytes(3), handoff_seq=0x1234)) == {HANDOFF: b"\x12\x34"}
    tlm = bytes([0x11, 0x16, 0xAA, 0xFE, 0x20, 0x00, 0x0B, 0xB8, 0x15, 0x00]) + (1000).to_bytes(4, "big") + bytes(4)
    assert extract_counters(tlm) == {EDDYSTONE_TLM: (1000).to_bytes(4, "big")}
    mi = bytes([0x08, 0x16, 0x95, 0xFE, 0x30, 0x58, 0x5B, 0x05, 0x2A])
    assert extract_counters(mi) == {MIBEACON: b"\x2a"}
    assert extract_counters(find_my_adv(bytes(22))) == {}


def test_counter_continuation_rules():
    assert continues(HANDOFF, b"\x12\x34", b"\x12\x36")
    assert continues(HANDOFF, b"\x12\x34", b"\x12\x34")          # no tick yet
    assert continues(HANDOFF, b"\xff\xff", b"\x00\x01")          # wraps
    assert continues(HANDOFF, b"\x34\x12", b"\x36\x12")          # other byte order
    assert not continues(HANDOFF, b"\x12\x34", b"\x40\x00")
    assert not continues(HANDOFF, b"\x12\x36", b"\x12\x10")      # went backwards
    assert continues(MIBEACON, b"\xfe", b"\x03")
    assert not continues(MIBEACON, b"\x10", b"\x80")


def _f(**kw) -> EpochFeatures:
    return EpochFeatures(**kw)


def test_timing_judged_against_how_often_we_hear_the_device():
    chatty = _f(observed_gap_us=200_000)
    quiet = _f(observed_gap_us=6_000_000)
    assert pairwise.timing(100_000, chatty, chatty).value > 0.9
    assert pairwise.timing(10_000_000, chatty, chatty).value < 0.05
    assert pairwise.timing(10_000_000, quiet, quiet).value > 0.5


def test_structure_clue():
    a = _f(signatures=frozenset({"01:1|ff:10"}), type_sequences=frozenset({(1, 255)}))
    same = _f(signatures=frozenset({"01:1|ff:10"}), type_sequences=frozenset({(1, 255)}))
    resized = _f(signatures=frozenset({"01:1|ff:12"}), type_sequences=frozenset({(1, 255)}))
    other = _f(signatures=frozenset({"09:5"}), type_sequences=frozenset({(9,)}))
    assert pairwise.structure(a, same).value == 1.0
    assert 0 < pairwise.structure(a, resized).value < 0.5
    assert pairwise.structure(a, other).value == -1.0
    assert pairwise.structure(a, _f()) is None


def test_cadence_clue():
    assert pairwise.cadence(_f(interval_ms=275.0), _f(interval_ms=274.6)).value > 0.9
    assert pairwise.cadence(_f(interval_ms=275.0), _f(interval_ms=186.0)).value == -1.0
    assert pairwise.cadence(_f(interval_ms=275.0), _f()) is None


def test_rssi_clue_compares_the_seam():
    a = _f(rssi_head=-90.0, rssi_tail=-50.0)
    assert pairwise.rssi(a, _f(rssi_head=-51.0)).value > 0.8
    assert pairwise.rssi(a, _f(rssi_head=-90.0)).value == -1.0
    assert pairwise.rssi(a, _f()) is None


def test_carryover_is_discounted_by_how_many_devices_share_the_token():
    token = ("svc:feed", b"\x01\x02\x03\x04")
    a, b = _f(tokens=frozenset({token})), _f(tokens=frozenset({token}))
    assert pairwise.carryover(a, b, {token: 1}).value == 1.0
    assert pairwise.carryover(a, b, {token: 4}).value == 0.25
    assert pairwise.carryover(a, b, {token: 8}) is None              # too common to count
    assert "no other address" in pairwise.carryover(a, b, {token: 1}).detail

    flags = ("ad:01", b"\x1a")
    weak_a, weak_b = _f(tokens=frozenset({flags})), _f(tokens=frozenset({flags}))
    assert pairwise.carryover(weak_a, weak_b, {flags: 10}) is None   # says nothing
    assert pairwise.carryover(a, _f(tokens=frozenset({flags})), {}) is None


def test_carryover_different_names_contradict():
    a = _f(name=b"Band-42", tokens=frozenset({(NAME, b"Band-42")}))
    b = _f(name=b"Band-43", tokens=frozenset({(NAME, b"Band-43")}))
    assert pairwise.carryover(a, b, {}).value == -1.0


def test_counter_clue():
    a = _f(counters={HANDOFF: (b"\x12\x30", b"\x12\x34")})
    assert pairwise.counter(a, _f(counters={HANDOFF: (b"\x12\x35", b"\x12\x39")})).value == 1.0
    assert pairwise.counter(a, _f(counters={HANDOFF: (b"\x80\x00", b"\x80\x01")})).value == -0.5
    assert pairwise.counter(a, _f()) is None
    assert ADV_DATA_B  # fixtures import used
