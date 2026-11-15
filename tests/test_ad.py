from fixtures import ADV_DATA_A, apple_adv, find_my_adv

from blestitch.dissect import vendors
from blestitch.dissect.ad import (
    ad_signature,
    ad_structure,
    decode_ad,
    extract_company_id,
    summarize_ad,
)
from blestitch.dissect.continuity import parse_continuity


def _by_name(advdata):
    return {f.name: f for f in decode_ad(advdata)}


def test_structure_and_signature():
    assert ad_structure(ADV_DATA_A) == ((0x01, 1), (0x0A, 1), (0xFF, 4))
    assert ad_signature(ad_structure(ADV_DATA_A)) == "01:1|0a:1|ff:4"


def test_truncated_tail_is_ignored():
    assert ad_structure(ADV_DATA_A + bytes([0x09, 0xFF, 0x4C])) == ad_structure(ADV_DATA_A)
    assert ad_structure(bytes([0x00, 0x01])) == ()


def test_generic_fields_decode():
    adv = (
        bytes([0x02, 0x01, 0x06])
        + bytes([0x03, 0x03, 0x0D, 0x18])            # Heart Rate service
        + bytes([0x03, 0x19, 0xC1, 0x00])            # appearance 0x00C1 (Watch)
        + bytes([0x02, 0x0A, 0xF4])
        + bytes([0x05, 0x09]) + b"Band"
    )
    f = _by_name(adv)
    assert "LE General Discoverable" in f["Flags"].summary
    assert f["16-bit Service UUIDs"].summary == "0x180d (Heart Rate)"
    assert f["Appearance"].summary == "0x00c1 (Watch)"
    assert f["TX Power Level"].summary == "-12 dBm"
    assert f["Complete Local Name"].summary == "Band"

    s = summarize_ad(adv)
    assert s.local_name == "Band"
    assert s.service_uuids == ["180d"]
    assert s.appearance == "Watch"
    assert s.tx_power == -12
    assert s.company_id is None


def test_128_bit_uuid_is_rendered_big_endian():
    uuid_le = bytes(range(16))
    f = decode_ad(bytes([17, 0x07]) + uuid_le)[0]
    assert f.summary == "0f0e0d0c-0b0a-0908-0706-050403020100"


def test_company_lookup():
    assert extract_company_id(ADV_DATA_A) == 0x004C
    assert vendors.company_name(0x004C) == "Apple, Inc."
    assert vendors.short_company_name(0x004C) == "Apple"
    assert vendors.short_company_name(0xFFFE) == "0xfffe"


def test_apple_nearby_info_and_handoff():
    adv = apple_adv(bytes([0xAA, 0xBB, 0xCC]), handoff_seq=0x1234)
    s = summarize_ad(adv)
    assert s.company_id == 0x004C
    assert s.tags == ["Handoff", "Nearby Info"]

    mfr = next(f for f in decode_ad(adv) if f.type == 0xFF)
    assert mfr.summary == "Apple, Inc. (0x004c) · Handoff, Nearby Info"
    fields = dict(mfr.fields)
    assert fields["Handoff: sequence (IV)"] == "1234"
    assert fields["Nearby Info: activity"] == "active user (screen on)"
    assert fields["Nearby Info: auth tag"] == "aabbcc"


def test_find_my():
    key = bytes(range(22))
    s = summarize_ad(find_my_adv(key))
    assert s.tags == ["Find My"]
    fields = dict(next(f for f in decode_ad(find_my_adv(key)) if f.type == 0xFF).fields)
    assert fields["Find My: public key bytes 6-27"] == key.hex()


def test_continuity_proximity_pairing_and_ibeacon():
    pp = bytes([0x07, 0x19, 0x01, 0x0E, 0x20, 0x55, 0x98, 0x8F, 0x39, 0x00, 0x00]) + bytes(16)
    beacon = bytes([0x02, 0x15]) + bytes(range(16)) + bytes([0x00, 0x01, 0x00, 0x02, 0xC5])
    msgs = parse_continuity(pp + beacon)
    assert [m.name for m in msgs] == ["Proximity Pairing", "iBeacon"]
    assert dict(msgs[0].fields)["model"] == "AirPods Pro"
    assert dict(msgs[0].fields)["lid open counter"] == "57"
    ib = dict(msgs[1].fields)
    assert (ib["major"], ib["minor"], ib["measured power"]) == ("1", "2", "-59 dBm")


def test_continuity_truncated_and_unknown_messages_do_not_raise():
    msgs = parse_continuity(bytes([0x10, 0x05, 0x07]) )       # Nearby Info cut short
    assert msgs[0].name == "Nearby Info"
    msgs = parse_continuity(bytes([0x7E, 0x02, 0x01, 0x02]))
    assert msgs[0].name == "Unknown 0x7e" and msgs[0].data == b"\x01\x02"
    for cut in range(30):
        parse_continuity((bytes([0x0C, 0x0E]) + bytes(14) + bytes([0x12, 0x19]) + bytes(25))[:cut])


def test_service_data_decoders():
    tag, fields = vendors.decode_service_data("feaa", bytes([0x20, 0x00, 0x0B, 0xB8, 0x15, 0x00]) + (1000).to_bytes(4, "big") + (36000).to_bytes(4, "big"))
    assert tag == "Eddystone-TLM"
    assert dict(fields)["advertisement count"] == "1000"

    tag, fields = vendors.decode_service_data("fd6f", bytes(range(20)))
    assert tag == "Exposure Notification"
    assert dict(fields)["rolling proximity id"] == bytes(range(16)).hex()

    tag, _ = vendors.decode_service_data("fe2c", b"\x01\x02\x03")
    assert tag == "Fast Pair"
    tag, _ = vendors.decode_service_data("feed", b"\x01\x02")
    assert tag == "Tile"
    # a short payload falls back to raw hex instead of raising
    tag, fields = vendors.decode_service_data("fe95", b"\x01")
    assert fields == [("data", "01")]
    # unknown UUID: named from the registry if possible
    assert vendors.decode_service_data("180f", b"\x64")[0] == "Battery Service"
    assert vendors.decode_service_data("abcd", b"\x64")[0] is None


def test_service_data_tags_reach_the_summary():
    adv = bytes([0x06, 0x16, 0xED, 0xFE, 0x01, 0x02, 0x03])
    assert summarize_ad(adv).tags == ["Tile"]
    assert summarize_ad(adv).service_uuids == ["feed"]
