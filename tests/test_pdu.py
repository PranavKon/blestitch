import struct

from fixtures import (
    ADDR_A1,
    ADDR_B1,
    ADDR_SCANNER,
    ADV_DATA_A,
    ADV_DIRECT_IND,
    ADV_EXT,
    ADV_IND,
    SCAN_REQ,
    addr_bytes,
    adv_ll,
    ll_packet,
    scan_req_ll,
)

from blestitch.dissect.pdu import parse_adv_pdu, pdu_type_name


def _pdu(ll: bytes) -> bytes:
    """Strip the access address and CRC the fixtures add."""
    return ll[4:-3]


def test_legacy_adv_ind():
    pdu = parse_adv_pdu(_pdu(adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A, chsel=1)))
    assert pdu.adv_a == ADDR_A1 and pdu.adv_random
    assert pdu.data == ADV_DATA_A
    assert pdu.header.chsel and pdu.peer_a is None


def test_directed_adv_has_a_target():
    ll = ll_packet(ADV_DIRECT_IND, addr_bytes(ADDR_A1) + addr_bytes(ADDR_B1), tx_add=1, rx_add=0)
    pdu = parse_adv_pdu(_pdu(ll))
    assert pdu.adv_a == ADDR_A1 and pdu.adv_random
    assert pdu.peer_a == ADDR_B1 and not pdu.peer_random
    assert pdu.data == b""


def test_scan_req_advertiser_is_the_second_address():
    pdu = parse_adv_pdu(_pdu(scan_req_ll(ADDR_SCANNER, ADDR_B1, adv_random=0)))
    assert pdu.header.pdu_type == SCAN_REQ
    assert pdu.adv_a == ADDR_B1 and not pdu.adv_random
    assert pdu.peer_a == ADDR_SCANNER and pdu.peer_random


def test_extended_adv_with_address_adi_and_tx_power():
    flags = 0x01 | 0x08 | 0x40  # AdvA, ADI, TxPower
    adi = struct.pack("<H", (0x5 << 12) | 0x123)
    ext = bytes([flags]) + addr_bytes(ADDR_A1) + adi + bytes([0xF8])
    payload = bytes([len(ext)]) + ext + ADV_DATA_A
    pdu = parse_adv_pdu(_pdu(ll_packet(ADV_EXT, payload, tx_add=1)))
    assert pdu.adv_a == ADDR_A1 and pdu.adv_random
    assert (pdu.sid, pdu.did) == (0x5, 0x123)
    assert pdu.tx_power == -8
    assert pdu.data == ADV_DATA_A


def test_extended_adv_pointing_at_aux_has_no_address():
    ext = bytes([0x10]) + bytes(3)  # AuxPtr only
    pdu = parse_adv_pdu(_pdu(ll_packet(ADV_EXT, bytes([len(ext)]) + ext)))
    assert pdu.adv_a is None


def test_truncated_pdu_does_not_raise():
    whole = _pdu(adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A))
    for cut in range(len(whole)):
        parse_adv_pdu(whole[:cut])
    assert parse_adv_pdu(whole[:5]).adv_a is None


def test_pdu_names_depend_on_channel():
    assert pdu_type_name(ADV_IND) == "ADV_IND"
    assert pdu_type_name(ADV_EXT, 37) == "ADV_EXT_IND"
    assert pdu_type_name(ADV_EXT, 12) == "AUX_ADV_IND"
    assert pdu_type_name(SCAN_REQ, 12) == "AUX_SCAN_REQ"
