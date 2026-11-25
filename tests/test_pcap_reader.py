import gzip
import struct

import pytest
from fixtures import (
    ADDR_A1,
    ADDR_B1,
    ADDR_PUB,
    ADDR_SCANNER,
    ADV_DATA_A,
    ADV_DATA_B,
    ADV_IND,
    adv_ll,
    build_pcap_raw,
    build_pcapng,
    connect_ind_ll,
    ll_packet,
    make_capture,
    nordic_record,
    phdr,
    scan_req_ll,
)

from blestitch.io.pcap_reader import PcapFormatError, iter_packets, read_capture
from blestitch.records import AddrType

HOST0 = 1_700_000_000_000_000


def _packets():
    return list(iter_packets(make_capture()))


def test_parses_all_packets():
    assert len(_packets()) == 8


def test_addresses_and_types():
    pkts = _packets()
    a1 = [p for p in pkts if p.address == ADDR_A1]
    assert len(a1) == 3
    assert all(p.addr_type is AddrType.RESOLVABLE for p in a1)
    pub = [p for p in pkts if p.address == ADDR_PUB]
    assert len(pub) == 1
    assert pub[0].addr_type is AddrType.PUBLIC
    assert pub[0].addr_random is False


def test_channel_and_rssi_recovered():
    # DLT 256 stores the RF channel number (0, 12, 39), not the channel index.
    a1 = [p for p in _packets() if p.address == ADDR_A1]
    assert [p.channel for p in a1] == [37, 38, 39]
    assert a1[0].rssi == -50


def test_tx_power_and_ad_structure():
    a1 = next(p for p in _packets() if p.address == ADDR_A1)
    assert a1.tx_power == -12  # 0xF4 as signed dBm
    # flags, tx power, manufacturer-specific data
    assert a1.ad_structure == ((0x01, 1), (0x0A, 1), (0xFF, 4))


def test_timestamp_microseconds():
    pkts = sorted(_packets(), key=lambda p: p.t_hw_us)
    assert pkts[0].t_hw_us == 1_000_000


def test_rejects_non_pcap():
    with pytest.raises(PcapFormatError):
        list(iter_packets(b"not a pcap file at all........"))


def test_rejects_capture_with_no_ble_link_type():
    ethernet = build_pcap_raw([(1, b"\x00" * 60)], linktype=1)
    with pytest.raises(PcapFormatError):
        read_capture(ethernet)


def test_gzip_is_transparent():
    packets, _ = read_capture(gzip.compress(make_capture()))
    assert len(packets) == 8


def test_nanosecond_pcap_timestamps():
    body = phdr(37, -50) + adv_ll(ADDR_B1, 1, ADV_IND, ADV_DATA_B)
    cap = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 256)
    cap += struct.pack("<IIII", 3, 500_000_000, len(body), len(body)) + body
    packets, _ = read_capture(cap)
    assert packets[0].t_hw_us == 3_500_000


def test_bad_crc_is_dropped_and_counted():
    good = phdr(37, -50) + adv_ll(ADDR_B1, 1, ADV_IND, ADV_DATA_B)
    bad = phdr(37, -50, crc_ok=False) + adv_ll(0x7FFFFFFFFFFF, 1, ADV_IND, ADV_DATA_B)
    packets, stats = read_capture(build_pcap_raw([(1, good), (2, bad)]))
    assert [p.address for p in packets] == [ADDR_B1]
    assert stats.n_bad_crc == 1
    assert stats.n_records == 2
    assert stats.n_packets == 1


def test_data_channel_packets_are_counted_not_parsed():
    data_pkt = phdr(5, -50) + ll_packet(0x2, b"\x01\x02", access_address=0x50123456)
    packets, stats = read_capture(build_pcap_raw([(1, data_pkt)]))
    assert packets == []
    assert stats.n_data_channel == 1


def test_coded_phy_has_a_coding_indicator_byte():
    ll = adv_ll(ADDR_B1, 1, ADV_IND, ADV_DATA_B)
    coded = phdr(37, -50, phy=2) + ll[:4] + b"\x01" + ll[4:]
    packets, _ = read_capture(build_pcap_raw([(1, coded)]))
    assert packets[0].address == ADDR_B1
    assert packets[0].payload == ADV_DATA_B


def test_scan_req_and_connect_ind_target_the_advertiser():
    cap = build_pcap_raw(
        [
            (1, phdr(37, -70) + scan_req_ll(ADDR_SCANNER, ADDR_B1)),
            (2, phdr(37, -70) + connect_ind_ll(ADDR_SCANNER, ADDR_B1)),
        ]
    )
    packets, _ = read_capture(cap)
    assert [p.address for p in packets] == [ADDR_B1, ADDR_B1]
    assert [p.peer_address for p in packets] == [ADDR_SCANNER, ADDR_SCANNER]
    assert all(p.addr_type is AddrType.RESOLVABLE for p in packets)
    assert not any(p.from_advertiser for p in packets)


# ---- pcapng -------------------------------------------------------------


def test_pcapng_matches_pcap():
    body = phdr(38, -44) + adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    packets, stats = read_capture(build_pcapng([256], [(0, 2_000_000, body)]))
    assert len(packets) == 1
    assert (packets[0].t_hw_us, packets[0].channel, packets[0].rssi) == (2_000_000, 38, -44)
    assert stats.link_types == ["BLUETOOTH_LE_LL_WITH_PHDR (256)"]
    assert stats.time_source == "capture"


def test_pcapng_timestamp_resolution_option():
    body = phdr(37, -44) + adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    cap = build_pcapng([256], [(0, 2_000_000_000, body)], tsresol=9)
    packets, _ = read_capture(cap)
    assert packets[0].t_hw_us == 2_000_000


def test_pcapng_skips_other_interfaces():
    body = phdr(37, -44) + adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    cap = build_pcapng([1, 256], [(0, 1, b"\x00" * 40), (1, 2, body)])
    packets, stats = read_capture(cap)
    assert len(packets) == 1
    assert stats.n_unsupported_link == 1


def test_truncated_pcapng_keeps_what_it_read():
    body = phdr(37, -44) + adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    cap = build_pcapng([256], [(0, 1, body), (0, 2, body)])
    packets, _ = read_capture(cap[:-10])
    assert len(packets) == 1


# ---- Nordic (DLT 272) ---------------------------------------------------


def test_nordic_fields():
    ll = adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    rec = nordic_record(ll, channel=39, rssi=-42, time_field=5_000)
    packets, stats = read_capture(build_pcapng([272], [(0, HOST0, rec)]))
    p = packets[0]
    assert (p.address, p.channel, p.rssi) == (ADDR_A1, 39, -42)
    assert p.payload == ADV_DATA_A
    assert stats.time_source == "firmware"
    assert stats.link_types == ["NORDIC_BLE (272)"]


def test_nordic_bad_crc_dropped():
    ll = adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    rec = nordic_record(ll, crc_ok=False)
    packets, stats = read_capture(build_pcapng([272], [(0, HOST0, rec)]))
    assert packets == [] and stats.n_bad_crc == 1


def test_nordic_v3_uses_firmware_clock_and_unwraps_it():
    ll = adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    wrap = 1 << 32
    # (host time offset, firmware timestamp): host time is jittery, and the
    # 32-bit firmware clock wraps between the 3rd and 4th packets.
    steps = [(0, 1_000), (600, 1_500), (wrap - 1_100 + 3_000, wrap - 100), (wrap - 600 - 2_000, 400)]
    recs = [
        (0, HOST0 + host, nordic_record(ll, counter=i, time_field=fw))
        for i, (host, fw) in enumerate(steps)
    ]
    packets, _ = read_capture(build_pcapng([272], recs))
    assert [p.t_hw_us - HOST0 for p in packets] == [0, 500, wrap - 1_100, wrap - 600]


def test_nordic_v2_accumulates_delta_times():
    ll = adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    airtime = 8 * (1 + len(ll))  # 1M PHY: preamble + packet, 8 us per byte
    recs = [
        (0, HOST0, nordic_record(ll, protover=2, counter=10, time_field=99_999)),
        # host timestamp is 4 ms late; the 150 us delta is what counts
        (0, HOST0 + 4_000, nordic_record(ll, protover=2, counter=11, time_field=150)),
        (0, HOST0 + 9_000, nordic_record(ll, protover=2, counter=12, time_field=700)),
    ]
    packets, _ = read_capture(build_pcapng([272], recs))
    t = [p.t_hw_us - HOST0 for p in packets]
    assert t == [0, airtime + 150, 2 * airtime + 150 + 700]


def test_nordic_v2_falls_back_to_host_gap_when_a_record_is_missing():
    ll = adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    recs = [
        (0, HOST0, nordic_record(ll, protover=2, counter=10, time_field=0)),
        # counter jumps 10 -> 12: the delta refers to a packet we never saw
        (0, HOST0 + 50_000, nordic_record(ll, protover=2, counter=12, time_field=150)),
    ]
    packets, _ = read_capture(build_pcapng([272], recs))
    assert packets[1].t_hw_us - HOST0 == 50_000


# ---- bare LL (DLT 251) --------------------------------------------------


def test_link_type_251_has_no_channel_or_signal():
    ll = adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    packets, stats = read_capture(build_pcap_raw([(1_000_000, ll)], linktype=251))
    (p,) = packets
    assert (p.address, p.t_hw_us, p.payload) == (ADDR_A1, 1_000_000, ADV_DATA_A)
    assert p.channel is None and p.rssi is None
    assert stats.link_types == ["BLUETOOTH_LE_LL (251)"]
    assert stats.time_source == "capture"


def test_nordic_event_header_length_is_read_from_the_record():
    ll = adv_ll(ADDR_A1, 1, ADV_IND, ADV_DATA_A)
    rec = bytearray(nordic_record(ll, channel=38, rssi=-47))
    # A longer event header: two extra bytes before the LL packet.
    rec[7] = 12
    rec[17:17] = b"\x00\x00"
    rec[1:3] = (len(rec) - 7).to_bytes(2, "little")
    packets, _ = read_capture(build_pcapng([272], [(0, HOST0, bytes(rec))]))
    assert (packets[0].address, packets[0].channel, packets[0].rssi) == (ADDR_A1, 38, -47)
