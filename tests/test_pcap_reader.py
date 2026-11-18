from blestitch.io.pcap_reader import PcapFormatError, iter_packets
from blestitch.records import AddrType
from fixtures import ADDR_A1, ADDR_PUB, make_capture


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
    pkts = _packets()
    first_a1 = next(p for p in pkts if p.address == ADDR_A1)
    assert first_a1.channel == 37
    assert first_a1.rssi == -50


def test_tx_power_and_ad_structure():
    pkts = _packets()
    a1 = next(p for p in pkts if p.address == ADDR_A1)
    assert a1.tx_power == -12  # 0xF4 as signed dBm
    # flags, tx power, manufacturer-specific data
    assert a1.ad_structure == ((0x01, 1), (0x0A, 1), (0xFF, 4))


def test_timestamp_microseconds():
    pkts = sorted(_packets(), key=lambda p: p.t_hw_us)
    assert pkts[0].t_hw_us == 1_000_000


def test_rejects_non_pcap():
    try:
        list(iter_packets(b"not a pcap file at all........"))
    except PcapFormatError:
        return
    raise AssertionError("expected PcapFormatError")
