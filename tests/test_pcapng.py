from fixtures import ADDR_A1, ADDR_PUB, make_pcapng_capture

from blestitch.dissect.epoch import segment_epochs
from blestitch.io.pcap_reader import iter_packets
from blestitch.records import AddrType


def _packets():
    return list(iter_packets(make_pcapng_capture()))


def test_pcapng_nordic_parses_all():
    assert len(_packets()) == 5


def test_pcapng_nordic_fields():
    pkts = _packets()
    a1 = next(p for p in pkts if p.address == ADDR_A1)
    assert a1.channel == 37
    assert a1.rssi == -50          # stored as magnitude in the Nordic header
    assert a1.addr_type is AddrType.RESOLVABLE
    assert a1.tx_power == -12
    assert a1.ad_structure == ((0x01, 1), (0x0A, 1), (0xFF, 4))


def test_pcapng_nordic_public_device():
    pub = next(p for p in _packets() if p.address == ADDR_PUB)
    assert pub.addr_type is AddrType.PUBLIC
    assert pub.addr_random is False


def test_pcapng_nordic_epochs():
    epochs = segment_epochs(_packets())
    # ADDR_A1 (x3 across channels), ADDR_B1, ADDR_PUB -> 3 epochs
    assert len(epochs) == 3
    a1 = next(e for e in epochs if e.address == ADDR_A1)
    assert a1.n_packets == 3
