from fixtures import (
    ADDR_A1,
    ADDR_B1,
    ADDR_SCANNER,
    ADV_DATA_B,
    ADV_IND,
    adv_ll,
    build_pcap,
    build_pcap_raw,
    connect_ind_ll,
    make_capture,
    phdr,
    scan_req_ll,
)

from blestitch.dissect.epoch import segment_epochs
from blestitch.io.pcap_reader import iter_packets
from blestitch.records import AddrType


def _epochs():
    pkts = list(iter_packets(make_capture()))
    return segment_epochs(pkts)


def test_one_epoch_per_distinct_address():
    epochs = _epochs()
    assert len(epochs) == 4  # A1, A2, B1, PUB


def test_epochs_sorted_by_start():
    epochs = _epochs()
    starts = [e.t_start_us for e in epochs]
    assert starts == sorted(starts)


def test_epoch_bounds_and_packets():
    a1 = next(e for e in _epochs() if e.address == ADDR_A1)
    assert a1.n_packets == 3
    assert a1.t_start_us == 1_000_000
    assert a1.t_end_us == 1_200_000
    assert a1.duration_us == 200_000


def test_gap_splits_same_address_into_two_epochs():
    pcap = build_pcap([
        (1_000_000, 37, -60, ADDR_B1, 1, ADV_IND, ADV_DATA_B),
        (11_000_000, 37, -60, ADDR_B1, 1, ADV_IND, ADV_DATA_B),
    ])
    pkts = list(iter_packets(pcap))
    assert len(segment_epochs(pkts, max_gap_us=5_000_000)) == 2
    assert len(segment_epochs(pkts, max_gap_us=10_000_000)) == 1
    assert len(segment_epochs(pkts)) == 1  # default tolerates slow advertisers


def test_same_bits_public_and_random_are_different_devices():
    addr = 0x0000AABBCCDD
    pcap = build_pcap([
        (1_000_000, 37, -60, addr, 0, ADV_IND, ADV_DATA_B),
        (1_100_000, 37, -60, addr, 1, ADV_IND, ADV_DATA_B),
    ])
    epochs = segment_epochs(list(iter_packets(pcap)))
    assert sorted(e.addr_type.value for e in epochs) == ["nrpa", "public"]


def test_interactions_attach_to_the_epoch_on_air():
    adv = adv_ll(ADDR_B1, 1, ADV_IND, ADV_DATA_B)
    cap = build_pcap_raw([
        (1_000_000, phdr(37, -60) + adv),
        (1_000_300, phdr(37, -80) + scan_req_ll(ADDR_SCANNER, ADDR_B1)),
        (2_000_000, phdr(37, -60) + adv),
        # 100 s later the same address is back and gets connected to
        (102_000_000, phdr(37, -60) + adv),
        (102_000_300, phdr(37, -80) + connect_ind_ll(ADDR_SCANNER, ADDR_B1)),
        # a scan request for an advertiser we never heard: no epoch
        (3_000_000, phdr(37, -80) + scan_req_ll(ADDR_SCANNER, ADDR_A1)),
    ])
    epochs = segment_epochs(list(iter_packets(cap)))
    assert len(epochs) == 2
    first, second = epochs
    assert first.addr_type is AddrType.RESOLVABLE
    assert (first.n_packets, len(first.interactions)) == (2, 1)
    assert (second.n_packets, len(second.interactions)) == (1, 1)
    # the scanner's RSSI and timing never leak into the epoch
    assert first.t_end_us == 2_000_000
    assert {p.rssi for p in first.packets} == {-60}
