from blestitch.dissect.epoch import segment_epochs
from blestitch.io.pcap_reader import iter_packets
from fixtures import ADDR_A1, make_capture


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
    from fixtures import ADDR_B1, build_pcap, ADV_DATA_B, ADV_IND

    # Same address seen twice, 10 s apart -> two epochs with default 5 s gap.
    pcap = build_pcap([
        (1_000_000, 37, -60, ADDR_B1, 1, ADV_IND, ADV_DATA_B),
        (11_000_000, 37, -60, ADDR_B1, 1, ADV_IND, ADV_DATA_B),
    ])
    epochs = segment_epochs(list(iter_packets(pcap)))
    assert len(epochs) == 2
