import random

from fixtures import (
    ADDR_A1,
    ADDR_B1,
    ADDR_SCANNER,
    ADV_DATA_B,
    ADV_IND,
    SCAN_RSP,
    adv_ll,
    apple_adv,
    build_pcap,
    build_pcap_raw,
    make_rotation_capture,
    phdr,
    scan_req_ll,
)

from blestitch.dissect.epoch import segment_epochs
from blestitch.dissect.profile import build_profile, estimate_adv_interval
from blestitch.io.pcap_reader import iter_packets, read_capture
from blestitch.pipeline import analyze_bytes


def _advertiser(interval_us, n_events, *, loss=0.0, seed=1):
    """An advertiser sending on 37/38/39 every interval + 0-10 ms advDelay."""
    rng = random.Random(seed)
    records, t = [], 1_000_000
    for _ in range(n_events):
        for i, ch in enumerate((37, 38, 39)):
            if rng.random() >= loss:
                records.append((t + i * 400, ch, -60, ADDR_B1, 1, ADV_IND, ADV_DATA_B))
        t += interval_us + rng.randint(0, 10_000)
    return list(iter_packets(build_pcap(records)))


def test_interval_estimate_no_loss():
    n_events, interval, jitter = estimate_adv_interval(_advertiser(100_000, 200))
    assert n_events == 200
    assert 103 < interval < 107      # 100 ms + mean 5 ms advDelay
    assert 0 < jitter < 6


def test_interval_estimate_survives_heavy_loss():
    _, interval, _ = estimate_adv_interval(_advertiser(100_000, 400, loss=0.6))
    assert 102 < interval < 108


def test_interval_needs_enough_samples():
    n_events, interval, jitter = estimate_adv_interval(_advertiser(100_000, 1))
    assert (n_events, interval, jitter) == (1, None, None)


def test_profile_basics():
    adv = adv_ll(ADDR_B1, 1, ADV_IND, ADV_DATA_B)
    rsp = adv_ll(ADDR_B1, 1, SCAN_RSP, bytes([0x05, 0x09]) + b"Band")
    cap = build_pcap_raw([
        (1_000_000, phdr(37, -60) + adv),
        (1_000_400, phdr(38, -64) + adv),
        (1_000_600, phdr(38, -90) + scan_req_ll(ADDR_SCANNER, ADDR_B1)),
        (1_000_900, phdr(38, -62) + rsp),
    ])
    packets, _ = read_capture(cap)
    (epoch,) = segment_epochs(packets)
    prof = build_profile(epoch)
    assert prof.pdu_counts == {"ADV_IND": 2, "SCAN_RSP": 1}
    assert prof.channel_counts == {37: 1, 38: 2}
    assert (prof.rssi_min, prof.rssi_max, prof.rssi_mean) == (-64, -60, -62.0)
    assert prof.connectable and prof.scannable and prof.has_scan_rsp
    assert (prof.n_scan_req, prof.n_connect_ind) == (1, 0)
    assert prof.n_events == 1
    assert prof.local_name == "Band"       # the longer scan-response name wins over "BB"
    assert prof.ad_signature == "01:1|09:2"  # shape of the advertisement, not the scan response
    assert len(prof.variants) == 2
    assert prof.label == "“Band”"


def test_payload_variants_are_in_order_of_first_appearance():
    tag = bytes([1, 2, 3])
    records = [
        (1_000_000 + i * 100_000, 37, -50, ADDR_A1, 1, ADV_IND, apple_adv(tag, 0x10 + i // 3))
        for i in range(9)
    ]
    (epoch,) = segment_epochs(list(iter_packets(build_pcap(records))))
    prof = build_profile(epoch)
    assert [v.count for v in prof.variants] == [3, 3, 3]
    assert [v.t_first_us for v in prof.variants] == [1_000_000, 1_300_000, 1_600_000]
    assert prof.vendor == "Apple"
    assert prof.tags == ["Handoff", "Nearby Info"]
    assert prof.label == "Apple · Handoff, Nearby Info"
    assert prof.n_signatures == 1


def test_rotation_scenario_segments_into_one_epoch_per_address():
    capture, truth = make_rotation_capture(minutes=6)
    analysis = analyze_bytes(capture, source="rotation")
    assert analysis.result.capture.time_source == "firmware"
    assert {e.address for e in analysis.epochs} == set(truth)
    assert len(analysis.epochs) == len(truth)
    by_device: dict[str, list] = {}
    for epoch, view in zip(analysis.epochs, analysis.result.epochs):
        by_device.setdefault(truth[epoch.address], []).append(view)
    assert len(by_device["phone-1"]) >= 2          # it rotated at least once
    assert all(v.addr_type == "resolvable" for v in by_device["phone-1"])
    assert all(180 < v.adv_interval_ms < 192 for v in by_device["phone-1"] if v.n_packets > 100)
    assert by_device["wearable"][0].local_name == "Band-42"
    assert by_device["wearable"][0].n_scan_req > 0
    assert by_device["tracker"][0].tags == ["Find My"]
    assert by_device["beacon"][0].label == "Eddystone-EID"


def test_interval_estimate_when_most_events_are_missed():
    # A weak device heard on one channel only, four events in five lost: even
    # the smallest gaps span several intervals.
    rng = random.Random(3)
    records, t = [], 1_000_000
    for _ in range(1500):
        if rng.random() < 0.2:
            records.append((t, 37, -88, ADDR_B1, 1, ADV_IND, ADV_DATA_B))
        t += 185_000 + rng.randint(0, 2_000)
    _, interval, _ = estimate_adv_interval(list(iter_packets(build_pcap(records))))
    assert 184 < interval < 188


def test_placeholder_company_id_is_not_named_as_a_vendor():
    adv = bytes([0x02, 0x01, 0x06, 0x05, 0xFF, 0x00, 0x00, 0x01, 0x02])
    records = [(1_000_000 + i * 100_000, 37, -60, ADDR_B1, 1, ADV_IND, adv) for i in range(3)]
    (epoch,) = segment_epochs(list(iter_packets(build_pcap(records))))
    prof = build_profile(epoch)
    assert prof.company_id == 0 and prof.vendor is None
