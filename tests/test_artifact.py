import json

from fixtures import (
    ADDR_B1,
    ADDR_SCANNER,
    ADV_DATA_B,
    ADV_IND,
    adv_ll,
    build_pcap_raw,
    make_capture,
    phdr,
    scan_req_ll,
)

from blestitch.dissect.epoch import segment_epochs
from blestitch.io.pcap_reader import iter_packets
from blestitch.pipeline import analyze_bytes, analyze_pcap
from blestitch.results.artifact import AnalysisResult, epoch_detail, packet_rows


def _result():
    pkts = list(iter_packets(make_capture()))
    epochs = segment_epochs(pkts)
    return AnalysisResult.from_epochs(epochs, source="test", n_packets=len(pkts))


def test_result_counts():
    res = _result()
    assert res.n_packets == 8
    assert res.n_epochs == 4
    assert res.addr_type_counts == {"resolvable": 3, "public": 1}
    assert (res.t_min_us, res.t_max_us) == (1_000_000, 2_100_000)


def test_address_rendered_as_hex():
    assert "7a:11:22:33:44:55" in {e.address for e in _result().epochs}


def test_epoch_ids_index_the_epoch_list():
    assert [e.id for e in _result().epochs] == [0, 1, 2, 3]


def test_epoch_view_carries_the_profile():
    a1 = next(e for e in _result().epochs if e.address == "7a:11:22:33:44:55")
    assert a1.vendor == "Apple" and a1.company_id == 0x004C
    assert a1.tx_power == -12
    assert a1.pdu_counts == {"ADV_IND": 3}
    assert a1.channels == [37, 38, 39]
    assert a1.rssi_mean == -52.3
    assert a1.n_payload_variants == 1


def test_json_roundtrips():
    parsed = json.loads(_result().to_json())
    assert parsed["n_epochs"] == 4
    assert len(parsed["epochs"]) == 4
    assert parsed["schema_version"] == 3
    assert parsed["capture"]["n_packets"] == 8


def test_analyze_pcap_from_file(tmp_path):
    p = tmp_path / "cap.pcap"
    p.write_bytes(make_capture())
    res = analyze_pcap(p)
    assert res.n_packets == 8
    assert res.n_epochs == 4
    assert res.source == "pcap:cap.pcap"
    assert res.capture.n_records == 8


def _drilldown_analysis():
    adv = adv_ll(ADDR_B1, 1, ADV_IND, ADV_DATA_B)
    cap = build_pcap_raw([
        (1_000_000, phdr(37, -60) + adv),
        (1_000_300, phdr(37, -80) + scan_req_ll(ADDR_SCANNER, ADDR_B1)),
        (1_100_000, phdr(38, -61) + adv),
    ])
    return analyze_bytes(cap, source="t")


def test_epoch_detail_decodes_each_variant():
    a = _drilldown_analysis()
    detail = epoch_detail(a.epochs[0], a.profiles[0])
    assert detail["n_variants"] == 1 and detail["n_rows"] == 3
    (variant,) = detail["variants"]
    assert variant["count"] == 2 and variant["pdu"] == "ADV_IND"
    assert variant["hex"] == ADV_DATA_B.hex()
    assert [f["name"] for f in variant["fields"]] == ["Flags", "Complete Local Name"]
    json.dumps(detail)  # must be serializable as-is


def test_packet_rows_interleave_interactions_and_paginate():
    a = _drilldown_analysis()
    page = packet_rows(a.epochs[0], a.profiles[0])
    assert page["total"] == 3
    assert [r["pdu"] for r in page["rows"]] == ["ADV_IND", "SCAN_REQ", "ADV_IND"]
    assert [r["variant"] for r in page["rows"]] == [0, None, 0]
    assert page["rows"][1]["peer"] == "4c:01:02:03:04:05"
    assert not page["rows"][1]["from_advertiser"]

    page = packet_rows(a.epochs[0], a.profiles[0], offset=2, limit=5)
    assert len(page["rows"]) == 1 and page["rows"][0]["channel"] == 38
