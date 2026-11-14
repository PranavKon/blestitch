import json

from blestitch.pipeline import analyze_pcap
from blestitch.results.artifact import AnalysisResult
from blestitch.dissect.epoch import segment_epochs
from blestitch.io.pcap_reader import iter_packets
from fixtures import make_capture


def test_result_counts():
    pkts = list(iter_packets(make_capture()))
    epochs = segment_epochs(pkts)
    res = AnalysisResult.from_epochs(epochs, source="test", n_packets=len(pkts))
    assert res.n_packets == 8
    assert res.n_epochs == 4
    assert res.addr_type_counts == {"resolvable": 3, "public": 1}


def test_address_rendered_as_hex():
    pkts = list(iter_packets(make_capture()))
    epochs = segment_epochs(pkts)
    res = AnalysisResult.from_epochs(epochs, source="test", n_packets=len(pkts))
    addrs = {e.address for e in res.epochs}
    assert "7a:11:22:33:44:55" in addrs


def test_json_roundtrips():
    pkts = list(iter_packets(make_capture()))
    epochs = segment_epochs(pkts)
    res = AnalysisResult.from_epochs(epochs, source="test", n_packets=len(pkts))
    parsed = json.loads(res.to_json())
    assert parsed["n_epochs"] == 4
    assert len(parsed["epochs"]) == 4


def test_analyze_pcap_from_file(tmp_path):
    p = tmp_path / "cap.pcap"
    p.write_bytes(make_capture())
    res = analyze_pcap(p)
    assert res.n_packets == 8
    assert res.n_epochs == 4
