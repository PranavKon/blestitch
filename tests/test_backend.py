import io

from fastapi.testclient import TestClient
from fixtures import (
    ADV_DATA_A,
    ADV_IND,
    adv_ll,
    build_pcapng,
    make_capture,
    nordic_record,
)

from backend import app as backend_app
from backend.app import app

client = TestClient(app)


def _upload(data: bytes, name: str = "cap.pcap", **params):
    files = {"file": (name, io.BytesIO(data), "application/octet-stream")}
    return client.post("/api/analyze", files=files, params=params)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_analyze_returns_epochs():
    r = _upload(make_capture())
    assert r.status_code == 200
    body = r.json()
    assert body["n_packets"] == 8
    assert body["n_epochs"] == 4
    assert body["filename"] == "cap.pcap"
    assert body["analysis_id"]
    assert body["capture"]["link_types"] == ["BLUETOOTH_LE_LL_WITH_PHDR (256)"]


def test_analyze_accepts_nordic_pcapng():
    rec = nordic_record(adv_ll(0x7A1122334455, 1, ADV_IND, ADV_DATA_A))
    r = _upload(build_pcapng([272], [(0, 1_700_000_000_000_000, rec)]), "cap.pcapng")
    assert r.status_code == 200
    assert r.json()["epochs"][0]["vendor"] == "Apple"


def test_analyze_rejects_garbage():
    r = _upload(b"nonsense-not-pcap-at-all-nope", "bad.pcap")
    assert r.status_code == 400
    assert "unreadable capture" in r.json()["detail"]


def test_analyze_rejects_empty_file():
    assert _upload(b"").status_code == 400


def test_max_gap_parameter():
    assert _upload(make_capture(), max_gap_s=0.05).json()["n_epochs"] > 4
    assert _upload(make_capture(), max_gap_s=0).status_code == 422


def test_epoch_drilldown():
    body = _upload(make_capture()).json()
    aid = body["analysis_id"]
    epoch = next(e for e in body["epochs"] if e["address"] == "7a:11:22:33:44:55")

    detail = client.get(f"/api/analyses/{aid}/epochs/{epoch['id']}").json()
    assert detail["n_variants"] == 1
    mfr = detail["variants"][0]["fields"][2]
    assert mfr["name"] == "Manufacturer Specific Data"
    assert mfr["summary"].startswith("Apple, Inc. (0x004c)")

    page = client.get(f"/api/analyses/{aid}/epochs/{epoch['id']}/packets", params={"limit": 2}).json()
    assert page["total"] == 3 and len(page["rows"]) == 2
    assert page["rows"][0]["t_us"] == 1_000_000


def test_drilldown_404s():
    aid = _upload(make_capture()).json()["analysis_id"]
    assert client.get(f"/api/analyses/{aid}/epochs/99").status_code == 404
    assert client.get("/api/analyses/nope/epochs/0").status_code == 404
    assert client.get(f"/api/analyses/{aid}/epochs/0/packets", params={"limit": 0}).status_code == 422


def test_only_recent_analyses_are_kept():
    first = _upload(make_capture()).json()["analysis_id"]
    for _ in range(backend_app.MAX_STORED_ANALYSES):
        _upload(make_capture())
    assert client.get(f"/api/analyses/{first}/epochs/0").status_code == 404
