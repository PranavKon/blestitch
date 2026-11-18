import io

from fastapi.testclient import TestClient

from backend.app import app
from fixtures import make_capture

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_analyze_returns_epochs():
    files = {"file": ("cap.pcap", io.BytesIO(make_capture()), "application/octet-stream")}
    r = client.post("/api/analyze", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["n_packets"] == 8
    assert body["n_epochs"] == 4
    assert body["filename"] == "cap.pcap"


def test_analyze_rejects_garbage():
    files = {"file": ("bad.pcap", io.BytesIO(b"nonsense-not-pcap"), "application/octet-stream")}
    r = client.post("/api/analyze", files=files)
    assert r.status_code == 400
