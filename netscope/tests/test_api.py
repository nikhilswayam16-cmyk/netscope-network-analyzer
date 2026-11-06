from pathlib import Path

from fastapi.testclient import TestClient

from netscope.main import app

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "demo-traffic.pcap"


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["service"] == "netscope"


def test_demo_endpoint_populates_analysis() -> None:
    client = TestClient(app)
    response = client.post("/api/demo")
    assert response.status_code == 200
    assert response.json()["meta"]["packets"] == 94
    assert client.get("/api/analysis").status_code == 200


def test_uploaded_capture_and_export() -> None:
    client = TestClient(app)
    with SAMPLE.open("rb") as capture:
        response = client.post("/api/analyze", files={"file": ("test.pcap", capture, "application/vnd.tcpdump.pcap")})
    assert response.status_code == 200
    assert response.json()["meta"]["filename"] == "test.pcap"
    exported = client.get("/api/export")
    assert exported.status_code == 200
    assert "application/json" in exported.headers["content-type"]


def test_upload_rejects_non_pcap_extension() -> None:
    client = TestClient(app)
    response = client.post("/api/analyze", files={"file": ("notes.txt", b"not a capture", "text/plain")})
    assert response.status_code == 415
