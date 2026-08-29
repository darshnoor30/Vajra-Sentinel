from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def sample_alert() -> dict:
    return {
        "timestamp": "2026-08-28T12:00:00Z",
        "event_type": "alert",
        "src_ip": "45.155.205.233",
        "src_port": 53000,
        "dest_ip": "10.0.0.15",
        "dest_port": 445,
        "proto": "TCP",
        "alert": {
            "signature_id": 1234,
            "signature": "Test critical signature",
            "category": "Exploit",
            "severity": 1,
            "action": "allowed",
        },
    }


def test_dashboard_and_health_have_security_headers(client: TestClient) -> None:
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Evidence before" in dashboard.text
    health = client.get("/api/v1/health")
    assert health.json()["status"] == "healthy"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]


def test_ingest_requires_auth_and_creates_incident(client: TestClient) -> None:
    payload = {"sensor_id": "pytest", "event": sample_alert()}
    assert client.post("/api/v1/events/ingest", json=payload).status_code == 401
    response = client.post(
        "/api/v1/events/ingest",
        json=payload,
        headers={"X-API-Key": "test-api-key-that-is-long-enough"},
    )
    assert response.status_code == 200
    result = response.json()
    assert len(result["detection_ids"]) == 1
    assert len(result["incident_ids"]) == 1
    assert client.get("/api/v1/metrics").json()["detections"] == 1


def test_response_is_simulated_and_audited(client: TestClient) -> None:
    headers = {"X-API-Key": "test-api-key-that-is-long-enough"}
    created = client.post(
        "/api/v1/events/ingest",
        json={"sensor_id": "pytest", "event": sample_alert()},
        headers=headers,
    ).json()
    detection_id = created["detection_ids"][0]
    contained = client.post(
        f"/api/v1/detections/{detection_id}/contain",
        json={"ttl_seconds": 600, "reason": "confirmed lab simulation"},
        headers=headers,
    )
    assert contained.status_code == 200
    assert contained.json()["status"] == "simulated"
    blocks = client.get("/api/v1/response/blocks").json()["items"]
    assert blocks[0]["ip"] == "45.155.205.233"
    assert client.get("/api/v1/audit").json()["items"][0]["action"] == "response.block_created"


def test_invalid_severity_and_disabled_demo_return_errors(client: TestClient) -> None:
    assert client.get("/api/v1/detections?severity=urgent").status_code == 422
    assert client.post("/api/v1/demo/scenarios/scan").status_code == 404
    oversized = client.post(
        "/api/v1/events/ingest",
        content=b"{}",
        headers={"Content-Length": "2000001"},
    )
    assert oversized.status_code == 413


def test_read_endpoints_and_incident_update(client: TestClient) -> None:
    headers = {"Authorization": "Bearer test-api-key-that-is-long-enough"}
    created = client.post(
        "/api/v1/events/ingest",
        json={"sensor_id": "pytest", "event": sample_alert()},
        headers=headers,
    ).json()
    detection_id = created["detection_ids"][0]
    incident_id = created["incident_ids"][0]
    assert client.get("/api/v1/events").json()["items"]
    assert client.get(f"/api/v1/detections/{detection_id}").status_code == 200
    assert client.get("/api/v1/detections/99999").status_code == 404
    changed = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "triaged", "note": "validated"},
        headers=headers,
    )
    assert changed.json()["status"] == "triaged"
    assert (
        client.patch(
            "/api/v1/incidents/99999",
            json={"status": "closed", "note": "missing"},
            headers=headers,
        ).status_code
        == 404
    )
    assert "vajra_events_total" in client.get("/metrics").text
    assert client.get("/api/v1/about").json()["name"] == "Vajra Sentinel"
    assert client.get("/api/v1/model").json()["status"] == "unavailable"


def test_demo_enabled_seeds_and_replays(tmp_path) -> None:
    settings = Settings(
        environment="test",
        api_key="test-api-key-that-is-long-enough",
        database_path=tmp_path / "demo.db",
        eve_path=tmp_path / "eve.json",
        model_path=tmp_path / "model.joblib",
        model_metadata_path=tmp_path / "metadata.json",
        demo_mode=True,
        ips_mode="dry-run",
    )
    with TestClient(create_app(settings)) as demo_client:
        assert demo_client.get("/api/v1/metrics").json()["events"] >= 30
        replay = demo_client.post("/api/v1/demo/scenarios/scan")
        assert replay.status_code == 200
        assert replay.json()["events_ingested"] == 25
        assert replay.json()["replaced"]["events_removed"] >= 30
        assert demo_client.get("/api/v1/metrics").json()["events"] == 25
        second_replay = demo_client.post("/api/v1/demo/scenarios/scan")
        assert second_replay.status_code == 200
        assert second_replay.json()["replaced"]["events_removed"] == 25
        assert demo_client.get("/api/v1/metrics").json()["events"] == 25
        assert demo_client.post("/api/v1/demo/scenarios/unknown").status_code == 404
