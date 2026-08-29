from __future__ import annotations

from app.database import Database
from app.schemas import Detection, NormalizedEvent
from app.services.pipeline import sanitize_evidence
from app.services.response import ResponseEngine


def make_detection() -> Detection:
    return Detection(
        rule_id="TEST-001",
        title="Test signal",
        severity="high",
        confidence=95,
        source="signature",
        description="Test description",
        evidence={"count": 1},
        mitre_techniques=["T1046"],
        recommended_action="Review",
        response_eligible=True,
    )


def test_database_correlation_updates_and_response_lifecycle(settings) -> None:
    database = Database(settings.database_path)
    database.initialize()
    event = NormalizedEvent(
        src_ip="45.155.205.233",
        dest_ip="10.0.0.4",
        dest_port=443,
        protocol="TCP",
    )
    first_event = database.insert_event(event, {"event_type": "flow"})
    first_detection = database.insert_detection(first_event, event, make_detection())
    first_incident = database.correlate_incident(first_detection)
    second_event = database.insert_event(event, {"event_type": "flow"})
    second_detection = database.insert_detection(second_event, event, make_detection())
    second_incident = database.correlate_incident(second_detection)

    assert first_incident == second_incident
    assert database.list_incidents()[0]["detection_count"] == 2
    assert "raw_json" not in database.list_events()[0]
    assert database.list_detections(severity="high")[0]["evidence"] == {"count": 1}
    assert database.get_detection(99999) is None
    assert database.update_incident(first_incident, "triaged", "reviewed", "pytest") is True
    assert database.update_incident(99999, "closed", "missing", "pytest") is False

    response = ResponseEngine(settings, database)
    result = response.contain(
        database.get_detection(first_detection),
        ttl_seconds=600,
        reason="confirmed",
        actor="pytest",
    )
    assert result["status"] == "simulated"
    assert response.revert(result["id"], "pytest")["status"] == "reverted"
    assert database.list_blocks()[0]["status"] == "reverted"
    assert database.metrics()["events"] == 2
    assert len(database.audit_log()) >= 3


def test_missing_detection_cannot_be_correlated(settings) -> None:
    database = Database(settings.database_path)
    database.initialize()
    try:
        database.correlate_incident(404)
    except KeyError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("Expected KeyError")


def test_demo_reset_preserves_live_evidence_and_repairs_incidents(settings) -> None:
    database = Database(settings.database_path)
    database.initialize()
    shared = NormalizedEvent(
        sensor_id="verified-demo-lab",
        src_ip="45.155.205.233",
        dest_ip="10.0.0.4",
        dest_port=443,
        protocol="TCP",
    )
    demo_event = database.insert_event(shared, {"event_type": "flow"})
    demo_detection = database.insert_detection(demo_event, shared, make_detection())
    database.correlate_incident(demo_detection)

    live = shared.model_copy(update={"sensor_id": "suricata-production"})
    live_event = database.insert_event(live, {"event_type": "flow"})
    live_detection = database.insert_detection(live_event, live, make_detection())
    database.correlate_incident(live_detection)

    demo_only = shared.model_copy(update={"sensor_id": "demo-scan", "src_ip": "8.8.8.8"})
    demo_only_event = database.insert_event(demo_only, {"event_type": "flow"})
    demo_only_detection = database.insert_detection(demo_only_event, demo_only, make_detection())
    database.correlate_incident(demo_only_detection)

    removed = database.reset_demo_data()

    assert removed == {
        "events_removed": 2,
        "detections_removed": 2,
        "incidents_removed": 1,
        "blocks_removed": 0,
    }
    assert database.metrics()["events"] == 1
    assert database.metrics()["detections"] == 1
    assert database.list_events()[0]["sensor_id"] == "suricata-production"
    assert database.list_incidents()[0]["detection_count"] == 1


def test_evidence_sanitizer_removes_content_and_bounds_values() -> None:
    raw = {
        "packet": "base64-packet",
        "http": {"cookie": "session=secret", "hostname": "example.org"},
        "records": list(range(120)),
        "long": "x" * 5000,
    }
    result = sanitize_evidence(raw)
    assert "packet" not in result
    assert "cookie" not in result["http"]
    assert result["http"]["hostname"] == "example.org"
    assert len(result["records"]) == 100
    assert result["long"].endswith("[truncated]")
