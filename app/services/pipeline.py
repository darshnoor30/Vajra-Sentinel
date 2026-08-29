from __future__ import annotations

from typing import Any

from app.database import Database
from app.services.detection import DetectionEngine
from app.services.normalizer import normalize_eve

REDACTED_KEYS = {
    "authorization",
    "cookie",
    "http_body",
    "packet",
    "password",
    "payload",
    "payload_printable",
    "request_body",
    "response_body",
}


def sanitize_evidence(value: Any) -> Any:
    """Remove packet/content secrets and bound unusually large scalar values."""

    if isinstance(value, dict):
        return {
            str(key): sanitize_evidence(item)
            for key, item in value.items()
            if str(key).lower() not in REDACTED_KEYS
        }
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value[:100]]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "…[truncated]"
    return value


class EventPipeline:
    def __init__(self, database: Database, detector: DetectionEngine):
        self.database = database
        self.detector = detector

    def process(self, raw: dict[str, Any], sensor_id: str) -> dict[str, Any]:
        event = normalize_eve(raw, sensor_id=sensor_id)
        event_id = self.database.insert_event(event, sanitize_evidence(raw))
        detection_ids: list[int] = []
        incident_ids: list[int] = []
        for detection in self.detector.analyze(event):
            detection_id = self.database.insert_detection(event_id, event, detection)
            incident_id = self.database.correlate_incident(detection_id)
            detection_ids.append(detection_id)
            if incident_id not in incident_ids:
                incident_ids.append(incident_id)
        return {
            "event_id": event_id,
            "detection_ids": detection_ids,
            "incident_ids": incident_ids,
        }
