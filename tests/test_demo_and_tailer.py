from __future__ import annotations

import json

import pytest

from app.database import Database
from app.sensors.demo import scenario_events
from app.sensors.eve_tailer import EveTailer
from app.services.detection import DetectionEngine
from app.services.model_runtime import ModelRuntime
from app.services.pipeline import EventPipeline


@pytest.mark.parametrize(
    ("name", "minimum"),
    [("scan", 25), ("beacon", 6), ("exfiltration", 1), ("multi-stage", 30)],
)
def test_demo_scenarios_are_deterministic_shapes(name: str, minimum: int) -> None:
    events = scenario_events(name)
    assert len(events) >= minimum
    assert all("src_ip" in event and "dest_ip" in event for event in events)


def test_unknown_demo_scenario_is_rejected() -> None:
    with pytest.raises(KeyError):
        scenario_events("ransomware")


def test_eve_tailer_processes_valid_records_and_skips_invalid(settings) -> None:
    database = Database(settings.database_path)
    database.initialize()
    model = ModelRuntime(settings.model_path, settings.model_metadata_path)
    pipeline = EventPipeline(database, DetectionEngine(model))
    valid = {
        "event_type": "flow",
        "src_ip": "8.8.8.8",
        "dest_ip": "10.0.0.3",
        "proto": "UDP",
    }
    settings.eve_path.write_text(json.dumps(valid) + "\nnot-json\n", encoding="utf-8")
    tailer = EveTailer(settings.eve_path, pipeline)
    tailer._poll_once()
    assert database.metrics()["events"] == 1

    with settings.eve_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event_type": "flow"}) + "\n")
    tailer._poll_once()
    assert database.metrics()["events"] == 1
    tailer.stop()
