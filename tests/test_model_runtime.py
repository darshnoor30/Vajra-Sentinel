from __future__ import annotations

import hashlib
import json

import joblib

from app.schemas import NormalizedEvent
from app.services.model_runtime import FEATURE_COLUMNS, ModelRuntime, event_features


class DummyPipeline:
    def predict_proba(self, _frame):
        return [[0.1, 0.9]]


def test_event_feature_contract() -> None:
    event = NormalizedEvent(
        src_ip="8.8.8.8",
        dest_ip="10.0.0.2",
        protocol="TCP",
        app_proto="TLS",
        duration=2,
        packets_to_server=3,
        packets_to_client=1,
        bytes_to_server=900,
        bytes_to_client=100,
    )
    features = event_features(event)
    assert list(features) == FEATURE_COLUMNS
    assert features["bytes_per_packet"] == 250
    assert features["packets_per_second"] == 2


def test_model_runtime_verifies_hash_and_scores(tmp_path) -> None:
    model_path = tmp_path / "model.joblib"
    metadata_path = tmp_path / "metadata.json"
    joblib.dump({"pipeline": DummyPipeline()}, model_path)
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    metadata_path.write_text(
        json.dumps(
            {
                "artifact_sha256": digest,
                "feature_contract": FEATURE_COLUMNS,
                "threshold": 0.8,
                "data_origin": "synthetic-smoke-test",
            }
        ),
        encoding="utf-8",
    )
    runtime = ModelRuntime(model_path, metadata_path)
    runtime.load()
    probability = runtime.score(
        NormalizedEvent(src_ip="8.8.8.8", dest_ip="10.0.0.2", protocol="TCP")
    )
    assert probability == 0.9
    assert runtime.threshold == 0.8
    assert runtime.data_origin == "synthetic-smoke-test"


def test_model_runtime_rejects_tampered_artifact(tmp_path) -> None:
    model_path = tmp_path / "model.joblib"
    metadata_path = tmp_path / "metadata.json"
    model_path.write_bytes(b"tampered")
    metadata_path.write_text(
        json.dumps({"artifact_sha256": "0" * 64, "feature_contract": FEATURE_COLUMNS}),
        encoding="utf-8",
    )
    runtime = ModelRuntime(model_path, metadata_path)
    runtime.load()
    assert runtime.pipeline is None
    assert "hash" in runtime.metadata["reason"]
