from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

from app.schemas import NormalizedEvent

FEATURE_COLUMNS = [
    "duration",
    "protocol",
    "app_proto",
    "bytes_to_server",
    "bytes_to_client",
    "packets_to_server",
    "packets_to_client",
    "bytes_per_packet",
    "packets_per_second",
    "byte_ratio",
]


def event_features(event: NormalizedEvent) -> dict[str, Any]:
    packets = event.packets_to_server + event.packets_to_client
    total_bytes = event.bytes_to_server + event.bytes_to_client
    return {
        "duration": event.duration,
        "protocol": event.protocol.lower(),
        "app_proto": (event.app_proto or "unknown").lower(),
        "bytes_to_server": event.bytes_to_server,
        "bytes_to_client": event.bytes_to_client,
        "packets_to_server": event.packets_to_server,
        "packets_to_client": event.packets_to_client,
        "bytes_per_packet": total_bytes / max(packets, 1),
        "packets_per_second": packets / max(event.duration, 0.001),
        "byte_ratio": (event.bytes_to_server + 1) / (event.bytes_to_client + 1),
    }


class ModelRuntime:
    """Hash-verified local model loader with a strict sensor feature contract."""

    def __init__(self, model_path: Path, metadata_path: Path):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.pipeline: Any | None = None
        self.metadata: dict[str, Any] = {
            "status": "unavailable",
            "reason": "No model artifact has been trained",
            "feature_contract": FEATURE_COLUMNS,
        }

    def load(self) -> None:
        if not self.model_path.exists() or not self.metadata_path.exists():
            return
        try:
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            expected = metadata.get("artifact_sha256")
            actual = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
            if not expected or not _constant_time_equal(expected, actual):
                raise ValueError("Model artifact hash does not match metadata")
            if metadata.get("feature_contract") != FEATURE_COLUMNS:
                raise ValueError("Model feature contract is incompatible with this sensor")
            import joblib

            artifact = joblib.load(self.model_path)  # noqa: S301 - local hash-verified artifact
            self.pipeline = artifact["pipeline"]
            metadata["status"] = "ready"
            self.metadata = metadata
        except Exception as exc:  # keep the detection service available when ML is not
            self.pipeline = None
            self.metadata = {
                "status": "unavailable",
                "reason": str(exc),
                "feature_contract": FEATURE_COLUMNS,
            }

    def score(self, event: NormalizedEvent) -> float | None:
        if self.pipeline is None:
            return None
        import pandas as pd

        frame = pd.DataFrame([event_features(event)], columns=FEATURE_COLUMNS)
        probability = float(self.pipeline.predict_proba(frame)[0][1])
        return probability if math.isfinite(probability) else None

    @property
    def threshold(self) -> float:
        return float(self.metadata.get("threshold", 0.8))

    @property
    def data_origin(self) -> str:
        return str(self.metadata.get("data_origin", "unknown"))


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode(), right.encode())
