from __future__ import annotations

import numpy as np
import pytest

from ml.generate_demo_dataset import generate
from ml.train import build_pipeline, choose_threshold, metrics, sensor_contract_frame


def test_training_pipeline_fits_sensor_contract() -> None:
    raw = generate(1200, 1234)
    features, labels = sensor_contract_frame(raw)
    pipeline = build_pipeline(42)
    pipeline.fit(features[:900], labels[:900])
    probability = pipeline.predict_proba(features[900:])[:, 1]
    threshold = choose_threshold(labels[900:], probability, target_fpr=0.05)
    result = metrics(labels[900:], probability, threshold)
    assert 0.3 <= threshold <= 0.99
    assert 0 <= result["false_positive_rate"] <= 1
    assert sum(result["confusion_matrix"].values()) == 300
    assert np.isfinite(probability).all()


def test_training_rejects_incompatible_dataset() -> None:
    with pytest.raises(ValueError, match="missing"):
        sensor_contract_frame(generate(1000, 7).drop(columns=["dbytes"]))
