from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder, StandardScaler

from app.services.model_runtime import FEATURE_COLUMNS

CATEGORICAL = ["protocol", "app_proto"]
NUMERIC = [column for column in FEATURE_COLUMNS if column not in CATEGORICAL]
REQUIRED_UNSW = {"dur", "proto", "service", "spkts", "dpkts", "sbytes", "dbytes", "label"}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sensor_contract_frame(raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    missing = REQUIRED_UNSW - set(raw.columns)
    if missing:
        raise ValueError(f"Dataset is missing required UNSW-NB15 columns: {sorted(missing)}")
    frame = pd.DataFrame(
        {
            "duration": pd.to_numeric(raw["dur"], errors="coerce"),
            "protocol": raw["proto"].fillna("unknown").astype(str).str.lower(),
            "app_proto": raw["service"]
            .replace("-", "unknown")
            .fillna("unknown")
            .astype(str)
            .str.lower(),
            "bytes_to_server": pd.to_numeric(raw["sbytes"], errors="coerce"),
            "bytes_to_client": pd.to_numeric(raw["dbytes"], errors="coerce"),
            "packets_to_server": pd.to_numeric(raw["spkts"], errors="coerce"),
            "packets_to_client": pd.to_numeric(raw["dpkts"], errors="coerce"),
        }
    )
    packet_total = frame["packets_to_server"] + frame["packets_to_client"]
    byte_total = frame["bytes_to_server"] + frame["bytes_to_client"]
    frame["bytes_per_packet"] = byte_total / packet_total.clip(lower=1)
    frame["packets_per_second"] = packet_total / frame["duration"].clip(lower=0.001)
    frame["byte_ratio"] = (frame["bytes_to_server"] + 1) / (frame["bytes_to_client"] + 1)
    frame = frame.replace([np.inf, -np.inf], np.nan)
    labels = pd.to_numeric(raw["label"], errors="raise").astype(int)
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError("label must be binary: 0=benign, 1=attack")
    return frame[FEATURE_COLUMNS], labels


def build_pipeline(random_state: int) -> Pipeline:
    numeric = Pipeline(
        steps=[("imputer", SimpleImputer(strategy="median")), ("scale", StandardScaler())]
    )
    categorical = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            (
                "encode",
                OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1),
            ),
        ]
    )
    preprocessing = ColumnTransformer(
        [("numeric", numeric, NUMERIC), ("categorical", categorical, CATEGORICAL)],
        verbose_feature_names_out=False,
    )
    classifier = HistGradientBoostingClassifier(
        learning_rate=0.08,
        max_iter=220,
        max_leaf_nodes=31,
        min_samples_leaf=30,
        l2_regularization=0.2,
        class_weight="balanced",
        early_stopping=True,
        random_state=random_state,
    )
    return Pipeline([("preprocess", preprocessing), ("classifier", classifier)])


def choose_threshold(y_true: pd.Series, probability: np.ndarray, target_fpr: float) -> float:
    best: tuple[float, float] | None = None
    for threshold in np.linspace(0.99, 0.30, 140):
        predicted = (probability >= threshold).astype(int)
        tn, fp, _, _ = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
        fpr = fp / max(tn + fp, 1)
        recall = recall_score(y_true, predicted, zero_division=0)
        if fpr <= target_fpr and (best is None or recall > best[1]):
            best = (float(threshold), float(recall))
    return best[0] if best else 0.9


def metrics(y_true: pd.Series, probability: np.ndarray, threshold: float) -> dict[str, Any]:
    predicted = (probability >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "roc_auc": round(float(roc_auc_score(y_true, probability)), 6),
        "pr_auc": round(float(average_precision_score(y_true, probability)), 6),
        "precision": round(float(precision_score(y_true, predicted, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, predicted, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, predicted, zero_division=0)), 6),
        "false_positive_rate": round(float(fp / max(tn + fp, 1)), 6),
        "specificity": round(float(tn / max(tn + fp, 1)), 6),
        "brier_score": round(float(brier_score_loss(y_true, probability)), 6),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Vajra Sentinel binary flow classifier")
    parser.add_argument("--train-csv", type=Path, required=True)
    parser.add_argument("--test-csv", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/model.joblib"))
    parser.add_argument("--metadata", type=Path, default=Path("artifacts/model_metadata.json"))
    parser.add_argument(
        "--data-origin",
        required=True,
        choices=["synthetic-smoke-test", "UNSW-NB15-official"],
    )
    parser.add_argument("--target-fpr", type=float, default=0.03)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    if not 0 < args.target_fpr < 0.5:
        parser.error("--target-fpr must be between 0 and 0.5")

    train_raw = pd.read_csv(args.train_csv, low_memory=False)
    test_raw = pd.read_csv(args.test_csv, low_memory=False)
    x_all, y_all = sensor_contract_frame(train_raw)
    x_test, y_test = sensor_contract_frame(test_raw)
    x_train, x_validation, y_train, y_validation = train_test_split(
        x_all,
        y_all,
        test_size=0.2,
        random_state=args.random_state,
        stratify=y_all,
    )
    pipeline = build_pipeline(args.random_state)
    pipeline.fit(x_train, y_train)
    validation_probability = pipeline.predict_proba(x_validation)[:, 1]
    threshold = choose_threshold(y_validation, validation_probability, args.target_fpr)
    test_probability = pipeline.predict_proba(x_test)[:, 1]
    evaluation = metrics(y_test, test_probability, threshold)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    artifact = {"pipeline": pipeline, "threshold": threshold, "feature_contract": FEATURE_COLUMNS}
    joblib.dump(artifact, args.output, compress=3)
    artifact_hash = file_sha256(args.output)
    metadata = {
        "schema_version": 1,
        "model_name": "Vajra Flow Classifier",
        "model_type": "HistGradientBoostingClassifier",
        "status": "ready",
        "trained_at": datetime.now(UTC).isoformat(),
        "data_origin": args.data_origin,
        "dataset_hashes": {
            "train_sha256": file_sha256(args.train_csv),
            "test_sha256": file_sha256(args.test_csv),
        },
        "rows": {
            "fit": len(x_train),
            "validation": len(x_validation),
            "independent_test": len(x_test),
        },
        "feature_contract": FEATURE_COLUMNS,
        "threshold": round(threshold, 6),
        "target_validation_fpr": args.target_fpr,
        "metrics": evaluation,
        "artifact_sha256": artifact_hash,
        "runtime": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "safety": {
            "ml_only_auto_block": False,
            "claim": (
                "Pipeline validation only; not a real-world performance claim."
                if args.data_origin == "synthetic-smoke-test"
                else "Evaluation on the official held-out split; local validation is still required."
            ),
        },
    }
    args.metadata.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
