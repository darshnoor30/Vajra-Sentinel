from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.services.model_runtime import FEATURE_COLUMNS


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    required = [
        "README.md",
        "CHECKSUMS.sha256",
        "SECURITY.md",
        "Dockerfile",
        "compose.yaml",
        "app/main.py",
        "app/web/index.html",
        "suricata/local.rules",
        "docs/MODEL_CARD.md",
        "docs/THREAT_MODEL.md",
        "docs/openapi.json",
        "artifacts/sbom.cdx.json",
    ]
    missing = [path for path in required if not (root / path).is_file()]
    if missing:
        raise SystemExit(f"Missing required project artifacts: {missing}")

    model_path = root / "artifacts/model.joblib"
    metadata_path = root / "artifacts/model_metadata.json"
    if model_path.exists() or metadata_path.exists():
        if not model_path.exists() or not metadata_path.exists():
            raise SystemExit("Model and metadata must be present together")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        actual = hashlib.sha256(model_path.read_bytes()).hexdigest()
        if actual != metadata.get("artifact_sha256"):
            raise SystemExit("Model artifact hash verification failed")
        if metadata.get("feature_contract") != FEATURE_COLUMNS:
            raise SystemExit("Model feature contract does not match the runtime")
    openapi = json.loads((root / "docs/openapi.json").read_text(encoding="utf-8"))
    if openapi.get("info", {}).get("version") != "1.0.1":
        raise SystemExit("OpenAPI contract version is not 1.0.1")
    sbom = json.loads((root / "artifacts/sbom.cdx.json").read_text(encoding="utf-8"))
    if sbom.get("bomFormat") != "CycloneDX":
        raise SystemExit("CycloneDX SBOM is invalid")
    print("Artifact validation passed: required files and model integrity are correct.")


if __name__ == "__main__":
    main()
