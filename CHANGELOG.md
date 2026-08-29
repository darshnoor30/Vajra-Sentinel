# Changelog

## 1.0.1 — 2026-08-29

### Fixed

- Pin `scikit-learn==1.8.0` so the packaged joblib artifact is served by the same library version used during training.
- Replace prior built-in lab telemetry before every replay, preventing duplicate events, detections, incidents, and posture-score inflation.
- Preserve non-demo sensor/API evidence when the lab scenario is replayed.
- Reset bounded behavioral windows before a clean replay so rule outcomes remain deterministic.
- Show an explicit temporary replay state and an unambiguous completion message in the dashboard.

### Validated

- 38 automated tests pass with 90.40% application coverage.
- Ruff formatting and lint checks pass.
- Model artifact hash, feature contract, OpenAPI version, and package structure pass validation.

### Security automation

- Add an official OpenSSF Scorecard workflow with authenticated result publication and SARIF upload to GitHub code scanning.
- Pin every GitHub Actions dependency to an immutable commit SHA and disable persisted checkout credentials.

## 1.0.0 — 2026-08-28

- Initial evidence-first hybrid IDS/IPS portfolio release.
