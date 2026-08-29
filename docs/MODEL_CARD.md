# Model card — Vajra Flow Classifier

## Intended use

Rank network flow records for analyst review when their sensor-derived characteristics resemble labeled malicious examples. The output is corroborating evidence for an IDS; it is not an attack verdict, zero-day detector, or autonomous IPS decision.

## Model details

| Field | Value |
| --- | --- |
| Algorithm | Histogram Gradient Boosting binary classifier |
| Output | Probability of `attack` class |
| Threshold | Selected on a validation split subject to a target FPR |
| Categorical handling | Imputation + ordinal encoding with explicit unknown value |
| Numeric handling | Median imputation + standardization |
| Artifact integrity | SHA-256 recorded in separate metadata |
| Auto-response | Prohibited for ML-only findings |

## Feature contract

The ten fields are `duration`, `protocol`, `app_proto`, directional bytes, directional packets, bytes per packet, packets per second, and byte ratio. Each can be reproduced from Suricata EVE `flow` data and mapped from the official UNSW-NB15 split. Ports and dataset-only engineered counters are deliberately excluded because the official split does not provide all of them or the live sensor cannot reproduce them consistently.

## Included artifact

The checked-in artifact is trained on deterministic synthetic distributions. It exists only to prove preprocessing, thresholding, serialization, integrity verification, runtime inference, and UI governance. Its metrics are expected to be unrealistically strong and must not appear in a résumé as real-world accuracy.

Authoritative metadata: `artifacts/model_metadata.json`.

## Official experiment path

UNSW states that UNSW-NB15 contains normal activity and nine attack types, with 175,341 training and 82,332 test records. Download the official files from <https://research.unsw.edu.au/projects/unsw-nb15-dataset>, preserve the original train/test boundary, and run the documented training command.

Threshold selection uses a stratified 20% validation portion of the training file. Final metrics are computed once on the official test file. This avoids tuning on the test set.

## Required evaluation

- PR-AUC and ROC-AUC
- Precision, recall, F1, specificity, and false-positive rate at the selected threshold
- Confusion matrix with absolute counts
- Brier score for probability calibration
- Dataset and artifact SHA-256 values
- Separate local-traffic false-positive review before deployment

## Limitations and bias

- Public IDS datasets age and differ from the local environment.
- Random record splits can exaggerate generalization when near-duplicate flows exist; this project preserves the provided official split but cannot guarantee temporal or organization-level generalization.
- Class labels represent the dataset's collection design, not every modern technique.
- Flow features cannot identify user intent, authentication outcome, or endpoint process lineage.
- Dataset drift, sensor configuration, NAT, and asymmetric routing can alter distributions.
- Ordinal encoding gives categories numerical order; tree splits can exploit this. Unknown categories are handled, but one-hot or target encoding should be compared during a production study.

## Human oversight

Every ML finding recommends corroboration. The response engine enforces this by making `ml` and `ml-demo` detections ineligible for containment.

