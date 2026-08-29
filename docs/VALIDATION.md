# Validation record

Validation date: 2026-08-29 UTC

## Automated checks

| Check | Result |
| --- | --- |
| Ruff lint | Passed |
| Ruff format | Passed |
| Pytest | 38 passed |
| Application coverage | 90.40% total, branch coverage enabled |
| Artifact structure | Passed |
| Model artifact SHA-256 | Passed |
| Model/runtime feature contract | Passed |
| Bandit static security scan | Passed; no findings |
| pip-audit project dependency scan | Passed; no known vulnerabilities |

## Tested controls

- unauthorized ingestion is rejected;
- security headers and same-origin content policy are present;
- invalid severity filters fail validation;
- signature evidence creates detections and incidents;
- source activity correlates into an existing incident window;
- protected networks cannot be contained;
- ML-only findings cannot be contained;
- dry-run containment is recorded and reversible;
- response action creates an audit entry;
- tampered model artifacts are rejected;
- all four safe demo scenarios produce valid EVE-shaped metadata;
- clean demo replay replaces earlier built-in telemetry without deleting live sensor evidence;
- repeated demo calls remain deterministic and do not inflate event or incident counts;
- the runtime dependency matches the scikit-learn version recorded by the model artifact;
- EVE tailer skips malformed input and continues;
- port scan, SSH repetition, DNS pattern, beaconing, and exfiltration rules meet their documented thresholds.

## Model smoke-test record

The packaged metadata is authoritative for the exact artifact. It records 9,600 fit rows, 2,400 validation rows, and 4,000 independent synthetic test rows. The results validate code paths only and must not be used as a real-world IDS performance claim.
