# Recruiter brief

## One-line résumé entry

**Vajra Sentinel — Hybrid Network IDS/IPS:** Built a Suricata EVE pipeline with explainable signature/behavior detection, MITRE-mapped incident correlation, a hash-verified sensor-compatible ML classifier, and safety-gated TTL nftables containment; validated with 38 tests and 90%+ application coverage.

## Three interview stories

### 1. Production feature parity

I rejected dataset features that the live Suricata adapter could not reproduce. The model uses the intersection between official UNSW-NB15 flow fields and live EVE fields. This prevents training-serving skew.

### 2. Truthful evidence

Repeated TCP connections to port 22 are labeled “repeated SSH connection attempts,” not “brute-force login failures,” because network telemetry does not contain the authentication result. The evidence drawer records that limitation and tells the analyst to correlate host logs.

### 3. Safer automation

The response layer is dry-run by default. Active mode requires an exact acknowledgement, Linux firewall capability, protected-network checks, a response-eligible detection, a short TTL, and an audit entry. ML-only alerts can never trigger it.

## Skills demonstrated

- Python, FastAPI, Pydantic, SQLite, HTML/CSS/JavaScript
- Suricata EVE JSON and custom rules
- Stateful network behavior analytics
- ML preprocessing, threshold selection, independent evaluation, artifact integrity
- MITRE ATT&CK mapping and SOC incident workflow
- Secure API design, threat modeling, Linux nftables, Docker hardening
- Unit/integration testing, coverage, CI, SAST, dependency auditing, documentation

## Defensible claims

Use the exact test/coverage result in `docs/VALIDATION.md`. Describe the bundled model as a smoke-test model. Only cite official-dataset metrics after you personally train the official files and preserve the generated metadata.
