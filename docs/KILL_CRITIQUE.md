# Kill critique

## Verdict

This is a strong top-tier student / internship portfolio project because it demonstrates an end-to-end defensive workflow and explicitly controls the places where IDS demos usually become misleading. It is not an enterprise-ready commercial IPS, and saying otherwise would weaken the application.

## Scorecard

| Area | Score | Why |
| --- | ---: | --- |
| Security problem framing | 10/10 | Optimizes for evidence and analyst decision quality, not alert volume |
| Architecture | 9/10 | Coherent data path, small trust boundaries, graceful rules-only fallback |
| Detection engineering | 9/10 | Explainable stateful rules and honest telemetry limitations; thresholds still need local baselining |
| ML rigor | 9.5/10 | Production feature parity, separate validation/test, useful metrics, integrity check; official data not redistributed |
| Response safety | 9.5/10 | Dry-run, allowlists, TTL, rollback, audit, no shell; single-host privilege boundary can be improved |
| UX / recruiter clarity | 9.5/10 | Real API-driven dashboard, evidence drill-down, clear demo labeling |
| Testing / delivery | 9/10 | 90%+ coverage, CI, Docker, SAST/audit, runbooks; browser E2E and load tests remain |
| Production scalability | 7/10 | SQLite and in-process windows are intentional demo constraints |

## What would get the project rejected

- Claiming the synthetic model's ~99.8% scores as real IDS accuracy.
- Calling SSH connections confirmed password failures.
- Enabling autonomous blocking based on ML probability.
- Presenting the demo events as captured attacks.
- Claiming Suricata is running when only the built-in scenario is active.
- Saying “enterprise production-ready” without HA, RBAC/SSO, TLS, durable streaming, and operational baselines.

The project prevents or documents every one of these mistakes.

## Real limitations

1. Behavior windows live in process memory and reset at restart.
2. SQLite is single-node and not designed for enterprise telemetry volume.
3. Read-only API routes rely on network/reverse-proxy restriction rather than app-level RBAC.
4. API-key attribution is a fingerprint, not a named SSO identity.
5. The included model proves plumbing only; official and local evaluation still need to be run.
6. No packet payloads or endpoint process data means some conclusions require external correlation.
7. Active response shares the application host; production should use a separate least-privilege response agent.
8. Custom Suricata rules require validation against the installed Suricata version and local baseline.
9. There is no multi-sensor clock-skew handling or durable message queue.
10. Browser E2E, soak, and high-volume load tests are not included yet.

## Highest-value next upgrades

1. Train the official UNSW-NB15 split and add temporal/local benign validation.
2. Add OIDC/RBAC with analyst, responder, and admin roles.
3. Move telemetry to Kafka/Redpanda and PostgreSQL/ClickHouse or OpenSearch.
4. Separate response into an mTLS-authenticated, least-privilege agent.
5. Add Playwright E2E tests, a 24-hour soak test, and measured ingestion throughput.
6. Export incidents through STIX/TAXII or a documented webhook/SIEM connector.

## Honest final rating

**9.3/10 as a recruiter-facing student security engineering project.** The remaining 0.7 is production operations and real-environment validation, not more visual polish or a more complicated model.
