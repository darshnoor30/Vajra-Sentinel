# Threat model

## Assets

- Network evidence and incident records
- API mutation credential
- Model artifact and governance metadata
- Response host firewall policy
- Analyst decision history

## Adversaries

- External attacker generating network traffic
- Malicious or compromised sensor sending crafted EVE records
- Unauthorized local/API user attempting containment
- Supply-chain attacker modifying a model or dependency
- Well-intentioned analyst making an unsafe response decision

## STRIDE analysis

| Threat | Example | Existing control | Residual risk / next control |
| --- | --- | --- | --- |
| Spoofing | Forged mutation request | Constant-time API-key check; mutation endpoints protected | Add SSO/OIDC and per-user identity in production |
| Tampering | Modified model artifact | SHA-256 and exact feature-contract verification | Sign metadata with Sigstore/KMS |
| Repudiation | Analyst denies a block | Append-only audit records with actor fingerprint and reason | Send audit stream to immutable external storage |
| Information disclosure | Payload or secret retained from EVE | Packet/payload/body/auth/cookie fields are stripped and large strings bounded | Add organization-specific field classification and DLP controls |
| Denial of service | Event flood or huge JSON line | 2 MB line cap, HTTP rate limit, pagination, SQLite timeout | Add queue/backpressure and per-sensor quotas |
| Elevation of privilege | App uses root for normal work | Container drops all caps; active response is separate and gated | Split response agent into least-privilege service |

## Abuse cases tested

- Active mode rejected without an exact acknowledgement.
- Private/protected sources rejected from containment.
- ML-only detections rejected from containment.
- Invalid IP addresses rejected by typed normalization.
- Unauthorized ingestion and case changes return 401.
- Artifact hash mismatch forces rules-only mode.
- nftables command is an argument array, never a shell string.

## Out of scope

- Endpoint isolation and identity-provider account suspension
- Full packet-content storage or malware sandboxing
- Multi-tenant authorization
- High-availability clustering
- Detection of encrypted payload content
