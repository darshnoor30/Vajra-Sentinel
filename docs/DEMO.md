# 90-second recruiter demonstration

## Preparation

Run the app in demo/dry-run mode and open the dashboard. Do not call the synthetic model a trained production detector.

## Script

**0–15 seconds — Problem**

“Vajra Sentinel is an evidence-first network IDS/IPS. The problem I focused on is not just raising alerts—it is helping an analyst understand why a signal fired and respond without creating a bigger outage.”

**15–35 seconds — Detection**

Click **Replay clean simulation**, then open the scan/signature detection. Each replay replaces the previous built-in lab run, so the queue remains deterministic even if the button is clicked again.

“Suricata signature context is preserved, including the SID, flow correlation IDs, action, and packet reference. Stateful rules also find a port scan, periodic beacon, DNS encoding pattern, and asymmetric transfer. Every rule exposes its threshold and limitations.”

**35–55 seconds — Investigation**

Show the incident queue and evidence drawer.

“Related source activity becomes one incident instead of alert spam. Notice the SSH finding says repeated connections, not failed logins, because network flow data cannot prove authentication outcome.”

**55–72 seconds — ML integrity**

Scroll to Model Governance.

“The included model is clearly labeled synthetic and exists only to validate the pipeline. The production path uses the official UNSW split, selects a threshold on validation data, evaluates once on the independent test set, and hash-verifies the artifact. ML alone can never block.”

**72–90 seconds — Response engineering**

Open a response-eligible signature and simulate containment.

“Response defaults to dry-run. Active nftables blocking requires Linux privilege, an exact safety acknowledgement, an eligible finding, and a source outside protected networks. Every block has a TTL, rollback path, and audit record.”

## Questions to invite

- “Would you like to inspect the feature contract or a behavior-rule test?”
- “Should I explain how I would migrate the single-node design to Kafka/PostgreSQL?”
- “Would you like to see the threat model and false-positive controls?”
