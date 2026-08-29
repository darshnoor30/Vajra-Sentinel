from __future__ import annotations

import ipaddress
import math
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta

from app.schemas import Detection, NormalizedEvent
from app.services.model_runtime import ModelRuntime, event_features


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


class DetectionEngine:
    """Stateful, explainable behavior rules plus an optional ML scoring layer."""

    def __init__(self, model: ModelRuntime):
        self.model = model
        self.port_activity: dict[str, deque[tuple[datetime, str, int]]] = defaultdict(deque)
        self.ssh_activity: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self.beacon_activity: dict[tuple[str, str, int], deque[datetime]] = defaultdict(deque)
        self.cooldowns: dict[tuple[str, str], datetime] = {}

    def reset_state(self) -> None:
        """Clear bounded, in-memory behavior windows before a clean lab replay."""

        self.port_activity.clear()
        self.ssh_activity.clear()
        self.beacon_activity.clear()
        self.cooldowns.clear()

    @staticmethod
    def _prune(values: deque, cutoff: datetime, timestamp_index: int | None = None) -> None:
        while values:
            timestamp = values[0] if timestamp_index is None else values[0][timestamp_index]
            if timestamp >= cutoff:
                break
            values.popleft()

    def _allowed(self, rule_id: str, src_ip: str, now: datetime, seconds: int = 90) -> bool:
        key = (rule_id, src_ip)
        last = self.cooldowns.get(key)
        if last and now - last < timedelta(seconds=seconds):
            return False
        self.cooldowns[key] = now
        return True

    def analyze(self, event: NormalizedEvent) -> list[Detection]:
        detections: list[Detection] = []
        if event.alert_signature:
            detections.append(self._signature_detection(event))
        detections.extend(self._behavior_detections(event))
        ml_detection = self._ml_detection(event)
        if ml_detection:
            detections.append(ml_detection)
        return detections

    def _signature_detection(self, event: NormalizedEvent) -> Detection:
        severity_map = {
            1: ("critical", 98),
            2: ("high", 92),
            3: ("medium", 82),
            4: ("low", 70),
        }
        severity, confidence = severity_map.get(event.alert_severity or 4, ("low", 65))
        action = event.alert_action or "unknown"
        sid = event.metadata.get("signature_id", "unknown")
        return Detection(
            rule_id=f"SURICATA-{sid}",
            title=event.alert_signature or "Suricata signature match",
            severity=severity,
            confidence=confidence,
            source="signature",
            description=(
                f"Suricata matched a network signature categorized as "
                f"{event.alert_category or 'uncategorized activity'}."
            ),
            evidence={
                "signature_id": sid,
                "category": event.alert_category,
                "suricata_action": action,
                "flow_id": event.flow_id,
                "community_id": event.community_id,
                "pcap_cnt": event.metadata.get("pcap_cnt"),
            },
            mitre_techniques=[],
            recommended_action=(
                "Validate the signature and correlated flow, preserve the packet reference, then "
                "contain the source only if the activity is confirmed."
            ),
            response_eligible=severity in {"critical", "high"} and _is_public(event.src_ip),
        )

    def _behavior_detections(self, event: NormalizedEvent) -> list[Detection]:
        now = event.timestamp
        results: list[Detection] = []

        if event.dest_port is not None:
            values = self.port_activity[event.src_ip]
            values.append((now, event.dest_ip, event.dest_port))
            self._prune(values, now - timedelta(seconds=60), timestamp_index=0)
            unique_ports = len({item[2] for item in values})
            unique_hosts = len({item[1] for item in values})
            if unique_ports >= 20 and self._allowed("VG-BEH-001", event.src_ip, now):
                results.append(
                    Detection(
                        rule_id="VG-BEH-001",
                        title="Probable network service scan",
                        severity="high",
                        confidence=min(99, 70 + unique_ports),
                        source="behavior",
                        description="One source contacted an unusually broad set of destination ports in 60 seconds.",
                        evidence={
                            "window_seconds": 60,
                            "unique_destination_ports": unique_ports,
                            "unique_destination_hosts": unique_hosts,
                            "event_count": len(values),
                        },
                        mitre_techniques=["T1046"],
                        recommended_action="Confirm the scan scope, check asset ownership, and block the source temporarily if unauthorized.",
                        response_eligible=unique_ports >= 30 and _is_public(event.src_ip),
                    )
                )

        if event.dest_port == 22 or (event.app_proto or "").lower() == "ssh":
            key = (event.src_ip, event.dest_ip)
            attempts = self.ssh_activity[key]
            attempts.append(now)
            self._prune(attempts, now - timedelta(seconds=60))
            if len(attempts) >= 12 and self._allowed("VG-BEH-002", event.src_ip, now):
                results.append(
                    Detection(
                        rule_id="VG-BEH-002",
                        title="Repeated SSH connection attempts",
                        severity="high",
                        confidence=86,
                        source="behavior",
                        description="Repeated SSH connections may indicate password guessing; flow data cannot prove authentication failure.",
                        evidence={
                            "window_seconds": 60,
                            "connection_attempts": len(attempts),
                            "destination": f"{event.dest_ip}:22",
                            "limitation": "Authentication outcome is not present in network-flow telemetry.",
                        },
                        mitre_techniques=["T1110", "T1021.004"],
                        recommended_action="Correlate with SSH authentication logs before containment or account action.",
                        response_eligible=False,
                    )
                )

        if event.dns_query:
            first_label = event.dns_query.split(".", 1)[0]
            label_entropy = round(_entropy(first_label), 2)
            if (
                len(first_label) >= 45
                and label_entropy >= 3.6
                and self._allowed("VG-BEH-003", event.src_ip, now, seconds=300)
            ):
                results.append(
                    Detection(
                        rule_id="VG-BEH-003",
                        title="Possible DNS tunneling pattern",
                        severity="medium",
                        confidence=min(92, int(45 + label_entropy * 10)),
                        source="behavior",
                        description="A long, high-entropy DNS label resembles encoded data transfer but can also occur in legitimate tracking domains.",
                        evidence={
                            "query": event.dns_query,
                            "first_label_length": len(first_label),
                            "first_label_entropy": label_entropy,
                        },
                        mitre_techniques=["T1071.004"],
                        recommended_action="Review query frequency, domain reputation, and endpoint process telemetry.",
                        response_eligible=False,
                    )
                )

        if event.dest_port is not None:
            key = (event.src_ip, event.dest_ip, event.dest_port)
            observations = self.beacon_activity[key]
            observations.append(now)
            self._prune(observations, now - timedelta(minutes=30))
            if len(observations) >= 6:
                intervals = [
                    (observations[index] - observations[index - 1]).total_seconds()
                    for index in range(1, len(observations))
                ]
                mean = statistics.mean(intervals)
                coefficient = statistics.pstdev(intervals) / max(mean, 0.001)
                if (
                    5 <= mean <= 300
                    and coefficient <= 0.12
                    and self._allowed("VG-BEH-004", event.src_ip, now, seconds=600)
                ):
                    results.append(
                        Detection(
                            rule_id="VG-BEH-004",
                            title="Low-jitter periodic connection pattern",
                            severity="medium",
                            confidence=84,
                            source="behavior",
                            description="Repeated flows to one endpoint have highly regular timing consistent with automated beaconing.",
                            evidence={
                                "observations": len(observations),
                                "mean_interval_seconds": round(mean, 2),
                                "interval_cv": round(coefficient, 3),
                                "destination": f"{event.dest_ip}:{event.dest_port}",
                            },
                            mitre_techniques=["T1071"],
                            recommended_action="Correlate with endpoint process lineage and destination reputation before isolation.",
                            response_eligible=False,
                        )
                    )

        total_bytes = event.bytes_to_server + event.bytes_to_client
        outbound_ratio = event.bytes_to_server / max(event.bytes_to_client, 1)
        if (
            event.bytes_to_server >= 50_000_000
            and outbound_ratio >= 10
            and self._allowed("VG-BEH-005", event.src_ip, now, seconds=900)
        ):
            results.append(
                Detection(
                    rule_id="VG-BEH-005",
                    title="Large asymmetric outbound transfer",
                    severity="high",
                    confidence=88,
                    source="behavior",
                    description="The flow sent a large volume with little return traffic, consistent with possible exfiltration.",
                    evidence={
                        "bytes_to_server": event.bytes_to_server,
                        "bytes_to_client": event.bytes_to_client,
                        "total_bytes": total_bytes,
                        "outbound_ratio": round(outbound_ratio, 2),
                    },
                    mitre_techniques=["T1041"],
                    recommended_action="Identify the sending process and data owner; preserve flow and endpoint evidence before containment.",
                    response_eligible=False,
                )
            )
        return results

    def _ml_detection(self, event: NormalizedEvent) -> Detection | None:
        if event.event_type not in {"flow", "netflow"}:
            return None
        probability = self.model.score(event)
        if probability is None or probability < self.model.threshold:
            return None
        if not self._allowed("VG-ML-001", event.src_ip, event.timestamp, seconds=300):
            return None
        is_demo = self.model.data_origin == "synthetic-smoke-test"
        return Detection(
            rule_id="VG-ML-001",
            title="ML flow anomaly score exceeded threshold",
            severity="medium" if probability < 0.95 else "high",
            confidence=round(probability * 100),
            source="ml-demo" if is_demo else "ml",
            description=(
                "The flow's sensor-derived features resemble malicious training examples. "
                "This score is supporting evidence, not a verdict."
            ),
            evidence={
                "probability": round(probability, 4),
                "threshold": self.model.threshold,
                "data_origin": self.model.data_origin,
                "features": event_features(event),
            },
            mitre_techniques=[],
            recommended_action="Require rule, asset, or endpoint corroboration before response.",
            response_eligible=False,
        )
