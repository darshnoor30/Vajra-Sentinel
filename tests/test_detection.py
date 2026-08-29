from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.schemas import NormalizedEvent
from app.services.detection import DetectionEngine
from app.services.model_runtime import ModelRuntime


def engine(tmp_path: Path) -> DetectionEngine:
    return DetectionEngine(ModelRuntime(tmp_path / "missing.joblib", tmp_path / "missing.json"))


def base_event(timestamp: datetime, **overrides) -> NormalizedEvent:
    values = {
        "timestamp": timestamp,
        "src_ip": "45.155.205.233",
        "dest_ip": "10.0.0.10",
        "src_port": 50000,
        "dest_port": 443,
        "protocol": "TCP",
        "event_type": "flow",
        "packets_to_server": 5,
        "packets_to_client": 4,
        "bytes_to_server": 500,
        "bytes_to_client": 400,
        "duration": 1,
    }
    values.update(overrides)
    return NormalizedEvent(**values)


def test_signature_evidence_is_response_eligible(tmp_path: Path) -> None:
    finding = engine(tmp_path).analyze(
        base_event(
            datetime.now(UTC),
            event_type="alert",
            alert_signature="Critical exploit",
            alert_category="Exploit",
            alert_severity=1,
            alert_action="allowed",
            metadata={"signature_id": 77, "pcap_cnt": 12},
        )
    )[0]
    assert finding.severity == "critical"
    assert finding.response_eligible is True
    assert finding.evidence["pcap_cnt"] == 12


def test_port_scan_requires_twenty_distinct_ports(tmp_path: Path) -> None:
    detector = engine(tmp_path)
    now = datetime.now(UTC)
    findings = []
    for index in range(20):
        findings.extend(
            detector.analyze(
                base_event(now + timedelta(milliseconds=index), dest_port=1000 + index)
            )
        )
    assert [item.rule_id for item in findings] == ["VG-BEH-001"]
    assert findings[0].evidence["unique_destination_ports"] == 20


def test_reset_state_clears_behavior_windows_and_cooldowns(tmp_path: Path) -> None:
    detector = engine(tmp_path)
    now = datetime.now(UTC)
    for index in range(19):
        detector.analyze(base_event(now + timedelta(milliseconds=index), dest_port=1000 + index))

    detector.reset_state()
    findings = detector.analyze(base_event(now + timedelta(seconds=1), dest_port=1019))

    assert not any(item.rule_id == "VG-BEH-001" for item in findings)
    assert len(detector.port_activity["45.155.205.233"]) == 1


def test_ssh_rule_states_telemetry_limitation(tmp_path: Path) -> None:
    detector = engine(tmp_path)
    now = datetime.now(UTC)
    findings = []
    for index in range(12):
        findings.extend(
            detector.analyze(
                base_event(now + timedelta(seconds=index), dest_port=22, app_proto="ssh")
            )
        )
    ssh = next(item for item in findings if item.rule_id == "VG-BEH-002")
    assert "cannot prove" in ssh.description
    assert ssh.response_eligible is False


def test_dns_tunnel_and_exfil_rules(tmp_path: Path) -> None:
    detector = engine(tmp_path)
    now = datetime.now(UTC)
    dns = detector.analyze(
        base_event(
            now,
            event_type="dns",
            protocol="UDP",
            dest_port=53,
            dns_query="a8d9f0c7b6e5a4d3c2f1e0b9a8d7c6e5f4a3b2c1d0e9f8.lab.example",
        )
    )
    exfil = detector.analyze(
        base_event(now + timedelta(minutes=1), bytes_to_server=60_000_000, bytes_to_client=1000)
    )
    assert any(item.rule_id == "VG-BEH-003" for item in dns)
    assert any(item.rule_id == "VG-BEH-005" for item in exfil)


def test_regular_beacon_is_detected(tmp_path: Path) -> None:
    detector = engine(tmp_path)
    now = datetime.now(UTC)
    findings = []
    for index in range(6):
        findings.extend(
            detector.analyze(
                base_event(
                    now + timedelta(seconds=30 * index), dest_ip="91.215.85.18", dest_port=8443
                )
            )
        )
    assert any(item.rule_id == "VG-BEH-004" for item in findings)
