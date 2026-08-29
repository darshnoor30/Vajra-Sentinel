from __future__ import annotations

from app.services.normalizer import normalize_eve


def test_normalizes_suricata_alert_and_flow_fields() -> None:
    event = normalize_eve(
        {
            "timestamp": "2026-08-28T12:30:00Z",
            "event_type": "alert",
            "src_ip": "8.8.8.8",
            "dest_ip": "10.0.0.2",
            "src_port": 443,
            "dest_port": 51000,
            "proto": "TCP",
            "flow_id": 123,
            "pcap_cnt": 44,
            "flow": {
                "pkts_toserver": 10,
                "pkts_toclient": 8,
                "bytes_toserver": 1200,
                "bytes_toclient": 900,
                "age": 3,
            },
            "alert": {
                "signature_id": 9001,
                "signature": "Test signature",
                "category": "Test category",
                "severity": 1,
                "action": "allowed",
            },
        },
        "sensor-a",
    )
    assert event.sensor_id == "sensor-a"
    assert event.alert_signature == "Test signature"
    assert event.metadata == {"pcap_cnt": 44, "signature_id": 9001}
    assert event.bytes_to_server == 1200
    assert event.flow_id == "123"


def test_extracts_dns_query_from_queries_array() -> None:
    event = normalize_eve(
        {
            "event_type": "dns",
            "src_ip": "10.0.0.2",
            "dest_ip": "1.1.1.1",
            "proto": "UDP",
            "dns": {"queries": [{"rrname": "example.org"}]},
        }
    )
    assert event.dns_query == "example.org"
