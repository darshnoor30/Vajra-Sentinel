from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any


def _flow(
    timestamp: datetime,
    src_ip: str,
    dest_ip: str,
    dest_port: int,
    *,
    app_proto: str | None = None,
    bytes_to_server: int = 420,
    bytes_to_client: int = 180,
    packets_to_server: int = 6,
    packets_to_client: int = 4,
    duration: float = 1.2,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": timestamp.isoformat(),
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": 49152,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": "TCP",
        "flow_id": f"demo-{int(timestamp.timestamp() * 1000)}-{dest_port}",
        "flow": {
            "pkts_toserver": packets_to_server,
            "pkts_toclient": packets_to_client,
            "bytes_toserver": bytes_to_server,
            "bytes_toclient": bytes_to_client,
            "age": duration,
            "state": "closed",
        },
    }
    if app_proto:
        event["app_proto"] = app_proto
    return event


def scenario_events(name: str = "multi-stage") -> list[dict[str, Any]]:
    if name not in {"multi-stage", "scan", "beacon", "exfiltration"}:
        raise KeyError(name)
    now = datetime.now(UTC).replace(microsecond=0)
    events: list[dict[str, Any]] = []

    if name in {"multi-stage", "scan"}:
        attacker = "45.155.205.233"
        for index, port in enumerate(range(20, 44)):
            events.append(
                _flow(now + timedelta(milliseconds=index * 150), attacker, "10.20.0.15", port)
            )
        events.append(
            {
                "timestamp": (now + timedelta(seconds=5)).isoformat(),
                "event_type": "alert",
                "src_ip": attacker,
                "src_port": 51515,
                "dest_ip": "10.20.0.15",
                "dest_port": 445,
                "proto": "TCP",
                "flow_id": "demo-signature-900001",
                "community_id": "1:demoCommunityFlow",
                "pcap_cnt": 1842,
                "alert": {
                    "action": "allowed",
                    "signature_id": 900001,
                    "signature": "VAJRA LAB SMB exploit-pattern simulation",
                    "category": "Attempted Administrator Privilege Gain",
                    "severity": 1,
                },
            }
        )

    if name in {"multi-stage", "beacon"}:
        for index in range(6):
            events.append(
                _flow(
                    now + timedelta(seconds=index * 30),
                    "10.20.0.47",
                    "91.215.85.18",
                    8443,
                    app_proto="tls",
                    bytes_to_server=210,
                    bytes_to_client=95,
                    packets_to_server=3,
                    packets_to_client=2,
                    duration=0.4,
                )
            )

    if name == "multi-stage":
        encoded = base64.b32encode(b"confidential-lab-marker-2026-repeated").decode().lower()
        events.append(
            {
                "timestamp": (now + timedelta(seconds=11)).isoformat(),
                "event_type": "dns",
                "src_ip": "10.20.0.47",
                "src_port": 53001,
                "dest_ip": "10.20.0.2",
                "dest_port": 53,
                "proto": "UDP",
                "app_proto": "dns",
                "dns": {"type": "query", "rrname": f"{encoded}.lab.example"},
            }
        )

    if name in {"multi-stage", "exfiltration"}:
        events.append(
            _flow(
                now + timedelta(seconds=180),
                "10.20.0.47",
                "185.199.108.153",
                443,
                app_proto="tls",
                bytes_to_server=64_000_000,
                bytes_to_client=900_000,
                packets_to_server=48_000,
                packets_to_client=2_400,
                duration=95,
            )
        )
    return events
