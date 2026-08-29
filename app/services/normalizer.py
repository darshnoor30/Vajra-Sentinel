from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas import NormalizedEvent


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        cleaned = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(cleaned)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def normalize_eve(raw: dict[str, Any], sensor_id: str = "suricata") -> NormalizedEvent:
    """Normalize selected Suricata EVE fields without retaining packet payloads."""

    if not raw.get("src_ip") or not raw.get("dest_ip"):
        raise ValueError("EVE record must contain src_ip and dest_ip")

    flow = raw.get("flow") if isinstance(raw.get("flow"), dict) else {}
    alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
    dns = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
    http = raw.get("http") if isinstance(raw.get("http"), dict) else {}
    tls = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}

    duration = flow.get("age", 0.0)
    if not duration and flow.get("start") and flow.get("end"):
        duration = max((_timestamp(flow["end"]) - _timestamp(flow["start"])).total_seconds(), 0)

    metadata: dict[str, Any] = {}
    if raw.get("pcap_cnt") is not None:
        metadata["pcap_cnt"] = raw["pcap_cnt"]
    if raw.get("pcap_filename"):
        metadata["pcap_filename"] = str(raw["pcap_filename"])
    if alert.get("signature_id") is not None:
        metadata["signature_id"] = alert["signature_id"]
    if raw.get("direction"):
        metadata["direction"] = raw["direction"]

    dns_query = dns.get("rrname") or dns.get("query")
    if not dns_query and isinstance(dns.get("queries"), list) and dns["queries"]:
        first = dns["queries"][0]
        if isinstance(first, dict):
            dns_query = first.get("rrname")

    return NormalizedEvent(
        timestamp=_timestamp(raw.get("timestamp")),
        sensor_id=sensor_id,
        event_type=str(raw.get("event_type", "flow")),
        src_ip=str(raw["src_ip"]),
        dest_ip=str(raw["dest_ip"]),
        src_port=raw.get("src_port"),
        dest_port=raw.get("dest_port"),
        protocol=str(raw.get("proto", "UNKNOWN")).upper(),
        app_proto=raw.get("app_proto"),
        flow_id=str(raw["flow_id"]) if raw.get("flow_id") is not None else None,
        community_id=raw.get("community_id"),
        bytes_to_server=int(flow.get("bytes_toserver", 0) or 0),
        bytes_to_client=int(flow.get("bytes_toclient", 0) or 0),
        packets_to_server=int(flow.get("pkts_toserver", 0) or 0),
        packets_to_client=int(flow.get("pkts_toclient", 0) or 0),
        duration=float(duration or 0),
        alert_signature=alert.get("signature"),
        alert_category=alert.get("category"),
        alert_severity=alert.get("severity"),
        alert_action=alert.get("action"),
        dns_query=dns_query,
        http_method=http.get("http_method"),
        http_host=http.get("hostname"),
        http_url=http.get("url"),
        tls_sni=tls.get("sni"),
        metadata=metadata,
    )
