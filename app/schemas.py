from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=utc_now)
    sensor_id: str = Field(default="sensor-unknown", max_length=80)
    event_type: str = Field(default="flow", max_length=40)
    src_ip: str
    dest_ip: str
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = Field(default="UNKNOWN", max_length=16)
    app_proto: str | None = Field(default=None, max_length=40)
    flow_id: str | None = Field(default=None, max_length=128)
    community_id: str | None = Field(default=None, max_length=160)
    bytes_to_server: int = Field(default=0, ge=0)
    bytes_to_client: int = Field(default=0, ge=0)
    packets_to_server: int = Field(default=0, ge=0)
    packets_to_client: int = Field(default=0, ge=0)
    duration: float = Field(default=0.0, ge=0)
    alert_signature: str | None = Field(default=None, max_length=500)
    alert_category: str | None = Field(default=None, max_length=240)
    alert_severity: int | None = Field(default=None, ge=1, le=255)
    alert_action: str | None = Field(default=None, max_length=40)
    dns_query: str | None = Field(default=None, max_length=1024)
    http_method: str | None = Field(default=None, max_length=24)
    http_host: str | None = Field(default=None, max_length=255)
    http_url: str | None = Field(default=None, max_length=2048)
    tls_sni: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("src_ip", "dest_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        import ipaddress

        return str(ipaddress.ip_address(value))


class Detection(BaseModel):
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: int = Field(ge=0, le=100)
    source: Literal["signature", "behavior", "ml", "ml-demo", "correlation"]
    description: str
    evidence: dict[str, Any]
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_action: str
    response_eligible: bool = False


class IngestRequest(BaseModel):
    sensor_id: str = Field(default="api-sensor", max_length=80)
    event: dict[str, Any]


class IngestResponse(BaseModel):
    event_id: int
    detection_ids: list[int]
    incident_ids: list[int]


class ContainRequest(BaseModel):
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)
    reason: str | None = Field(default=None, max_length=300)


class IncidentUpdate(BaseModel):
    status: Literal["new", "triaged", "contained", "closed"]
    note: str = Field(default="", max_length=1000)
