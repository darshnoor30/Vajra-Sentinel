from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str = field(default_factory=lambda: os.getenv("VAJRA_ENV", "development"))
    host: str = field(default_factory=lambda: os.getenv("VAJRA_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("VAJRA_PORT", "8765")))
    api_key: str = field(
        default_factory=lambda: os.getenv("VAJRA_API_KEY", "local-demo-key-change-me")
    )
    database_path: Path = field(
        default_factory=lambda: Path(os.getenv("VAJRA_DATABASE_PATH", "runtime/vajra.db"))
    )
    eve_path: Path = field(
        default_factory=lambda: Path(os.getenv("VAJRA_EVE_PATH", "runtime/eve.json"))
    )
    model_path: Path = field(
        default_factory=lambda: Path(os.getenv("VAJRA_MODEL_PATH", "artifacts/model.joblib"))
    )
    model_metadata_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("VAJRA_MODEL_METADATA_PATH", "artifacts/model_metadata.json")
        )
    )
    demo_mode: bool = field(default_factory=lambda: _as_bool(os.getenv("VAJRA_DEMO_MODE"), True))
    ips_mode: str = field(default_factory=lambda: os.getenv("VAJRA_IPS_MODE", "dry-run"))
    active_response_ack: str = field(
        default_factory=lambda: os.getenv("VAJRA_ACTIVE_RESPONSE_ACK", "")
    )
    block_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("VAJRA_BLOCK_TTL_SECONDS", "900"))
    )
    protected_networks: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            item.strip()
            for item in os.getenv(
                "VAJRA_PROTECTED_NETWORKS",
                "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7",
            ).split(",")
            if item.strip()
        )
    )
    trusted_proxies: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            item.strip()
            for item in os.getenv("VAJRA_TRUSTED_PROXIES", "127.0.0.1").split(",")
            if item.strip()
        )
    )

    def validate(self) -> None:
        if self.ips_mode not in {"dry-run", "active"}:
            raise ValueError("VAJRA_IPS_MODE must be 'dry-run' or 'active'")
        if self.ips_mode == "active" and self.active_response_ack != "I_UNDERSTAND_ACTIVE_BLOCKING":
            raise ValueError(
                "Active IPS requires VAJRA_ACTIVE_RESPONSE_ACK=I_UNDERSTAND_ACTIVE_BLOCKING"
            )
        if not 1 <= self.port <= 65535:
            raise ValueError("VAJRA_PORT must be between 1 and 65535")
        if self.block_ttl_seconds < 60 or self.block_ttl_seconds > 86400:
            raise ValueError("VAJRA_BLOCK_TTL_SECONDS must be between 60 and 86400")
        for network in self.protected_networks:
            ipaddress.ip_network(network, strict=False)
        if self.environment == "production" and (
            len(self.api_key) < 24 or self.api_key == "local-demo-key-change-me"
        ):
            raise ValueError("Production VAJRA_API_KEY must be a non-demo value of 24+ characters")

    @property
    def active_response_enabled(self) -> bool:
        return (
            self.ips_mode == "active" and self.active_response_ack == "I_UNDERSTAND_ACTIVE_BLOCKING"
        )
