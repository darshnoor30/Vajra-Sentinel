from __future__ import annotations

import pytest

from app.config import Settings


def test_rejects_active_mode_without_ack() -> None:
    with pytest.raises(ValueError, match="Active IPS"):
        Settings(ips_mode="active", active_response_ack="").validate()


def test_rejects_invalid_ttl() -> None:
    with pytest.raises(ValueError, match="TTL"):
        Settings(block_ttl_seconds=5).validate()


def test_accepts_deliberately_enabled_active_mode() -> None:
    settings = Settings(ips_mode="active", active_response_ack="I_UNDERSTAND_ACTIVE_BLOCKING")
    settings.validate()
    assert settings.active_response_enabled is True


def test_production_rejects_demo_key() -> None:
    with pytest.raises(ValueError, match="non-demo"):
        Settings(environment="production", api_key="local-demo-key-change-me").validate()
