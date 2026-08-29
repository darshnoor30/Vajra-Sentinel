from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        host="127.0.0.1",
        port=8765,
        api_key="test-api-key-that-is-long-enough",
        database_path=tmp_path / "vajra.db",
        eve_path=tmp_path / "eve.json",
        model_path=tmp_path / "model.joblib",
        model_metadata_path=tmp_path / "model_metadata.json",
        demo_mode=False,
        ips_mode="dry-run",
        active_response_ack="",
        block_ttl_seconds=900,
        protected_networks=(
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "::1/128",
        ),
        trusted_proxies=("127.0.0.1",),
    )


@pytest.fixture
def client(settings: Settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client
