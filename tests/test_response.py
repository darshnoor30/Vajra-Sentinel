from __future__ import annotations

import pytest

from app.config import Settings
from app.database import Database
from app.services.response import ResponseDenied, ResponseEngine


def detection(ip: str, eligible: bool = True) -> dict:
    return {"id": 1, "src_ip": ip, "rule_id": "TEST", "response_eligible": eligible}


def test_protected_network_cannot_be_blocked(settings: Settings) -> None:
    database = Database(settings.database_path)
    database.initialize()
    response = ResponseEngine(settings, database)
    with pytest.raises(ResponseDenied, match="protected"):
        response.contain(detection("10.0.0.5"), ttl_seconds=900, reason="test", actor="pytest")


def test_ml_only_detection_cannot_be_blocked(settings: Settings) -> None:
    database = Database(settings.database_path)
    database.initialize()
    response = ResponseEngine(settings, database)
    with pytest.raises(ResponseDenied, match="not response-eligible"):
        response.contain(
            detection("45.155.205.233", eligible=False),
            ttl_seconds=900,
            reason="test",
            actor="pytest",
        )


def test_nft_command_does_not_use_a_shell(settings: Settings) -> None:
    database = Database(settings.database_path)
    database.initialize()
    response = ResponseEngine(settings, database)
    command = response.adapter.block_command("45.155.205.233", 900)
    assert command[:5] == ["nft", "add", "element", "inet", "vajra_sentinel"]
    assert ";" not in command
