from __future__ import annotations

import ipaddress
import os
import platform

# Import is constrained to the argv-only nft adapter below; no shell is invoked.
import subprocess  # nosec B404
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import Settings
from app.database import Database


class ResponseDenied(ValueError):
    """Raised when a containment request violates a safety policy."""


class NftablesAdapter:
    def block_command(self, ip: str, ttl_seconds: int) -> list[str]:
        address = ipaddress.ip_address(ip)
        set_name = "blocklist_v4" if address.version == 4 else "blocklist_v6"
        return [
            "nft",
            "add",
            "element",
            "inet",
            "vajra_sentinel",
            set_name,
            "{",
            ip,
            "timeout",
            f"{ttl_seconds}s",
            "}",
        ]

    def unblock_command(self, ip: str) -> list[str]:
        address = ipaddress.ip_address(ip)
        set_name = "blocklist_v4" if address.version == 4 else "blocklist_v6"
        return [
            "nft",
            "delete",
            "element",
            "inet",
            "vajra_sentinel",
            set_name,
            "{",
            ip,
            "}",
        ]

    @staticmethod
    def execute(command: list[str]) -> None:
        # The command is constructed from fixed tokens, a parsed IP address, and bounded integer TTL.
        subprocess.run(  # noqa: S603  # nosec B603
            command, check=True, timeout=5, capture_output=True, text=True
        )


class ResponseEngine:
    def __init__(self, settings: Settings, database: Database):
        self.settings = settings
        self.database = database
        self.adapter = NftablesAdapter()
        self.protected = [
            ipaddress.ip_network(network, strict=False) for network in settings.protected_networks
        ]

    def _validate_ip(self, ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        address = ipaddress.ip_address(ip)
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ResponseDenied("Special-use addresses cannot be contained")
        if any(address in network for network in self.protected):
            raise ResponseDenied("The source belongs to a protected network")
        return address

    def _validate_active_host(self) -> None:
        if platform.system() != "Linux":
            raise ResponseDenied("Active response requires a Linux nftables host")
        if os.geteuid() != 0:
            raise ResponseDenied("Active response requires root/CAP_NET_ADMIN")
        if not self.settings.active_response_enabled:
            raise ResponseDenied("Active response safety acknowledgement is missing")

    def contain(
        self,
        detection: dict[str, Any],
        *,
        ttl_seconds: int,
        reason: str,
        actor: str,
    ) -> dict[str, Any]:
        ip = detection["src_ip"]
        self._validate_ip(ip)
        if not detection["response_eligible"]:
            raise ResponseDenied(
                "This detection is not response-eligible; corroborate it and contain manually"
            )
        command = self.adapter.block_command(ip, ttl_seconds)
        status = "simulated"
        if self.settings.ips_mode == "active":
            self._validate_active_host()
            self.adapter.execute(command)
            status = "active"
        expires_at = (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat()
        block_id = self.database.create_block(
            detection_id=detection["id"],
            ip=ip,
            expires_at=expires_at,
            reason=reason,
            mode=self.settings.ips_mode,
            status=status,
            command=command,
            actor=actor,
        )
        return {
            "id": block_id,
            "ip": ip,
            "status": status,
            "mode": self.settings.ips_mode,
            "expires_at": expires_at,
            "command_preview": command,
        }

    def revert(self, block_id: int, actor: str) -> dict[str, Any]:
        blocks = {item["id"]: item for item in self.database.list_blocks(limit=500)}
        block = blocks.get(block_id)
        if block is None:
            raise KeyError(f"Block {block_id} not found")
        if block["status"] not in {"active", "simulated"}:
            raise ResponseDenied(f"Block is already {block['status']}")
        if block["status"] == "active":
            self._validate_active_host()
            self.adapter.execute(self.adapter.unblock_command(block["ip"]))
        self.database.revert_block(block_id, actor)
        return {"id": block_id, "ip": block["ip"], "status": "reverted"}
