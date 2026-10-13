from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FloatingIPRecord:
    id: str
    address: str
    port_id: str | None
    region: str

    @property
    def is_attached(self) -> bool:
        """True, если floating IP привязан к порту (VM) — такой никогда не удаляем."""
        return bool(self.port_id)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "FloatingIPRecord":
        return cls(
            id=str(payload.get("id") or "").strip(),
            address=str(payload.get("floating_ip_address") or "").strip(),
            port_id=(str(payload["port_id"]).strip() if payload.get("port_id") else None),
            region=str(payload.get("region") or "").strip(),
        )


@dataclass
class ResellProject:
    id: str
    name: str
    enabled: bool = True

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ResellProject":
        return cls(
            id=str(payload.get("id") or "").strip(),
            name=str(payload.get("name") or "").strip(),
            enabled=bool(payload.get("enabled", True)),
        )
