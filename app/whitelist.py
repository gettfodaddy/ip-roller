"""
whitelist.py

Загрузка и проверка CIDR-списка "белого списка" (БС) РКН/ТСПУ по зонам
Selectel (Москва / Санкт-Петербург). Список правится руками в
config/cidr_whitelist.json по мере поступления новых диапазонов —
никакого сетевого источника, весь список даёт пользователь сам.

Использование:
    from whitelist import Whitelist

    wl = Whitelist.load("config/cidr_whitelist.json")
    match = wl.check("31.129.42.15")
    if match:
        print(f"IP в БС, зона={match.zone}, cidr={match.cidr}")
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Match:
    zone: str
    cidr: str


class Whitelist:
    def __init__(self, zones: dict[str, list[ipaddress.IPv4Network]], updated: str = ""):
        self._zones = zones
        self.updated = updated

    @classmethod
    def load(cls, path: str | Path) -> "Whitelist":
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))

        zones: dict[str, list[ipaddress.IPv4Network]] = {}
        for zone_name, cidr_list in data.get("zones", {}).items():
            networks = []
            for raw in cidr_list:
                try:
                    networks.append(ipaddress.ip_network(raw, strict=True))
                except ValueError as e:
                    raise ValueError(f"Некорректный CIDR '{raw}' в зоне '{zone_name}': {e}") from e
            zones[zone_name] = networks

        return cls(zones=zones, updated=data.get("updated", ""))

    def check(self, ip: str) -> Optional[Match]:
        """Возвращает Match(zone, cidr), если IP попадает в один из диапазонов
        белого списка, иначе None. Проверяет все зоны — IP может теоретически
        совпасть с диапазоном другого города, чем ожидалось при запросе,
        это тоже стоит логировать, а не отбрасывать молча."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for zone_name, networks in self._zones.items():
            for net in networks:
                if addr in net:
                    return Match(zone=zone_name, cidr=str(net))
        return None

    def zones(self) -> list[str]:
        return list(self._zones.keys())

    def cidr_count(self, zone: Optional[str] = None) -> int:
        if zone is not None:
            return len(self._zones.get(zone, []))
        return sum(len(v) for v in self._zones.values())

    def entries(self) -> dict[str, list[str]]:
        """CIDR по зонам (городам), отсортированные по возрастанию адреса —
        для отображения на дашборде, что именно ищет роллер."""
        return {
            zone_name: [str(net) for net in sorted(networks)]
            for zone_name, networks in self._zones.items()
        }


if __name__ == "__main__":
    # Быстрая самопроверка при запуске файла напрямую.
    wl = Whitelist.load(Path(__file__).resolve().parents[1] / "config" / "cidr_whitelist.json")
    print(f"Загружено зон: {wl.zones()}, всего CIDR: {wl.cidr_count()}")

    test_cases = [
        ("31.129.42.15", "spb"),    # из присланного списка (совпадает со скриншотом ранее в чате)
        ("87.228.32.200", "spb"),   # из "новых подсетей"
        ("5.178.85.1", "moscow"),
        ("8.8.8.8", None),          # заведомо не в списке
    ]
    for ip, expected_zone in test_cases:
        match = wl.check(ip)
        status = f"НЕ в БС" if match is None else f"в БС, zone={match.zone}, cidr={match.cidr}"
        ok = "OK" if (match.zone if match else None) == expected_zone else "MISMATCH"
        print(f"{ip:16s} -> {status:40s} [{ok}]")
