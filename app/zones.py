"""
zones.py

Загрузка config/zones.json — список зон Selectel по городам (Москва/СПб),
подтверждённых по скриншотам панели. gis-1/gis-2 (аттестованный сегмент)
выключены по умолчанию (enabled: false) — см. флаг в файле.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Zone:
    code: str
    availability_zone: str
    flags: list[str]
    enabled: bool


@dataclass(frozen=True)
class ZoneCatalog:
    cities: dict[str, list[Zone]]  # "moscow" | "spb" -> [Zone, ...]

    @classmethod
    def load(cls, path: str | Path) -> "ZoneCatalog":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cities = {}
        for city, zones in data.get("cities", {}).items():
            cities[city] = [
                Zone(
                    code=z["code"],
                    availability_zone=z.get("availability_zone", ""),
                    flags=z.get("flags", []),
                    enabled=bool(z.get("enabled", False)),
                )
                for z in zones
            ]
        return cls(cities=cities)

    def enabled_codes(self) -> set[str]:
        return {z.code for zones in self.cities.values() for z in zones if z.enabled}

    def all_codes(self) -> set[str]:
        return {z.code for zones in self.cities.values() for z in zones}

    def city_of(self, code: str) -> str | None:
        for city, zones in self.cities.items():
            if any(z.code == code for z in zones):
                return city
        return None

    CITY_LABELS = {"moscow": "Москва", "spb": "Санкт-Петербург"}

    def city_label(self, city: str) -> str:
        return self.CITY_LABELS.get(city, city)
