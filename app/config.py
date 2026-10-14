"""
config.py

Настройки приложения из .env (через os.environ — без лишних зависимостей).
Всё, что реально секретно (пароль админки, пароли Selectel-аккаунтов,
telegram token) — либо в .env, либо в БД (пароли аккаунтов), никогда не
хардкодится и не попадает в git (.gitignore закрывает .env и data/).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"


def _load_dotenv(path: Path) -> None:
    """Минимальный .env-загрузчик для локальной разработки — не переписывает
    переменные, уже заданные в окружении (systemd EnvironmentFile важнее)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(PROJECT_ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Веб-панель
    admin_username: str = field(default_factory=lambda: _env("ADMIN_USERNAME", "admin"))
    admin_password_hash: str = field(default_factory=lambda: _env("ADMIN_PASSWORD_HASH"))
    session_secret: str = field(default_factory=lambda: _env("SESSION_SECRET") or secrets.token_hex(32))
    session_https_only: bool = field(default_factory=lambda: _env("SESSION_HTTPS_ONLY", "true").lower() in {"1", "true", "yes"})
    host: str = field(default_factory=lambda: _env("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("PORT", 8000))

    # Пути
    db_path: Path = field(default_factory=lambda: Path(_env("DB_PATH") or str(DATA_DIR / "ip-roller.db")))
    zones_path: Path = field(default_factory=lambda: Path(_env("ZONES_PATH") or str(CONFIG_DIR / "zones.json")))
    whitelist_path: Path = field(
        default_factory=lambda: Path(_env("WHITELIST_PATH") or str(CONFIG_DIR / "cidr_whitelist.json"))
    )

    # Telegram-уведомления (опционально)
    telegram_bot_token: str = field(default_factory=lambda: _env("TELEGRAM_BOT_TOKEN"))
    telegram_chat_id: str = field(default_factory=lambda: _env("TELEGRAM_CHAT_ID"))
    telegram_hourly_report_enabled: bool = field(
        default_factory=lambda: _env("TELEGRAM_HOURLY_REPORT_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
    )
    telegram_report_timezone: str = field(default_factory=lambda: _env("TELEGRAM_REPORT_TIMEZONE", "Europe/Moscow"))
    telegram_panel_url: str = field(default_factory=lambda: _env("TELEGRAM_PANEL_URL"))

    # Roller-параметры (безопасные дефолты по эмпирике пользователя:
    # 10 попыток create на аккаунт -> 429 -> ~8 минут cooldown, ГЛОБАЛЬНО
    # на аккаунт, не по зонам)
    max_creates_per_burst: int = field(default_factory=lambda: _env_int("MAX_CREATES_PER_BURST", 8))
    cooldown_429_seconds: float = field(default_factory=lambda: float(_env("COOLDOWN_429_SECONDS", "480")))
    cooldown_4xx_seconds: float = field(default_factory=lambda: float(_env("COOLDOWN_4XX_SECONDS", "60")))
    cooldown_max_seconds: float = field(default_factory=lambda: float(_env("COOLDOWN_MAX_SECONDS", "960")))

    # Сколько сетевых ошибок подряд именно в одной зоне терпим с короткими
    # растущими паузами (network_error_base_seconds, потом *1.5 за каждую
    # следующую), прежде чем признать зону недоступной и увести в полный
    # карантин — см. ZONE_QUARANTINE_* ниже.
    network_error_escalate_after: int = field(default_factory=lambda: _env_int("NETWORK_ERROR_ESCALATE_AFTER", 3))
    network_error_base_seconds: float = field(
        default_factory=lambda: float(_env("NETWORK_ERROR_BASE_SECONDS", "30"))
    )
    # Затяжной простой ОДНОЙ зоны (например, региональный хост Selectel лёг
    # на всю ночь) — каждый следующий карантин подряд без единого успеха
    # длиннее предыдущего в ZONE_QUARANTINE_GROWTH раз, до потолка
    # ZONE_QUARANTINE_MAX_SECONDS (час по умолчанию), вместо долбёжки
    # мёртвого хоста каждые 8 минут часами напролёт.
    zone_quarantine_growth: float = field(default_factory=lambda: float(_env("ZONE_QUARANTINE_GROWTH", "2.0")))
    zone_quarantine_max_seconds: float = field(
        default_factory=lambda: float(_env("ZONE_QUARANTINE_MAX_SECONDS", "3600"))
    )
    # После скольких карантинов ПОДРЯД без единого успеха слать алерт в
    # Telegram про конкретную зону (если Telegram настроен) — чтобы узнать
    # про затяжной сбой из уведомления, а не по факту зайдя в панель через
    # много часов простоя.
    zone_outage_alert_after: int = field(default_factory=lambda: _env_int("ZONE_OUTAGE_ALERT_AFTER", 2))

    # Параллельное удаление miss-IP — сколько delete-запросов к Selectel
    # можно держать в полёте одновременно на один аккаунт, не дожидаясь
    # подтверждения удаления перед следующим create.
    delete_concurrency: int = field(default_factory=lambda: _env_int("DELETE_CONCURRENCY", 4))

    # Реконсилятор осиротевших IP — как часто (в секундах) воркер сверяет
    # фактический список floating IP в Selectel с тем, что записано в БД,
    # чтобы подхватить пропущенный MATCH (например, ответ на create
    # потерялся из-за сетевого сбоя, а IP на самом деле создался) и
    # добить недоудалённый MISS. 0 — реконсилятор выключен.
    reconciler_interval_seconds: float = field(
        default_factory=lambda: float(_env("RECONCILER_INTERVAL_SECONDS", "180"))
    )

    # Per-worker smoothing; SQLite reservations also enforce this as one
    # service-wide ceiling shared by all account workers.
    max_creates_per_minute: int = field(default_factory=lambda: _env_int("MAX_CREATES_PER_MINUTE", 10))
    scheduler_lease_seconds: int = field(default_factory=lambda: _env_int("SCHEDULER_LEASE_SECONDS", 120))
    global_429_threshold_accounts: int = field(default_factory=lambda: _env_int("GLOBAL_429_THRESHOLD_ACCOUNTS", 2))
    global_429_window_seconds: int = field(default_factory=lambda: _env_int("GLOBAL_429_WINDOW_SECONDS", 120))
    # Optional provider tariff for transparent estimate. Zero keeps monetary
    # totals disabled until operator enters a verified Selectel rate.
    floating_ip_cost_per_hour_rub: float = field(default_factory=lambda: float(_env("FLOATING_IP_COST_PER_HOUR_RUB", "0") or "0"))
    max_estimated_daily_cost_rub: float = field(default_factory=lambda: float(_env("MAX_ESTIMATED_DAILY_COST_RUB", "0") or "0"))
    max_estimated_hourly_cost_rub: float = field(default_factory=lambda: float(_env("MAX_ESTIMATED_HOURLY_COST_RUB", "0") or "0"))

    # Service-wide fail-safe limits. Reservations are shared through SQLite,
    # so separate account workers cannot multiply these caps.
    max_create_operations_per_day: int = field(default_factory=lambda: _env_int("MAX_CREATE_OPERATIONS_PER_DAY", 100))
    max_active_managed_ips: int = field(default_factory=lambda: _env_int("MAX_ACTIVE_MANAGED_IPS", 20))


settings = Settings()

DATA_DIR.mkdir(parents=True, exist_ok=True)
