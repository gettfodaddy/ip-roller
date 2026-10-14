"""
notify.py

Уведомления в Telegram-группу при находке IP в БС. Простой POST на
sendMessage, без интерактивности — бот тут только пишет, ничего не
принимает (в отличие от cdn_telegram_bot.py из другого проекта).
"""

from __future__ import annotations

import logging

import httpx

log = logging.getLogger("ip-roller.notify")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
TELEGRAM_RICH_API = "https://api.telegram.org/bot{token}/sendRichMessage"


def format_found_message(*, account_label: str, ip: str, zone: str, city: str, cidr: str) -> str:
    city_ru = {"moscow": "Москва", "spb": "Санкт-Петербург"}.get(city, city)
    return (
        f"🎯 Обнаружен IP в БС\n\n"
        f"Аккаунт: {account_label}\n"
        f"IP: {ip}\n"
        f"Зона: {zone} ({city_ru})\n"
        f"CIDR: {cidr}"
    )


def format_zone_down_message(
    *, account_label: str, zone: str, city: str, quarantine_count: int, cooldown_seconds: float
) -> str:
    city_ru = {"moscow": "Москва", "spb": "Санкт-Петербург"}.get(city, city)
    cooldown_min = max(1, round(cooldown_seconds / 60))
    return (
        f"🔴 Зона недоступна уже давно\n\n"
        f"Аккаунт: {account_label}\n"
        f"Зона: {zone} ({city_ru})\n"
        f"Карантинов подряд без единого успеха: {quarantine_count}\n"
        f"Текущая пауза: ~{cooldown_min} мин\n\n"
        f"Похоже на затяжной сбой конкретного регионального хоста Selectel "
        f"(или сетевого маршрута до него), а не разовый обрыв — стоит проверить."
    )


async def send_telegram_message(
    bot_token: str, chat_id: str, text: str, *, timeout: float = 10.0, parse_mode: str | None = None
) -> bool:
    if not bot_token or not chat_id:
        log.warning("Telegram не настроен (пустой token/chat_id) — уведомление пропущено")
        return False
    url = TELEGRAM_API.format(token=bot_token)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            payload = {"chat_id": chat_id, "text": text}
            if parse_mode:
                payload["parse_mode"] = parse_mode
            response = await client.post(url, json=payload)
        if response.status_code != 200:
            log.warning("Telegram sendMessage вернул %s: %s", response.status_code, response.text[:300])
            return False
        return True
    except httpx.HTTPError as exc:
        log.warning("Ошибка сети при отправке в Telegram: %r", exc)
        return False


async def send_telegram_rich_message(
    bot_token: str, chat_id: str, card: dict, *, panel_url: str = "", timeout: float = 20.0
) -> bool:
    """Send a native Telegram card with sections and striped tables."""
    if not bot_token or not chat_id:
        log.warning("Telegram не настроен (пустой token/chat_id) — карточка пропущена")
        return False
    url = TELEGRAM_RICH_API.format(token=bot_token)
    payload = {"chat_id": chat_id, "rich_message": card}
    if panel_url:
        from urllib.parse import urlsplit
        parsed = urlsplit(panel_url)
        if parsed.scheme in {"http", "https"} and parsed.netloc and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment:
            payload["reply_markup"] = {"inline_keyboard": [[
                {"text": "📊 Панель", "url": panel_url.rstrip("/") + "/"},
                {"text": "🔎 История IP", "url": panel_url.rstrip("/") + "/ip-history"},
            ]]}
        else:
            log.warning("TELEGRAM_PANEL_URL некорректен — кнопки пропущены")
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload)
        if response.status_code != 200 or not response.json().get("ok", False):
            log.warning("Telegram sendRichMessage не принял карточку (HTTP %s)", response.status_code)
            return False
        return True
    except (httpx.HTTPError, ValueError):
        log.warning("Ошибка отправки карточки в Telegram")
        return False
