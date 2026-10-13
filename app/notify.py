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


async def send_telegram_message(bot_token: str, chat_id: str, text: str, *, timeout: float = 10.0) -> bool:
    if not bot_token or not chat_id:
        log.warning("Telegram не настроен (пустой token/chat_id) — уведомление пропущено")
        return False
    url = TELEGRAM_API.format(token=bot_token)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json={"chat_id": chat_id, "text": text})
        if response.status_code != 200:
            log.warning("Telegram sendMessage вернул %s: %s", response.status_code, response.text[:300])
            return False
        return True
    except httpx.HTTPError as exc:
        log.warning("Ошибка сети при отправке в Telegram: %r", exc)
        return False
