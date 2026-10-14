"""Hourly Telegram rolling reports and an operator-triggered test report."""

from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import db
from .config import settings
from .notify import send_telegram_message

log = logging.getLogger("ip-roller.telegram-reports")


def _period_label(start: datetime, end: datetime, timezone_name: str) -> str:
    try:
        tz = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        tz = timezone.utc
    return f"{start.astimezone(tz):%d.%m %H:%M}–{end.astimezone(tz):%H:%M} ({tz.key})"


async def build_hourly_report(
    db_path: Path,
    start: datetime,
    end: datetime,
    *,
    cost_per_ip_hour_rub: float = 0.0,
    timezone_name: str = "Europe/Moscow",
    manager=None,
    test: bool = False,
) -> str:
    """Build a report from persisted create/check events, never dashboard estimates."""
    start_s = start.astimezone(timezone.utc).isoformat(timespec="seconds")
    end_s = end.astimezone(timezone.utc).isoformat(timespec="seconds")
    async with db.connect(db_path) as conn:
        cur = await conn.execute(
            """SELECT region,outcome,COUNT(*) AS n FROM operation_events
               WHERE created_at>=? AND created_at<? GROUP BY region,outcome""",
            (start_s, end_s),
        )
        event_rows = [dict(row) for row in await cur.fetchall()]
        cur = await conn.execute(
            """SELECT COUNT(*) FROM operation_events e
               WHERE e.created_at>=? AND e.created_at<? AND e.ip IS NOT NULL
                 AND EXISTS (SELECT 1 FROM operation_events p WHERE p.ip=e.ip
                   AND (p.created_at<e.created_at OR (p.created_at=e.created_at AND p.id<e.id)))""",
            (start_s, end_s),
        )
        repeats = int((await cur.fetchone())[0] or 0)
        cur = await conn.execute(
            """SELECT COUNT(*) FROM operation_events e
               WHERE e.created_at>=? AND e.created_at<? AND e.outcome='match' AND e.ip IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM operation_events p WHERE p.ip=e.ip
                   AND (p.created_at<e.created_at OR (p.created_at=e.created_at AND p.id<e.id)))""",
            (start_s, end_s),
        )
        new_matches = int((await cur.fetchone())[0] or 0)
        cur = await conn.execute("SELECT id,status,cooldown_until,desired_running FROM accounts")
        accounts = [dict(row) for row in await cur.fetchall()]
        cur = await conn.execute("SELECT created_at,updated_at,state FROM managed_resources")
        resources = [dict(row) for row in await cur.fetchall()]

    counts: dict[str, int] = {}
    regions: dict[str, dict[str, int]] = {}
    for row in event_rows:
        outcome = row["outcome"]
        counts[outcome] = counts.get(outcome, 0) + row["n"]
        region = regions.setdefault(row["region"], {"allocated": 0, "matches": 0, "repeats": 0})
        if outcome in {"match", "miss", "check_error"}:
            region["allocated"] += row["n"]
        if outcome == "match":
            region["matches"] += row["n"]

    checked = counts.get("match", 0) + counts.get("miss", 0)
    allocated = checked + counts.get("check_error", 0)
    # Report repeats by region with an independent query; this avoids attributing
    # a repeated address to whichever region happened to be iterated last.
    async with db.connect(db_path) as conn:
        cur = await conn.execute(
            """SELECT e.region,COUNT(*) AS n FROM operation_events e
               WHERE e.created_at>=? AND e.created_at<? AND e.ip IS NOT NULL
                 AND EXISTS (SELECT 1 FROM operation_events p WHERE p.ip=e.ip
                   AND (p.created_at<e.created_at OR (p.created_at=e.created_at AND p.id<e.id)))
               GROUP BY e.region""", (start_s, end_s),
        )
        for row in await cur.fetchall():
            regions.setdefault(row["region"], {"allocated": 0, "matches": 0, "repeats": 0})["repeats"] = row["n"]

    now = datetime.now(timezone.utc)
    def parse(value: str | None) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(value) if value else None
            return parsed.replace(tzinfo=timezone.utc) if parsed and parsed.tzinfo is None else parsed
        except ValueError:
            return None

    running = sum(1 for a in accounts if manager.is_running(a["id"])) if manager else sum(
        1 for a in accounts if a["desired_running"]
    )
    cooldown = sum(1 for a in accounts if a["status"] == "cooldown" and (parse(a["cooldown_until"]) or now) > now)

    held_hours = 0.0
    if cost_per_ip_hour_rub > 0:
        for resource in resources:
            created = parse(resource["created_at"])
            updated = parse(resource["updated_at"])
            if created is None:
                continue
            finish = updated if resource["state"] == "deleted" and updated else end
            overlap = max(0.0, (min(end, finish) - max(start, created)).total_seconds() / 3600)
            held_hours += overlap
    cost = held_hours * max(0.0, cost_per_ip_hour_rub)
    match_rate = 100 * counts.get("match", 0) / checked if checked else 0
    repeat_rate = 100 * repeats / allocated if allocated else 0
    efficiency = 100 * new_matches / checked if checked else 0

    lines = ["🧪 ТЕСТОВЫЙ ОТЧЁТ РОЛЛИНГА" if test else "📊 Статистика роллинга за час",
             f"Период: {_period_label(start, end, timezone_name)}", "",
             f"Выделено IP / проверок: {allocated}",
             f"Совпадений с CIDR: {counts.get('match', 0)} ({match_rate:.1f}% от успешных проверок)",
             f"Не совпало с CIDR: {counts.get('miss', 0)}",
             f"Ошибок проверки IP: {counts.get('check_error', 0)}",
             f"Повторных IP: {repeats} ({repeat_rate:.1f}% от выделенных)",
             f"Новых уникальных совпадений: {new_matches}",
             f"Эффективность: {efficiency:.2f} новых IP на 100 успешных проверок",
             f"Ошибок 429: {counts.get('rate_limited', 0) + counts.get('http_429', 0)}"]
    other_errors = sum(n for name, n in counts.items() if name not in {"match", "miss", "check_error", "rate_limited", "http_429"})
    lines += [f"Других ошибок API/сети: {other_errors}",
              f"Аккаунты: активно {running}/{len(accounts)}, cooldown {cooldown}"]
    if regions:
        lines += ["", "По зонам:"]
        for region, values in sorted(regions.items()):
            lines.append(f"• {region}: IP {values['allocated']}, совпадений {values['matches']}, повторов {values['repeats']}")
    if cost_per_ip_hour_rub > 0:
        lines += ["", f"Оценка стоимости ресурсов за период: {cost:.2f} ₽",
                  f"Стоимость одного совпадения: {cost / counts['match']:.2f} ₽" if counts.get("match") else "Стоимость совпадения: — (совпадений нет)"]
    else:
        lines += ["", "Стоимость: не рассчитана — FLOATING_IP_COST_PER_HOUR_RUB не задана"]
    lines += ["", "Повторы считаются по IP, которые уже встречались ранее в журнале. Стоимость — оценка по заданному тарифу."]
    return "\n".join(lines)


async def send_report_for_period(start: datetime, end: datetime, *, manager=None, test: bool = False) -> bool:
    text = await build_hourly_report(
        settings.db_path, start, end,
        cost_per_ip_hour_rub=settings.floating_ip_cost_per_hour_rub,
        timezone_name=settings.telegram_report_timezone, manager=manager, test=test,
    )
    return await send_telegram_message(settings.telegram_bot_token, settings.telegram_chat_id, text)


def previous_complete_hour(now: datetime | None = None, timezone_name: str = "Europe/Moscow") -> tuple[datetime, datetime]:
    try:
        tz = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        tz = timezone.utc
    current = (now or datetime.now(timezone.utc)).astimezone(tz)
    end_local = current.replace(minute=0, second=0, microsecond=0)
    start_local = end_local - timedelta(hours=1)
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


async def hourly_report_loop(stop: asyncio.Event, *, manager=None) -> None:
    """Retry the most recently completed hour until delivery, once per hour."""
    while not stop.is_set():
        start, end = previous_complete_hour(timezone_name=settings.telegram_report_timezone)
        now = datetime.now(timezone.utc)
        # Allow late events/DB writes to settle before sending the completed hour.
        if now >= end + timedelta(minutes=2) and settings.telegram_bot_token and settings.telegram_chat_id:
            key = start.isoformat(timespec="seconds")
            async with db.connect(settings.db_path) as conn:
                cur = await conn.execute("SELECT 1 FROM notification_deliveries WHERE channel='telegram_hourly' AND period_start=?", (key,))
                sent = await cur.fetchone()
            if not sent:
                delivered = await send_report_for_period(start, end, manager=manager)
                if delivered:
                    async with db.connect(settings.db_path) as conn:
                        await conn.execute("INSERT OR IGNORE INTO notification_deliveries(channel,period_start,delivered_at) VALUES('telegram_hourly',?,?)", (key, db.now_iso()))
                        await conn.commit()
                else:
                    log.warning("Не удалось отправить почасовой Telegram-отчёт за %s", key)
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass


async def _send_test() -> int:
    await db.init_db(settings.db_path)
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        print("Telegram не настроен: задайте TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID в .env")
        return 2
    start, end = previous_complete_hour(timezone_name=settings.telegram_report_timezone)
    if await send_report_for_period(start, end, test=True):
        print("Тестовый подробный отчёт за последний завершённый час отправлен.")
        return 0
    print("Telegram не подтвердил отправку. Проверьте токен, chat_id и журнал приложения.")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Отправить тестовую статистику роллинга в Telegram")
    parser.add_argument("--test", action="store_true", help="отправить тестовый отчёт за последний завершённый час")
    args = parser.parse_args()
    if not args.test:
        parser.error("укажите --test")
    raise SystemExit(asyncio.run(_send_test()))


if __name__ == "__main__":
    main()
