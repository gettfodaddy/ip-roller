"""Background refresh of expired local CIDR checks.

This is deliberately separate from Telegram and all Selectel API operations.
The database's due MISS/ERROR rows form a durable work queue; an expired
negative result is re-evaluated against the currently loaded CIDR data.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from . import db
from .whitelist import Whitelist

log = logging.getLogger("ip-roller.ip-checker")


async def run_registry_checker(db_path: Path, whitelist: Whitelist, stop_event: asyncio.Event,
                               *, interval_seconds: float = 30.0, batch_size: int = 200) -> None:
    while not stop_event.is_set():
        try:
            due = await db.list_due_ip_checks(db_path, limit=batch_size)
            batch_failed = False
            for row in due:
                if stop_event.is_set():
                    return
                try:
                    match = whitelist.check(row["ip"])
                    await db.refresh_ip_check(db_path, ip=row["ip"], match=match)
                except Exception as exc:
                    batch_failed = True
                    log.exception("Ошибка повторной проверки IP %s; статус останется ERROR", row["ip"])
                    try:
                        await db.refresh_ip_check(db_path, ip=row["ip"], match=None, error=repr(exc))
                    except Exception:
                        log.exception("Не удалось сохранить ошибку повторной проверки IP %s", row["ip"])
            if due and not batch_failed:
                continue
        except Exception:
            log.exception("Реестр проверки IP временно недоступен; повторю попытку")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=max(1.0, interval_seconds))
        except asyncio.TimeoutError:
            pass
