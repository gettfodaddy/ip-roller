"""
manager.py

Оркестратор воркеров: держит в памяти {account_id: asyncio.Task} для
процесса веб-приложения, даёт start/stop по запросу из веб-панели,
восстанавливает воркеры для аккаунтов с desired_running=True при старте
приложения (переживает рестарт процесса).

Реальный Selectel-клиент создаётся здесь (client_factory) — roller.py
про Selectel вообще не знает, только про протокол NeutronLike.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from . import db
from .config import Settings
from .roller import run_account_worker
from .selectel.neutron import SelectelNeutronClient
from .whitelist import Whitelist
from .zones import ZoneCatalog
from .proxies import ProxyPool, CheckedProxyTransport

log = logging.getLogger("ip-roller.manager")


class RollerManager:
    def __init__(self, *, db_path: Path, whitelist: Whitelist, zone_catalog: ZoneCatalog, settings: Settings):
        self.db_path = db_path
        self.whitelist = whitelist
        self.zone_catalog = zone_catalog
        self.settings = settings
        self._tasks: dict[int, asyncio.Task] = {}
        self._stop_events: dict[int, asyncio.Event] = {}
        self._lifecycle_lock = asyncio.Lock()
        self._proxy_pool = ProxyPool(settings.proxy_pool_path, threshold=settings.proxy_failure_threshold) if settings.proxy_pool_enabled else None

    async def _client_factory(self, account: db.AccountRow) -> SelectelNeutronClient:
        async def status(value, detail):
            await db.update_account_status(self.db_path, account.id, value, detail)

        transport = CheckedProxyTransport(self._proxy_pool, account.selected_zones, status, self._stop_events.get(account.id), account_label=account.label) if self._proxy_pool else None
        client = SelectelNeutronClient(
            username=account.username,
            password=account.password,
            account_id=account.account_id,
            project_id=account.project_id or "",
            project_name=account.project_name or "",
            transport=transport,
        )
        try:
            await client.ensure_authenticated()  # fail fast on invalid credentials
        except BaseException:
            await client.close()
            raise
        return client

    def is_running(self, account_id: int) -> bool:
        task = self._tasks.get(account_id)
        return task is not None and not task.done()

    async def start_account(self, account_id: int) -> None:
        async with self._lifecycle_lock:
            if self.is_running(account_id):
                return
            account = await db.get_account(self.db_path, account_id)
            if account is None:
                raise ValueError(f"Аккаунт {account_id} не найден")
            if not account.selected_zones:
                raise ValueError("Сначала выбери хотя бы одну зону для этого аккаунта")
            stop_event = asyncio.Event()
            self._stop_events[account_id] = stop_event

            async def _runner():
                try:
                    await run_account_worker(
                        account,
                        db_path=self.db_path,
                        whitelist=self.whitelist,
                        zone_catalog=self.zone_catalog,
                        settings=self.settings,
                        client_factory=self._client_factory,
                        stop_event=stop_event,
                    )
                except asyncio.CancelledError:
                    if not stop_event.is_set():
                        raise
                    await db.update_account_status(self.db_path, account_id, "stopped", "остановлено пользователем")
                except Exception:
                    log.exception("[%s] воркер упал с необработанным исключением", account.label)
                    await db.update_account_status(self.db_path, account_id, "error", "Воркер упал — см. server log")
                    await db.set_account_desired_running(self.db_path, account_id, False)

            # Persist intent before scheduling: a crash between these steps
            # must not leave an untracked worker running after restart.
            await db.set_account_desired_running(self.db_path, account_id, True)
            self._tasks[account_id] = asyncio.create_task(_runner())

    async def stop_account(self, account_id: int) -> None:
        async with self._lifecycle_lock:
            await db.set_account_desired_running(self.db_path, account_id, False)
            stop_event = self._stop_events.get(account_id)
            if stop_event is not None:
                stop_event.set()
            task = self._tasks.get(account_id)
            if task is not None:
                try:
                    # Neutron uses a 30s HTTP timeout. Give an in-flight
                    # request time to finish so its remote result can be
                    # recorded before forcing cancellation.
                    await asyncio.wait_for(task, timeout=40.0)
                except asyncio.TimeoutError:
                    log.warning("Аккаунт %s не остановился за 40с, отменяю задачу принудительно", account_id)
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                self._tasks.pop(account_id, None)
            self._stop_events.pop(account_id, None)
            await db.update_account_status(self.db_path, account_id, "stopped", "остановлено пользователем")

    async def resume_desired_running(self) -> None:
        """Вызывается при старте приложения — поднимает воркеры для
        аккаунтов, которые были запущены до рестарта процесса."""
        for account in await db.list_accounts(self.db_path):
            if account.desired_running:
                log.info("Восстанавливаю воркер для аккаунта %s после рестарта", account.label)
                try:
                    await self.start_account(account.id)
                except Exception:
                    log.exception("Не удалось восстановить воркер для %s", account.label)

    async def shutdown(self) -> None:
        for account_id in list(self._tasks.keys()):
            stop_event = self._stop_events.get(account_id)
            if stop_event is not None:
                stop_event.set()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    async def emergency_stop(self) -> None:
        """Stop every account worker and persist the stopped intent.

        This changes worker state only. Managed and protected Floating IPs
        remain untouched for operator review.
        """
        for account_id in list(self._tasks.keys()):
            await self.stop_account(account_id)
        for account in await db.list_accounts(self.db_path):
            await db.set_account_desired_running(self.db_path, account.id, False)
            await db.update_account_status(self.db_path, account.id, "stopped", "аварийная остановка")
