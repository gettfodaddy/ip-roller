"""
roller.py

Воркер на один аккаунт: create floating ip -> сверка с whitelist ->
оставить (найден IP в БС) или удалить -> лог попытки в БД. Работает,
пока account.desired_running=True и не пришла отмена (stop_event).

Уровни защиты от перегрузки Selectel (см. strategy.py за подробностями):
  - account-wide (AccountState) — 429/квота/самоограничение по адаптивному
    burst_limit. Подтверждено эмпирически: у Selectel это лимит на
    аккаунт целиком, поэтому блокирует ВСЕ зоны сразу.
  - per-зона (ZoneState, в zone_states) — сетевые ошибки конкретного
    регионального API-хоста. Не блокирует остальные зоны того же
    аккаунта — если, скажем, ru-3 не отвечает, а ru-9 работает, роллер
    продолжает крутить ru-9, просто временно обходя ru-3 стороной.
  - скользящее окно (RateWindow) — сглаживает темп попыток создания
    равномерно во времени, независимо от burst_limit.

Плюс два фоновых механизма, не блокирующие основной цикл:
  - параллельное удаление miss-IP (не ждём подтверждения delete перед
    следующим create — освобождённые слоты в semaphore ограничивают,
    сколько delete-запросов летит одновременно);
  - реконсилятор — периодически сверяет реальный список floating IP в
    Selectel с БД, чтобы подхватить пропущенные MATCH и добить
    недоудалённые MISS (например, после сетевого сбоя на create/delete).

client_factory внедряется параметром — чтобы можно было подставить
фейковый клиент в тестах, не трогая реальный Selectel API.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Protocol

import httpx

from . import db
from .config import Settings
from .notify import format_found_message, format_zone_down_message, send_telegram_message
from .selectel.errors import SelectelAuthError, SelectelQuotaError, SelectelRateLimitError, SelectelRequestError
from .selectel.models import FloatingIPRecord
from .strategy import (
    AccountState,
    RateWindow,
    StrategyConfig,
    ZoneState,
    on_quota_4xx,
    on_rate_limit_429,
    on_successful_create,
    on_zone_network_error,
    on_zone_success,
)
from .whitelist import Whitelist
from .zones import ZoneCatalog

log = logging.getLogger("ip-roller.roller")


class NeutronLike(Protocol):
    async def create_floating_ip(self, region: str) -> FloatingIPRecord: ...
    async def delete_floating_ip(self, floating_ip_id: str, region: str) -> bool: ...
    async def list_floating_ips(self, region: str) -> list[FloatingIPRecord]: ...
    async def close(self) -> None: ...


ClientFactory = Callable[[db.AccountRow], Awaitable[NeutronLike]]


async def _sleep_cancellable(seconds: float, stop_event: asyncio.Event, step: float = 1.0) -> bool:
    """Спит до `seconds`, но выходит раньше, если пришёл stop_event.
    Возвращает True, если доспали полностью, False если прервали по stop."""
    remaining = seconds
    while remaining > 0:
        if stop_event.is_set():
            return False
        chunk = min(step, remaining)
        await asyncio.sleep(chunk)
        remaining -= chunk
    return True


async def run_account_worker(
    account: db.AccountRow,
    *,
    db_path: Path,
    whitelist: Whitelist,
    zone_catalog: ZoneCatalog,
    settings: Settings,
    client_factory: ClientFactory,
    stop_event: asyncio.Event,
) -> None:
    if not account.selected_zones:
        await db.update_account_status(db_path, account.id, "error", "Не выбрана ни одна зона")
        await db.set_account_desired_running(db_path, account.id, False)
        return

    strategy_config = StrategyConfig(
        max_creates_per_burst=settings.max_creates_per_burst,
        cooldown_429_seconds=settings.cooldown_429_seconds,
        cooldown_4xx_seconds=settings.cooldown_4xx_seconds,
        cooldown_max_seconds=settings.cooldown_max_seconds,
        zone_quarantine_growth=settings.zone_quarantine_growth,
        zone_quarantine_max_seconds=settings.zone_quarantine_max_seconds,
        network_error_escalate_after=settings.network_error_escalate_after,
        network_error_base_seconds=settings.network_error_base_seconds,
    )
    state = AccountState(burst_limit=strategy_config.max_creates_per_burst)
    zone_states: dict[str, ZoneState] = {z: ZoneState() for z in account.selected_zones}
    runtime = await db.load_account_runtime(db_path, account.id)
    if runtime:
        state.consecutive_errors = int(runtime.get("consecutive_errors") or 0)
        state.creates_in_burst = int(runtime.get("creates_in_burst") or 0)
        state.burst_limit = max(strategy_config.burst_limit_min, min(strategy_config.burst_limit_max,
            int(runtime.get("burst_limit") or strategy_config.max_creates_per_burst)))
        for field_name, attr in (("backoff_until", "backoff_until"), ("last_request_at", "last_request_at"),
                                 ("last_success_at", "last_success_at")):
            raw = runtime.get(field_name)
            if raw:
                try:
                    setattr(state, attr, datetime.fromisoformat(raw))
                except (TypeError, ValueError):
                    pass
        for zone, saved in runtime.get("zone_states", {}).items():
            if zone not in zone_states or not isinstance(saved, dict):
                continue
            zstate = zone_states[zone]
            zstate.consecutive_errors = int(saved.get("consecutive_errors") or 0)
            zstate.quarantine_count = int(saved.get("quarantine_count") or 0)
            zstate.alert_sent = bool(saved.get("alert_sent"))
            try:
                zstate.cooldown_until = datetime.fromisoformat(saved["cooldown_until"]) if saved.get("cooldown_until") else None
            except (TypeError, ValueError):
                zstate.cooldown_until = None
    zone_idx = 0

    async def persist_runtime() -> None:
        zone_snapshot = {
            zone: {
                "consecutive_errors": zs.consecutive_errors,
                "quarantine_count": zs.quarantine_count,
                "alert_sent": zs.alert_sent,
                "cooldown_until": zs.cooldown_until.isoformat() if zs.cooldown_until else None,
            }
            for zone, zs in zone_states.items()
        }
        await db.save_account_runtime(
            db_path, account.id,
            consecutive_errors=state.consecutive_errors,
            creates_in_burst=state.creates_in_burst,
            burst_limit=state.burst_limit,
            backoff_until=state.backoff_until.isoformat() if state.backoff_until else None,
            last_request_at=state.last_request_at.isoformat() if state.last_request_at else None,
            last_success_at=state.last_success_at.isoformat() if state.last_success_at else None,
            zone_states=zone_snapshot,
        )

    rate_window = RateWindow(limit=settings.max_creates_per_minute) if settings.max_creates_per_minute > 0 else None

    # Фоновые delete miss-IP не блокируют основной цикл — ограничены
    # только семафором (сколько delete-запросов летит одновременно), а
    # не ожиданием ответа перед следующим create. Задачи держим в set(),
    # иначе их может собрать GC до завершения (fire-and-forget gotcha).
    delete_semaphore = asyncio.Semaphore(max(1, settings.delete_concurrency))
    background_tasks: set[asyncio.Task] = set()

    def pick_ready_zone() -> tuple[str | None, float]:
        """Крутит по кругу зоны аккаунта и возвращает первую, что сейчас НЕ
        в личном сетевом карантине. Если в карантине все — вернёт (None,
        сколько ждать до ближайшего освобождения)."""
        nonlocal zone_idx
        n = len(account.selected_zones)
        soonest_wait: float | None = None
        for _ in range(n):
            z = account.selected_zones[zone_idx % n]
            zone_idx += 1
            zstate = zone_states[z]
            if not zstate.is_cooling_down():
                return z, 0.0
            wait = zstate.seconds_until_ready()
            if soonest_wait is None or wait < soonest_wait:
                soonest_wait = wait
        return None, (soonest_wait if soonest_wait is not None else 1.0)

    async def delete_miss_ip(record: FloatingIPRecord, zone: str) -> None:
        async with delete_semaphore:
            deleted = False
            await db.update_managed_resource_state(db_path, record.id, "delete_pending")
            delete_error = False
            try:
                deleted = await client.delete_floating_ip(record.id, zone)
            except Exception as exc:
                delete_error = True
                log.warning("[%s] не удалось удалить miss-IP %s: %r", account.label, record.address, exc)
            await db.update_managed_resource_state(db_path, record.id, "delete_error" if delete_error else "deleted")
            await db.log_attempt(
                db_path, account_id=account.id, zone=zone, ip=record.address,
                result="miss", http_status=201, neutron_id=record.id,
                detail=f"deleted={deleted}, error={delete_error}",
            )
            await db.bump_account_counters(db_path, account.id, attempts=1, matches=0)
            log.info(
                "[%s] MISS: %s (зона %s) — %s", account.label, record.address, zone,
                "удалён" if deleted else "НЕ удалён (см. предупреждение выше)",
            )

    def spawn_background(coro: Awaitable[None]) -> None:
        task = asyncio.create_task(coro)
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)

    async def notify_in_background(text: str, context: str) -> None:
        sent = await send_telegram_message(settings.telegram_bot_token, settings.telegram_chat_id, text)
        if not sent:
            log.warning("[%s] не удалось отправить уведомление в Telegram: %s", account.label, context)

    async def reconcile_once() -> None:
        """Reconcile only resources in the durable ownership ledger.

        Unknown resources are deliberately left untouched: listing a project
        is not proof that this application created every returned IP.
        Protected matches are never auto-deleted, even if the CIDR file changes.
        """
        owned = {item["neutron_id"]: item for item in await db.list_managed_resources(db_path, account.id)}
        for zone in account.selected_zones:
            try:
                records = await client.list_floating_ips(zone)
            except Exception as exc:
                log.warning(
                    "[%s] реконсилятор: не удалось получить список IP в зоне %s: %r",
                    account.label, zone, exc,
                )
                continue
            for record in records:
                if record.is_attached or not record.address:
                    continue
                managed = owned.get(record.id)
                if managed is None or managed["zone"] != zone:
                    continue
                if managed["state"] == "deleted":
                    continue
                match = whitelist.check(record.address)
                # A crash between protecting a match and persisting its
                # found_ips row must be repaired, but a protected IP is never
                # downgraded or deleted if the local CIDR list later changes.
                if managed["state"] == "protected" and match is None:
                    continue
                if match is not None:
                    await db.update_managed_resource_state(db_path, record.id, "protected")
                    registry_entry = await db.get_ip_registry_entry(db_path, record.address)
                    if registry_entry:
                        await db.refresh_ip_check(db_path, ip=record.address, match=match)
                    else:
                        await db.record_ip_observation(
                            db_path, ip=record.address, account_id=account.id,
                            region=zone, match=match, neutron_id=record.id,
                        )
                    if await db.found_ip_exists(db_path, account.id, record.address):
                        continue
                    log.info(
                        "[%s] реконсилятор нашёл пропущенный MATCH: %s (зона %s, cidr %s)",
                        account.label, record.address, zone, match.cidr,
                    )
                    await db.log_attempt(
                        db_path, account_id=account.id, zone=zone, ip=record.address,
                        result="match", http_status=200, neutron_id=record.id,
                        detail=f"cidr={match.cidr}, найдено реконсилятором",
                    )
                    await db.add_found_ip(
                        db_path, account_id=account.id, ip=record.address, zone=zone,
                        city=match.zone, cidr_matched=match.cidr, neutron_id=record.id,
                    )
                    await db.bump_account_counters(db_path, account.id, matches=1)
                    if settings.telegram_bot_token and settings.telegram_chat_id:
                        text = format_found_message(
                            account_label=account.label, ip=record.address, zone=zone,
                            city=match.zone, cidr=match.cidr,
                        )
                        spawn_background(notify_in_background(text, f"IP {record.address}"))
                else:
                    log.info("[%s] повтор удаления собственного miss-IP %s (зона %s)", account.label, record.address, zone)
                    async with delete_semaphore:
                        await db.update_managed_resource_state(db_path, record.id, "delete_pending")
                        try:
                            await client.delete_floating_ip(record.id, zone)
                            await db.update_managed_resource_state(db_path, record.id, "deleted")
                        except Exception as exc:
                            await db.update_managed_resource_state(db_path, record.id, "delete_error")
                            log.warning(
                                "[%s] реконсилятор: не удалось удалить собственный IP %s: %r",
                                account.label, record.address, exc,
                            )

    async def reconciler_loop() -> None:
        while not stop_event.is_set():
            finished = await _sleep_cancellable(settings.reconciler_interval_seconds, stop_event)
            if not finished:
                break
            try:
                await reconcile_once()
            except Exception:
                log.exception("[%s] реконсилятор упал с необработанным исключением", account.label)

    try:
        client = await client_factory(account)
    except Exception as exc:  # аутентификация/сеть при старте
        log.error("[%s] не удалось создать Selectel-клиент: %r", account.label, exc)
        await db.update_account_status(db_path, account.id, "error", f"Ошибка подключения: {exc}")
        await db.set_account_desired_running(db_path, account.id, False)
        return

    reconciler_task: asyncio.Task | None = None
    try:
        await db.update_account_status(db_path, account.id, "running", "старт")
        log.info("[%s] воркер запущен, зоны: %s", account.label, ", ".join(account.selected_zones))

        if settings.reconciler_interval_seconds > 0:
            reconciler_task = asyncio.create_task(reconciler_loop())

        while not stop_event.is_set():
            circuit = await db.get_service_circuit(db_path)
            if circuit.get("open_until"):
                try:
                    circuit_until = datetime.fromisoformat(circuit["open_until"])
                    circuit_wait = max(1.0, (circuit_until - datetime.now(timezone.utc)).total_seconds())
                except (TypeError, ValueError):
                    circuit_wait = 1.0
                await db.update_account_status(
                    db_path, account.id, "cooldown",
                    f"общая пауза Selectel API: {circuit.get('reason') or 'rate limit'}",
                    cooldown_until=circuit["open_until"],
                )
                if not await _sleep_cancellable(min(circuit_wait, 5.0), stop_event):
                    break
                continue

            if state.is_cooling_down():
                # Account-wide cooldown (429 / квота / самоограничение по burst) —
                # это подтверждённо общий лимит на аккаунт, блокирует все зоны сразу.
                wait_s = state.seconds_until_ready()
                cooldown_until_iso = state.backoff_until.isoformat() if state.backoff_until else None
                await db.update_account_status(
                    db_path, account.id, "cooldown", f"cooldown, осталось ~{int(wait_s)}с",
                    cooldown_until=cooldown_until_iso,
                )
                log.warning(
                    "[%s] ушёл в cooldown на ~%.0fс (создано в текущей пачке: %d/%d, подряд ошибок: %d)",
                    account.label, wait_s, state.creates_in_burst,
                    state.burst_limit, state.consecutive_errors,
                )
                finished = await _sleep_cancellable(wait_s, stop_event)
                if not finished:
                    break
                log.info("[%s] cooldown окончен, продолжаю", account.label)
                continue

            zone, wait_hint = pick_ready_zone()
            if zone is None:
                # Все выбранные зоны сейчас в личном сетевом карантине —
                # по факту это уже account-wide простой, показываем как cooldown.
                soonest_until = min(
                    (zs.cooldown_until for zs in zone_states.values() if zs.cooldown_until is not None),
                    default=None,
                )
                cooldown_until_iso = soonest_until.isoformat() if soonest_until else None
                await db.update_account_status(
                    db_path, account.id, "cooldown",
                    f"все зоны временно недоступны (сетевые ошибки), жду ~{int(wait_hint)}с",
                    cooldown_until=cooldown_until_iso,
                )
                log.warning(
                    "[%s] все выбранные зоны (%s) сейчас в карантине из-за сетевых ошибок — жду ~%.0fс",
                    account.label, ", ".join(account.selected_zones), wait_hint,
                )
                finished = await _sleep_cancellable(min(wait_hint, 30.0), stop_event)
                if not finished:
                    break
                continue

            if rate_window is not None:
                rate_wait = rate_window.wait_seconds()
                if rate_wait > 0:
                    await db.update_account_status(
                        db_path, account.id, "running",
                        f"темп запросов: жду ~{int(rate_wait) + 1}с (лимит {settings.max_creates_per_minute}/мин)",
                    )
                    finished = await _sleep_cancellable(min(rate_wait, 15.0), stop_event)
                    if not finished:
                        break
                    continue

            has_turn, scheduler_wait = await db.claim_create_turn(
                db_path, account.id, lease_seconds=settings.scheduler_lease_seconds,
            )
            if not has_turn:
                if not await _sleep_cancellable(scheduler_wait, stop_event):
                    break
                continue
            state.last_request_at = datetime.now(timezone.utc)
            await persist_runtime()

            try:
                operation_id = await db.reserve_create_operation(
                    db_path, account.id,
                    daily_limit=max(1, settings.max_create_operations_per_day),
                    active_limit=max(1, settings.max_active_managed_ips),
                    minute_limit=max(1, settings.max_creates_per_minute),
                    cost_per_ip_hour_rub=settings.floating_ip_cost_per_hour_rub,
                    max_estimated_daily_cost_rub=settings.max_estimated_daily_cost_rub,
                    max_estimated_hourly_cost_rub=settings.max_estimated_hourly_cost_rub,
                )
            except db.GlobalCreateRateWait as exc:
                await db.release_create_turn(db_path, account.id)
                await db.update_account_status(db_path, account.id, "running", f"общий лимит сервиса: пауза ~{int(exc.seconds) + 1}с")
                finished = await _sleep_cancellable(exc.seconds, stop_event)
                if not finished:
                    break
                continue
            except ValueError as exc:
                await db.release_create_turn(db_path, account.id)
                log.warning("[%s] остановлен предохранителем: %s", account.label, exc)
                await db.set_account_desired_running(db_path, account.id, False)
                await db.update_account_status(db_path, account.id, "error", str(exc))
                break

            if rate_window is not None:
                rate_window.record()
            operation_resolved = False
            try:
                record = await client.create_floating_ip(zone)
                await db.release_create_turn(db_path, account.id)
                if not record.id or not record.address:
                    await db.finish_create_operation(db_path, operation_id, "uncertain")
                    raise RuntimeError("Selectel вернул Floating IP без ID или адреса; автоматическая обработка остановлена")
                # Persist ownership immediately after the successful response,
                # before whitelist processing or any possible delete.
                await db.register_managed_resource(
                    db_path, account_id=account.id, account_label=account.label,
                    project_id=account.project_id, zone=zone, ip=record.address, neutron_id=record.id,
                )
                await db.finish_create_operation(db_path, operation_id, "created")
                operation_resolved = True
                on_successful_create(state, strategy_config)
                on_zone_success(zone_states[zone])
                state.last_success_at = datetime.now(timezone.utc)
                await persist_runtime()
            except asyncio.CancelledError:
                # The remote POST may have succeeded even though stop timed
                # out locally. Keep the reservation conservative for manual
                # reconciliation and always free the scheduler lease.
                await db.release_create_turn(db_path, account.id)
                if not operation_resolved:
                    await db.finish_create_operation(db_path, operation_id, "uncertain")
                raise
            except SelectelRateLimitError as exc:
                await db.release_create_turn(db_path, account.id)
                await db.finish_create_operation(db_path, operation_id, "rate_limited")
                on_rate_limit_429(state, strategy_config, retry_after=exc.retry_after)
                global_until = await db.register_rate_limit(
                    db_path, account_id=account.id, retry_after=exc.retry_after,
                    window_seconds=settings.global_429_window_seconds,
                    global_threshold_accounts=settings.global_429_threshold_accounts,
                    fallback_pause_seconds=int(settings.cooldown_429_seconds),
                )
                on_zone_success(zone_states[zone])  # хост зоны ответил — сетевой проблемы с ним нет
                await persist_runtime()
                log.warning(
                    "[%s] 429 Too Many Requests (зона %s), retry_after=%s — уйду в cooldown ~%.0fс, burst_limit -> %d",
                    account.label, zone, exc.retry_after, state.seconds_until_ready(), state.burst_limit,
                )
                await db.log_attempt(
                    db_path, account_id=account.id, zone=zone, ip=None,
                    result="error", http_status=429, detail=str(exc),
                )
                await db.record_operation_event(db_path, account_id=account.id, region=zone, outcome="rate_limited")
                if global_until:
                    log.warning("Общая пауза Selectel API до %s: 429 пришёл в нескольких аккаунтах", global_until)
                await db.bump_account_counters(db_path, account.id, attempts=1)
                continue
            except SelectelQuotaError as exc:
                await db.release_create_turn(db_path, account.id)
                await db.finish_create_operation(db_path, operation_id, "api_error")
                on_quota_4xx(state, strategy_config)
                on_zone_success(zone_states[zone])  # хост зоны ответил — сетевой проблемы с ним нет
                await persist_runtime()
                log.warning(
                    "[%s] квота/4xx ошибка (зона %s, HTTP %s): %s — cooldown ~%.0fс, burst_limit -> %d",
                    account.label, zone, exc.status_code, exc, state.seconds_until_ready(), state.burst_limit,
                )
                await db.log_attempt(
                    db_path, account_id=account.id, zone=zone, ip=None,
                    result="error", http_status=exc.status_code, detail=str(exc),
                )
                await db.record_operation_event(db_path, account_id=account.id, region=zone, outcome=f"http_{exc.status_code}")
                await db.bump_account_counters(db_path, account.id, attempts=1)
                continue
            except SelectelAuthError as exc:
                await db.release_create_turn(db_path, account.id)
                await db.finish_create_operation(db_path, operation_id, "auth_error")
                log.error("[%s] ошибка аутентификации, останавливаю воркер: %r", account.label, exc)
                await db.update_account_status(db_path, account.id, "error", f"Auth error: {exc}")
                await db.set_account_desired_running(db_path, account.id, False)
                break
            except SelectelRequestError as exc:
                await db.release_create_turn(db_path, account.id)
                await db.finish_create_operation(db_path, operation_id, "request_error")
                await db.log_attempt(db_path, account_id=account.id, zone=zone, ip=None,
                                     result="error", http_status=exc.status_code, detail=str(exc))
                await db.record_operation_event(db_path, account_id=account.id, region=zone, outcome=f"http_{exc.status_code}")
                await db.update_account_status(db_path, account.id, "error", f"Ошибка запроса Selectel HTTP {exc.status_code}: {exc}")
                await db.set_account_desired_running(db_path, account.id, False)
                break
            except Exception as exc:  # сетевые и прочие непредвиденные — карантин только для этой зоны
                await db.release_create_turn(db_path, account.id)
                await db.finish_create_operation(db_path, operation_id, "uncertain")
                if isinstance(exc, (httpx.RequestError, httpx.HTTPStatusError)):
                    await db.register_provider_failure(
                        db_path, account_id=account.id, error_class=type(exc).__name__,
                        window_seconds=settings.global_429_window_seconds,
                        threshold_accounts=settings.global_429_threshold_accounts,
                        pause_seconds=60,
                    )
                zstate = zone_states[zone]
                escalated = on_zone_network_error(zstate, strategy_config)
                await persist_runtime()
                escalated_note = (
                    f" — зона уходит в карантин на ~{int(zstate.seconds_until_ready())}с "
                    f"(после {strategy_config.network_error_escalate_after} сетевых ошибок подряд именно в ней; "
                    f"карантинов подряд без успеха: {zstate.quarantine_count}; "
                    f"остальные зоны аккаунта продолжают работать)"
                    if escalated else ""
                )
                log.warning(
                    "[%s] сетевая/непредвиденная ошибка (зона %s): %r — пауза для этой зоны ~%.0fс%s",
                    account.label, zone, exc, zstate.seconds_until_ready(), escalated_note,
                )
                await db.log_attempt(
                    db_path, account_id=account.id, zone=zone, ip=None,
                    result="error", detail=repr(exc),
                )
                await db.record_operation_event(db_path, account_id=account.id, region=zone, outcome="network_error")
                await db.bump_account_counters(db_path, account.id, attempts=1)

                if (
                    escalated
                    and zstate.quarantine_count >= settings.zone_outage_alert_after
                    and not zstate.alert_sent
                    and settings.telegram_bot_token and settings.telegram_chat_id
                ):
                    zstate.alert_sent = True  # шлём один раз за весь эпизод простоя, не на каждой эскалации
                    city = zone_catalog.city_of(zone) if zone_catalog is not None else None
                    text = format_zone_down_message(
                        account_label=account.label, zone=zone, city=city or zone,
                        quarantine_count=zstate.quarantine_count,
                        cooldown_seconds=zstate.seconds_until_ready(),
                    )
                    spawn_background(notify_in_background(text, f"простой зоны {zone}"))
                continue

            try:
                match = whitelist.check(record.address)
            except Exception as exc:
                await db.record_ip_check_error(
                    db_path, ip=record.address, account_id=account.id, region=zone, error=repr(exc),
                )
                await db.log_attempt(
                    db_path, account_id=account.id, zone=zone, ip=record.address,
                    result="error", http_status=201, neutron_id=record.id,
                    detail=f"Ошибка локальной проверки CIDR; IP оставлен без удаления: {exc!r}",
                )
                await db.bump_account_counters(db_path, account.id, attempts=1)
                log.exception("[%s] проверка CIDR для %s завершилась ошибкой; ресурс сохранён", account.label, record.address)
                continue
            await db.record_ip_observation(db_path, ip=record.address, account_id=account.id,
                                           region=zone, match=match, neutron_id=record.id)
            if match is not None:
                await db.update_managed_resource_state(db_path, record.id, "protected")
                await db.log_attempt(
                    db_path, account_id=account.id, zone=zone, ip=record.address,
                    result="match", http_status=201, neutron_id=record.id,
                    detail=f"cidr={match.cidr}",
                )
                await db.add_found_ip(
                    db_path, account_id=account.id, ip=record.address, zone=zone,
                    city=match.zone, cidr_matched=match.cidr, neutron_id=record.id,
                )
                await db.bump_account_counters(db_path, account.id, attempts=1, matches=1)
                log.info("[%s] MATCH: %s (зона %s, cidr %s) — оставлен", account.label, record.address, zone, match.cidr)

                if settings.telegram_bot_token and settings.telegram_chat_id:
                    text = format_found_message(
                        account_label=account.label, ip=record.address, zone=zone,
                        city=match.zone, cidr=match.cidr,
                    )
                    spawn_background(notify_in_background(text, f"IP {record.address}"))
            else:
                # Удаление miss-IP уходит в фон — не ждём подтверждения
                # delete перед следующим create, только семафор ограничивает,
                # сколько delete-запросов летит одновременно.
                spawn_background(delete_miss_ip(record, zone))

            await db.update_account_status(
                db_path, account.id, "running", f"зона {zone}, burst {state.creates_in_burst}/{state.burst_limit}"
            )
    finally:
        if reconciler_task is not None:
            reconciler_task.cancel()
            try:
                await reconciler_task
            except asyncio.CancelledError:
                pass
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)
        await client.close()
        if not stop_event.is_set():
            # вышли не по явной остановке (например, auth error) - статус уже проставлен выше
            pass
        else:
            log.info("[%s] воркер остановлен пользователем", account.label)
            await db.update_account_status(db_path, account.id, "stopped", "остановлено пользователем")
