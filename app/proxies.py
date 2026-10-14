"""Validated HTTP CONNECT proxies; network failures never replay a request."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

log = logging.getLogger('ip-roller.proxy')


def load_candidates(path: Path) -> list[str]:
    """Accept public numeric HTTP proxy endpoints, one per line."""
    candidates = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue
        url = raw if '://' in raw else 'http://' + raw
        try:
            parsed = urlsplit(url)
            address = ipaddress.ip_address(parsed.hostname or '')
            valid = (parsed.scheme == 'http' and address.is_global and parsed.port
                     and not parsed.username and not parsed.password
                     and parsed.path in {'', '/'} and not parsed.query and not parsed.fragment)
        except ValueError:
            valid = False
        if valid and url not in candidates:
            candidates.append(url)
    return candidates[:100]


async def check_proxy(url: str, zones: list[str], timeout: float = 8) -> bool:
    """Two complete passes, no credentials, TLS verification always enabled."""
    endpoints = [('https://cloud.api.selcloud.ru/identity/v3/auth/tokens', {401})]
    endpoints += [(f'https://{zone}.cloud.api.selcloud.ru/', {200, 401, 403, 404})
                  for zone in zones if zone in {'ru-1', 'ru-2', 'ru-3', 'ru-7', 'ru-8', 'ru-9'}]
    # Do not silently validate an unrecognised region.
    if len(endpoints) != len(zones) + 1:
        return False
    try:
        async with httpx.AsyncClient(proxy=url, verify=True, trust_env=False,
                                     timeout=timeout, follow_redirects=False) as client:
            for attempt in range(1, 3):
                for endpoint, accepted in endpoints:
                    started = time.monotonic()
                    log.info('Проверка прокси=%s проход=%s API=%s', url, attempt, urlsplit(endpoint).hostname)
                    async with client.stream('GET', endpoint) as response:
                        log.info('Проверка прокси=%s API=%s HTTP=%s время=%.2fс', url, urlsplit(endpoint).hostname, response.status_code, time.monotonic() - started)
                        if response.status_code not in accepted:
                            log.warning('Прокси=%s отклонён: неожиданный HTTP=%s API=%s', url, response.status_code, urlsplit(endpoint).hostname)
                            return False
                        if endpoint.endswith('/auth/tokens') and 'Keystone' not in response.headers.get('www-authenticate', ''):
                            log.warning('Прокси=%s отклонён: IAM не вернул ожидаемый заголовок Keystone', url)
                            return False
        log.info('Прокси=%s прошёл два прохода проверки зон=%s', url, ','.join(zones))
        return True
    except (httpx.HTTPError, OSError, ValueError) as exc:
        reason = 'TLS certificate verification failed' if 'CERTIFICATE_VERIFY_FAILED' in str(exc) else type(exc).__name__
        log.warning('Прокси=%s отклонён: API=%s причина=%s', url, urlsplit(endpoint).hostname, reason)
        return False


class ProxyPool:
    def __init__(self, path: Path, *, threshold=3, quarantine=900, retry=60):
        self.path = path
        self.threshold = max(1, threshold)
        self.quarantine = max(60, quarantine)
        self.retry = max(10, retry)
        self.lock = asyncio.Lock()
        self.leased = set()
        self.rejected = {}

    async def acquire(self, zones, status):
        while True:
            await status('cooldown', 'Автопауза: проверка и подбор прокси')
            async with self.lock:
                try:
                    candidates = load_candidates(self.path)
                except OSError:
                    log.warning('Не удалось прочитать файл кандидатов прокси')
                    candidates = []
                for candidate in candidates:
                    if candidate in self.leased or self.rejected.get(candidate, 0) > time.monotonic():
                        continue
                    if await check_proxy(candidate, zones):
                        self.leased.add(candidate)
                        return candidate
                    self.rejected[candidate] = time.monotonic() + self.quarantine
            await status('cooldown', 'Автопауза: нет проверенного прокси; ожидание обновления пула')
            log.info('Нет свободного проверенного прокси; кандидатов=%s занятых=%s повтор через=%sс', len(candidates), len(self.leased), self.retry)
            await asyncio.sleep(self.retry)

    def release(self, url, *, failed=False):
        self.leased.discard(url)
        if failed:
            self.rejected[url] = time.monotonic() + self.quarantine


class CheckedProxyTransport(httpx.AsyncBaseTransport):
    """Serialise account traffic across IAM, creation, cleanup and reconciliation."""
    def __init__(self, pool, zones, status, stop_event=None, account_label='unknown'):
        self.pool, self.zones, self.status = pool, zones, status
        self.account_label = account_label
        self.stop_event = stop_event
        self.lock = asyncio.Lock()
        self.transport = None
        self.url = None
        self.failures = 0
        self.closed = False

    async def acquire_cancellable(self):
        if self.stop_event is None:
            return await self.pool.acquire(self.zones, self.status)
        if self.stop_event.is_set():
            raise asyncio.CancelledError
        selection = asyncio.create_task(self.pool.acquire(self.zones, self.status))
        stopped = asyncio.create_task(self.stop_event.wait())
        adopted = False
        try:
            await asyncio.wait([selection, stopped], return_when=asyncio.FIRST_COMPLETED)
            if self.stop_event.is_set():
                raise asyncio.CancelledError
            result = await selection
            adopted = True
            return result
        finally:
            selection.cancel()
            stopped.cancel()
            results = await asyncio.gather(selection, stopped, return_exceptions=True)
            if not adopted and isinstance(results[0], str):
                self.pool.release(results[0])

    async def handle_async_request(self, request):
        async with self.lock:
            if self.closed:
                raise httpx.ConnectError('Proxy transport closed', request=request)
            if self.transport is None:
                self.url = await self.acquire_cancellable()
                self.transport = httpx.AsyncHTTPTransport(proxy=self.url, verify=True, retries=0)
                self.failures = 0
                log.info('[%s] Активный прокси=%s зоны=%s', self.account_label, self.url, ','.join(self.zones))
                await self.status('running', 'Прокси проверен и установлен; работа возобновлена')
            started = time.monotonic()
            try:
                response = await self.transport.handle_async_request(request)
                try:
                    await response.aread()
                finally:
                    await response.aclose()
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                    httpx.WriteTimeout, httpx.ReadError, httpx.WriteError, httpx.ProxyError) as exc:
                self.failures += 1
                log.warning('[%s] Прокси=%s метод=%s API=%s ошибка=%s подряд=%s/%s время=%.2fс', self.account_label, self.url, request.method, request.url.host, type(exc).__name__, self.failures, self.pool.threshold, time.monotonic() - started)
                if self.failures >= self.pool.threshold:
                    log.warning('[%s] Прокси=%s исключён на %sс; подбор замены; запрос не повторяется', self.account_label, self.url, self.pool.quarantine)
                    self.pool.release(self.url, failed=True)
                    self.url = None
                    old, self.transport = self.transport, None
                    await old.aclose()
                    await self.status('cooldown', 'Автопауза: серия сетевых отказов; требуется новый прокси')
                # Especially POST: never replay after an ambiguous failure.
                raise
            self.failures = 0
            log.info('[%s] Прокси=%s метод=%s API=%s HTTP=%s время=%.2fс', self.account_label, self.url, request.method, request.url.host, response.status_code, time.monotonic() - started)
            # HTTP 429/401/403 do not trigger proxy rotation.
            return response

    async def aclose(self):
        self.closed = True
        if self.url:
            log.info('[%s] Прокси=%s освобождён при закрытии клиента', self.account_label, self.url)
            self.pool.release(self.url, failed=self.failures > 0)
            self.url = None
        if self.transport:
            await self.transport.aclose()
            self.transport = None
