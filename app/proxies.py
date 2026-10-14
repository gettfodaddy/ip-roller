"""Validated HTTP CONNECT proxies; network failures never replay a request."""
from __future__ import annotations

import asyncio
import ipaddress
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


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
            for _ in range(2):
                for endpoint, accepted in endpoints:
                    async with client.stream('GET', endpoint) as response:
                        if response.status_code not in accepted:
                            return False
                        if endpoint.endswith('/auth/tokens') and 'Keystone' not in response.headers.get('www-authenticate', ''):
                            return False
        return True
    except (httpx.HTTPError, OSError, ValueError):
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
                    candidates = []
                for candidate in candidates:
                    if candidate in self.leased or self.rejected.get(candidate, 0) > time.monotonic():
                        continue
                    if await check_proxy(candidate, zones):
                        self.leased.add(candidate)
                        return candidate
                    self.rejected[candidate] = time.monotonic() + self.quarantine
            await status('cooldown', 'Автопауза: нет проверенного прокси; ожидание обновления пула')
            await asyncio.sleep(self.retry)

    def release(self, url, *, failed=False):
        self.leased.discard(url)
        if failed:
            self.rejected[url] = time.monotonic() + self.quarantine


class CheckedProxyTransport(httpx.AsyncBaseTransport):
    """Serialise account traffic across IAM, creation, cleanup and reconciliation."""
    def __init__(self, pool, zones, status, stop_event=None):
        self.pool, self.zones, self.status = pool, zones, status
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
                await self.status('running', 'Прокси проверен и установлен; работа возобновлена')
            try:
                response = await self.transport.handle_async_request(request)
                try:
                    await response.aread()
                finally:
                    await response.aclose()
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                    httpx.WriteTimeout, httpx.ReadError, httpx.WriteError, httpx.ProxyError):
                self.failures += 1
                if self.failures >= self.pool.threshold:
                    self.pool.release(self.url, failed=True)
                    self.url = None
                    old, self.transport = self.transport, None
                    await old.aclose()
                    await self.status('cooldown', 'Автопауза: серия сетевых отказов; требуется новый прокси')
                # Especially POST: never replay after an ambiguous failure.
                raise
            self.failures = 0
            # HTTP 429/401/403 do not trigger proxy rotation.
            return response

    async def aclose(self):
        self.closed = True
        if self.url:
            self.pool.release(self.url, failed=self.failures > 0)
            self.url = None
        if self.transport:
            await self.transport.aclose()
            self.transport = None
