"""
neutron.py

Floating IP через чистый OpenStack Neutron — это то, что реально стоит за
UI "Плавающие IP" в панели Selectel. Требует project-scoped IAM-токен;
URL Neutron для каждого региона берётся динамически из service catalog
токена (никакого региона в теле запроса нет — регион определяется тем,
в какой Neutron-эндпоинт стучимся).

Основано на client.py из bymakk/selectel_roller, с исправлениями:
  - TLS проверяется как обычно (никакого verify=False)
  - 429 и прочие 4xx поднимаются как типизированные исключения
    (SelectelRateLimitError / SelectelQuotaError), а не просто HTTPStatusError —
    чтобы strategy.py мог отличить "подожди 8 минут" от прочих ошибок.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from . import keystone
from .errors import SelectelAuthError, SelectelQuotaError, SelectelRateLimitError, SelectelRequestError
from .models import FloatingIPRecord


class SelectelNeutronClient:
    def __init__(
        self,
        *,
        username: str,
        password: str,
        account_id: str,
        project_id: str = "",
        project_name: str = "",
        timeout: float = 30.0,
    ):
        self.username = username.strip()
        self.password = password
        self.account_id = account_id.strip()
        self.project_id = project_id.strip()
        self.project_name = project_name.strip()

        self._token = ""
        self._expires = None
        self._auth_lock = asyncio.Lock()
        self._neutron_urls: dict[str, str] = {}
        self._external_network_ids: dict[str, str] = {}
        self._resource_regions: dict[str, str] = {}

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    def available_regions(self) -> tuple[str, ...]:
        return tuple(self._neutron_urls.keys())

    async def ensure_authenticated(self) -> None:
        if keystone.token_still_valid(self._expires):
            return
        async with self._auth_lock:
            if keystone.token_still_valid(self._expires):
                return
            payloads = keystone.project_scoped_payloads(
                self.username, self.password, self.account_id,
                project_id=self.project_id, project_name=self.project_name,
            )
            self._token, self._expires, body = await keystone.request_token(self._client, payloads)
            token_project = body.get("token", {}).get("project", {})
            resolved_id = str(token_project.get("id", "")).strip()
            if resolved_id:
                self.project_id = resolved_id
            self._apply_service_catalog(body)

    def _apply_service_catalog(self, body: dict[str, Any]) -> None:
        self._neutron_urls = {}
        for service in body.get("token", {}).get("catalog", []):
            if str(service.get("type", "")).strip().lower() != "network":
                continue
            for endpoint in service.get("endpoints", []):
                if endpoint.get("interface") != "public":
                    continue
                region = str(endpoint.get("region_id") or endpoint.get("region") or "").strip()
                url = str(endpoint.get("url", "")).rstrip("/")
                if region and url:
                    self._neutron_urls[region] = url

    def _neutron_url(self, region: str) -> str:
        url = self._neutron_urls.get(region, "")
        if not url:
            raise SelectelAuthError(
                f"В service catalog нет Neutron-эндпоинта для региона '{region}' "
                f"(доступно: {sorted(self._neutron_urls)}) — либо region не подключён проекту, "
                f"либо опечатка в коде зоны"
            )
        return url

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "Content-Type": "application/json", "X-Auth-Token": self._token}

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        await self.ensure_authenticated()
        response = await self._client.request(method, url, headers=self._headers(), **kwargs)

        if response.status_code == 401:
            self._token, self._expires = "", None
            await self.ensure_authenticated()
            response = await self._client.request(method, url, headers=self._headers(), **kwargs)

        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            retry_seconds = None
            if retry_after:
                try:
                    retry_seconds = max(0.0, float(retry_after))
                except ValueError:
                    try:
                        retry_at = parsedate_to_datetime(retry_after)
                        if retry_at.tzinfo is None:
                            retry_at = retry_at.replace(tzinfo=timezone.utc)
                        retry_seconds = max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())
                    except (TypeError, ValueError, OverflowError):
                        retry_seconds = None
            raise SelectelRateLimitError(
                f"429 Too Many Requests: {response.text[:200]}",
                retry_after=retry_seconds,
            )
        if 400 <= response.status_code < 500:
            error_type = SelectelQuotaError if response.status_code in {402, 409} else SelectelRequestError
            raise error_type(f"HTTP {response.status_code}: {response.text[:200]}", status_code=response.status_code)
        response.raise_for_status()
        return response

    async def _get_external_network_id(self, region: str) -> str:
        cached = self._external_network_ids.get(region, "")
        if cached:
            return cached
        response = await self._request(
            "GET", f"{self._neutron_url(region)}/v2.0/networks",
            params={"router:external": True, "status": "ACTIVE"},
        )
        networks = response.json().get("networks", [])
        if not networks:
            raise SelectelAuthError(f"В регионе '{region}' нет активных external-сетей для этого проекта")
        if len(networks) != 1:
            raise SelectelRequestError(
                f"В регионе '{region}' найдено {len(networks)} external-сетей; автоматический выбор неоднозначен",
                status_code=409,
            )
        network_id = str(networks[0].get("id", "")).strip()
        self._external_network_ids[region] = network_id
        return network_id

    async def create_floating_ip(self, region: str) -> FloatingIPRecord:
        network_id = await self._get_external_network_id(region)
        response = await self._request(
            "POST", f"{self._neutron_url(region)}/v2.0/floatingips",
            json={"floatingip": {"floating_network_id": network_id}},
        )
        payload = response.json().get("floatingip", {})
        record = FloatingIPRecord.from_payload({**payload, "region": region})
        if record.id:
            self._resource_regions[record.id] = region
        return record

    async def delete_floating_ip(self, floating_ip_id: str, region: str) -> bool:
        try:
            await self._request("DELETE", f"{self._neutron_url(region)}/v2.0/floatingips/{floating_ip_id}")
            self._resource_regions.pop(floating_ip_id, None)
            return True
        except SelectelQuotaError as exc:
            if exc.status_code == 404:
                self._resource_regions.pop(floating_ip_id, None)
                return False
            raise
        except SelectelRequestError as exc:
            if exc.status_code == 404:
                self._resource_regions.pop(floating_ip_id, None)
                return False
            raise

    async def list_floating_ips(self, region: str) -> list[FloatingIPRecord]:
        base_url = f"{self._neutron_url(region)}/v2.0/floatingips"
        url = base_url
        records: list[FloatingIPRecord] = []
        seen_urls: set[str] = set()
        for _ in range(1000):
            if url in seen_urls:
                raise RuntimeError("Neutron вернул повторяющуюся ссылку пагинации Floating IP")
            seen_urls.add(url)
            response = await self._request("GET", url)
            body = response.json()
            items = body.get("floatingips", [])
            records.extend(FloatingIPRecord.from_payload({**item, "region": region}) for item in items if isinstance(item, dict))
            next_href = next((link.get("href") for link in body.get("floatingips_links", []) if link.get("rel") == "next"), None)
            if not next_href:
                break
            next_url = urljoin(url, str(next_href))
            parsed_next, parsed_base = urlparse(next_url), urlparse(base_url)
            if parsed_next.scheme != parsed_base.scheme or parsed_next.netloc != parsed_base.netloc:
                raise RuntimeError("Neutron pagination URL points outside the authenticated endpoint")
            url = next_url
        else:
            raise RuntimeError("Слишком много страниц списка Floating IP")
        for record in records:
            if record.id:
                self._resource_regions[record.id] = region
        return records
