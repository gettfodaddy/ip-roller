"""
resell.py

VPC Resell API v2 — используется только для поиска/создания проекта.
Требует account-scoped (domain-scoped) IAM-токен -> роль "Администратор
аккаунта" на сервисном пользователе. Если проект уже создан вручную и
project_id известен — этот клиент вообще не нужен (см. account_setup.py).
"""

from __future__ import annotations

from typing import Any

import httpx

from . import keystone
from .models import ResellProject

RESELL_BASE_URL = "https://api.selectel.ru/vpc/resell/v2"


class SelectelResellClient:
    def __init__(self, *, username: str, password: str, account_id: str, timeout: float = 20.0):
        self.username = username.strip()
        self.password = password
        self.account_id = account_id.strip()
        self._token = ""
        self._expires = None
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _ensure_token(self) -> None:
        if keystone.token_still_valid(self._expires):
            return
        payloads = keystone.account_scoped_payloads(self.username, self.password, self.account_id)
        self._token, self._expires, _ = await keystone.request_token(self._client, payloads)

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "Content-Type": "application/json", "X-Auth-Token": self._token}

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        await self._ensure_token()
        url = f"{RESELL_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
        response = await self._client.request(method, url, headers=self._headers(), **kwargs)
        if response.status_code == 401:
            self._token, self._expires = "", None
            await self._ensure_token()
            response = await self._client.request(method, url, headers=self._headers(), **kwargs)
        response.raise_for_status()
        return response

    async def list_projects(self) -> list[ResellProject]:
        response = await self._request("GET", "/projects")
        items = response.json().get("projects", [])
        return [ResellProject.from_payload(i) for i in items if isinstance(i, dict) and i.get("id")]

    async def create_project(self, name: str, *, description: str = "") -> ResellProject:
        safe_name = (name or "ip-roller").strip()[:64]
        payload: dict[str, Any] = {"project": {"name": safe_name}}
        if description:
            payload["project"]["description"] = description[:255]
        response = await self._request("POST", "/projects", json=payload)
        return ResellProject.from_payload(response.json().get("project") or {})

    async def find_or_create_project(self, name: str) -> ResellProject:
        for project in await self.list_projects():
            if project.name == name:
                return project
        return await self.create_project(name)
