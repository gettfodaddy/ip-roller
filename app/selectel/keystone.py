"""
keystone.py

Общая часть аутентификации Selectel (OpenStack Keystone v3) — используется
и для account-scoped токена (Resell API), и для project-scoped токена
(Neutron floating ip). Основано на рабочей логике из bymakk/selectel_roller,
но без verify=False — TLS проверяется как обычно.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .errors import SelectelAuthError

IDENTITY_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"


def account_scoped_payloads(username: str, password: str, account_id: str) -> list[dict[str, Any]]:
    """Selectel принимает domain и как name, и как id — пробуем оба варианта."""
    payloads = []
    for domain_key in ("name", "id"):
        payloads.append(
            {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": username,
                                "password": password,
                                "domain": {domain_key: account_id},
                            }
                        },
                    },
                    "scope": {"domain": {domain_key: account_id}},
                }
            }
        )
    return payloads


def project_scoped_payloads(
    username: str, password: str, account_id: str, *, project_id: str = "", project_name: str = ""
) -> list[dict[str, Any]]:
    if not project_id and not project_name:
        raise ValueError("Нужен project_id или project_name для project-scoped токена")

    payloads = []
    for domain_key in ("name", "id"):
        if project_id:
            project_scope: dict[str, Any] = {"project": {"id": project_id, "domain": {domain_key: account_id}}}
        else:
            project_scope = {"project": {"name": project_name, "domain": {domain_key: account_id}}}

        payloads.append(
            {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": username,
                                "password": password,
                                "domain": {domain_key: account_id},
                            }
                        },
                    },
                    "scope": project_scope,
                }
            }
        )
    return payloads


def parse_expiration(payload: dict[str, Any]) -> datetime | None:
    raw = str(payload.get("token", {}).get("expires_at", "")).strip()
    if not raw:
        return None
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


async def request_token(client: httpx.AsyncClient, payloads: list[dict[str, Any]]) -> tuple[str, datetime | None, dict[str, Any]]:
    """Пробует по очереди payload-варианты (domain name/id), возвращает
    (token, expires_at, полное тело ответа) первого удавшегося."""
    last_error: Exception | None = None
    for payload in payloads:
        try:
            response = await client.post(IDENTITY_URL, json=payload)
        except httpx.HTTPError as exc:
            last_error = exc
            continue
        if response.status_code in (400, 401, 403):
            last_error = SelectelAuthError(
                f"Keystone auth failed: HTTP {response.status_code} — {response.text[:300]}"
            )
            continue
        response.raise_for_status()
        token = response.headers.get("X-Subject-Token", "").strip()
        if not token:
            raise SelectelAuthError("Keystone вернул 2xx, но без заголовка X-Subject-Token")
        body = response.json()
        return token, parse_expiration(body), body

    raise SelectelAuthError(
        "Не удалось получить IAM-токен — проверьте username/password/account_id"
    ) from last_error


def token_still_valid(expires_at: datetime | None, *, margin_minutes: int = 5) -> bool:
    if expires_at is None:
        return False
    return datetime.now(timezone.utc) < (expires_at - timedelta(minutes=margin_minutes))
