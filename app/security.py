"""
security.py

Простая аутентификация одним админ-паролем (как и в остальных ботах
этого проекта — не многопользовательская система). Сессия — подписанная
cookie через Starlette SessionMiddleware (secret из settings.session_secret),
без серверного хранилища сессий.
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import HTTPException
from passlib.hash import bcrypt
from starlette.requests import Request
from starlette.responses import RedirectResponse


def hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.verify(password, password_hash)
    except ValueError:
        return False


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


def login(request: Request) -> None:
    request.session.clear()
    request.session["authenticated"] = True


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


async def verify_csrf(request: Request) -> None:
    form = await request.form()
    supplied = str(form.get("csrf_token", ""))
    expected = str(request.session.get("csrf_token", ""))
    if not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail="CSRF token отсутствует или недействителен")


def logout(request: Request) -> None:
    request.session.clear()


def require_login(request: Request) -> RedirectResponse | None:
    """Вернуть redirect на /login, если не залогинен; иначе None — можно
    продолжать обработку. Вызывается в начале каждого защищённого route."""
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return None
