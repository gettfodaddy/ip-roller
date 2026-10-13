"""Encryption at rest for provider credentials stored in SQLite."""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"


def _fernet() -> Fernet:
    key = os.environ.get("CREDENTIALS_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("Задайте CREDENTIALS_ENCRYPTION_KEY в .env; создайте ключ командой из DEPLOY.md")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("CREDENTIALS_ENCRYPTION_KEY имеет неверный формат Fernet") from exc


def encrypt_password(value: str) -> str:
    if value.startswith(PREFIX):
        return value
    return PREFIX + _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_password(value: str) -> str:
    if not value.startswith(PREFIX):
        raise RuntimeError("В БД найден незашифрованный пароль; перезапустите миграцию с CREDENTIALS_ENCRYPTION_KEY")
    try:
        return _fernet().decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError) as exc:
        raise RuntimeError("Не удалось расшифровать пароль Selectel: проверьте CREDENTIALS_ENCRYPTION_KEY") from exc
