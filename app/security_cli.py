"""
security_cli.py

Утилита из командной строки — сгенерировать bcrypt-хэш пароля для
ADMIN_PASSWORD_HASH в .env (в plaintext пароль в .env класть не надо).

Использование:
    python3 -m app.security_cli hash-password 'мой_пароль'
"""

from __future__ import annotations

import sys
from getpass import getpass

from .security import hash_password


def main() -> None:
    if len(sys.argv) not in (2, 3) or sys.argv[1] != "hash-password":
        print("Использование: python3 -m app.security_cli hash-password [пароль]")
        raise SystemExit(1)
    password = sys.argv[2] if len(sys.argv) == 3 else getpass("Новый пароль администратора: ")
    if len(sys.argv) == 2:
        confirmation = getpass("Повторите пароль: ")
        if password != confirmation:
            raise SystemExit("Пароли не совпали")
    if not password or len(password) < 14:
        raise SystemExit("Задайте пароль длиной не менее 14 символов")
    print(hash_password(password))


if __name__ == "__main__":
    main()
