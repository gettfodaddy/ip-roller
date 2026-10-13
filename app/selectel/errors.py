from __future__ import annotations


class SelectelError(Exception):
    """Базовая ошибка Selectel-клиента."""


class SelectelAuthError(SelectelError):
    """Не удалось получить IAM-токен (неверный логин/пароль/account_id/scope)."""


class SelectelRateLimitError(SelectelError):
    """429 Too Many Requests — сработал rate limit Selectel."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class SelectelQuotaError(SelectelError):
    """Ответ API, который может означать временную квоту или конфликт."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


class SelectelRequestError(SelectelError):
    """Некорректный/запрещённый запрос: не повторять его циклически."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code
