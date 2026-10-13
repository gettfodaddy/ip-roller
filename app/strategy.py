"""
strategy.py

Управление темпом запросов на аккаунт. Механизмы:

1. Самоограничение (проактивное) — не ждём реального 429, сами
   останавливаемся после `state.burst_limit` create подряд (стартует с
   `max_creates_per_burst`, дефолт 8, с запасом от подтверждённого порога
   в 10) и уходим в cooldown на `cooldown_429_seconds` (дефолт 480 = 8
   минут, по замеру пользователя). Это должно почти всегда предотвращать
   реальный 429.

   Размер пачки АДАПТИВНЫЙ (burst_limit на AccountState, не фиксированное
   число из конфига): после каждой "чистой" пачки без единой 429/квота
   ошибки — burst_limit чуть подрастает (мы, видимо, слишком консервативны
   для текущих условий), а при первом же реальном отказе — резко ужимается
   (сработали слишком агрессивно). Так каждый аккаунт нащупывает свой
   текущий потолок сам, а не использует один и тот же дефолт всегда.

2. Реактивный backoff на 429/quota (на случай, если самоограничение
   промахнулось, либо поведение отличается на конкретном аккаунте/дате) —
   если Selectel всё же вернул 429 или другой 4xx, берём минимум из
   конфига и экспоненциально растим при повторах, до cooldown_max_seconds.
   Идея растущего backoff — из strategy.py в bymakk/selectel_roller,
   калибровка цифр — по эмпирике из этого проекта (8 мин, не 60 сек).

3. Отдельный, ЗОННЫЙ backoff на сетевые ошибки (ZoneState / on_zone_*).
   Важно не путать его с (1)/(2): 429/quota у Selectel — подтверждённо
   ГЛОБАЛЬНЫЙ лимит на аккаунт (см. AccountState), а вот ConnectTimeout
   и подобные сетевые обрывы — это свойство КОНКРЕТНОГО регионального
   API-хоста конкретной зоны (ru-3.cloud.api.selcloud.ru — отдельный
   хост от ru-9.cloud.api.selcloud.ru), а не аккаунта целиком. На практике
   бывает так: одна зона стабильно не отвечает (просевший IPv6-маршрут до
   именно этого хоста), а остальные выбранные зоны работают нормально.
   Если тормозить весь аккаунт из-за одной битой зоны — роллер зря стоит,
   хотя мог бы продолжать крутить рабочие зоны. Поэтому у каждой зоны
   своё состояние (ZoneState) и свой личный "карантин", который не
   блокирует остальные зоны того же аккаунта.

4. Скользящее окно created/минуту (RateWindow) — независимо от (1),
   сглаживает сам темп запросов внутри пачки: вместо "рвани burst_limit
   штук подряд как можно быстрее, потом стой 8 минут" — равномерно
   размазывает попытки во времени. Это не заменяет self-throttle, а
   работает вместе с ним (более редкая, но более гладкая нагрузка на
   Selectel API снижает шанс поймать реальный 429 вообще).
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class AccountState:
    creates_in_burst: int = 0
    consecutive_errors: int = 0
    backoff_until: datetime | None = None
    last_result: str = ""
    # Адаптивный размер пачки — см. п.1 в докстринге модуля. Реальное
    # стартовое значение выставляется в roller.py из StrategyConfig
    # (AccountState(burst_limit=strategy_config.max_creates_per_burst)),
    # дефолт здесь — просто на случай прямого создания без параметра.
    burst_limit: int = 8
    last_request_at: datetime | None = None
    last_success_at: datetime | None = None

    def is_cooling_down(self) -> bool:
        return self.backoff_until is not None and datetime.now(timezone.utc) < self.backoff_until

    def seconds_until_ready(self) -> float:
        if self.backoff_until is None:
            return 0.0
        delta = (self.backoff_until - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)


@dataclass
class ZoneState:
    """Состояние сетевых ошибок ОДНОЙ зоны — независимо от остальных зон
    того же аккаунта и от account-wide 429/quota состояния (AccountState).

    quarantine_count считает, сколько РАЗ ПОДРЯД зона уходила в полный
    карантин без единого успеха между ними — сбрасывается в 0 при первом
    же успешном ответе от зоны (on_zone_success). Это отличает разовый
    обрыв (одна короткая пауза, потом всё ок) от затяжного простоя хоста
    на многие часы — во втором случае фиксированные 8 минут между
    попытками бессмысленно молотят в мёртвый хост всю ночь, поэтому
    каждый следующий карантин подряд длиннее предыдущего (см.
    on_zone_network_error / StrategyConfig.zone_quarantine_growth)."""
    consecutive_errors: int = 0
    cooldown_until: datetime | None = None
    quarantine_count: int = 0
    alert_sent: bool = False

    def is_cooling_down(self) -> bool:
        return self.cooldown_until is not None and datetime.now(timezone.utc) < self.cooldown_until

    def seconds_until_ready(self) -> float:
        if self.cooldown_until is None:
            return 0.0
        delta = (self.cooldown_until - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)


@dataclass
class RateWindow:
    """Скользящее окно на `window_seconds` секунд, не больше `limit`
    попыток внутри него — сглаживает темп запросов равномерно, в отличие
    от burst_limit (тот про "сколько подряд, потом длинный cooldown").

    Использование в roller.py: перед каждой попыткой create — спросить
    wait_seconds(); если > 0, подождать и не тратить попытку; иначе сразу
    после инициации запроса вызвать record()."""
    limit: int
    window_seconds: float = 60.0
    _timestamps: deque[float] = field(default_factory=deque)

    def wait_seconds(self) -> float:
        if self.limit <= 0:
            return 0.0
        now = time.monotonic()
        while self._timestamps and now - self._timestamps[0] >= self.window_seconds:
            self._timestamps.popleft()
        if len(self._timestamps) < self.limit:
            return 0.0
        return max(0.0, self.window_seconds - (now - self._timestamps[0]))

    def record(self) -> None:
        if self.limit <= 0:
            return
        self._timestamps.append(time.monotonic())


@dataclass(frozen=True)
class StrategyConfig:
    max_creates_per_burst: int = 8
    cooldown_429_seconds: float = 480.0
    cooldown_4xx_seconds: float = 60.0
    cooldown_max_seconds: float = 960.0
    backoff_growth: float = 1.5
    # Сколько подряд сетевых ошибок ИМЕННО В ОДНОЙ ЗОНЕ терпим с короткими
    # растущими паузами, прежде чем признать, что "подождать чуть-чуть" не
    # помогает, и вывести эту зону в карантин на cooldown_429_seconds
    # (те же 8 минут, что и при подтверждённом 429) — см. on_zone_network_error.
    network_error_escalate_after: int = 3
    network_error_base_seconds: float = 30.0
    # Затяжной простой зоны (см. докстринг ZoneState.quarantine_count) —
    # каждый следующий карантин подряд без единого успеха длиннее
    # предыдущего в zone_quarantine_growth раз, до потолка
    # zone_quarantine_max_seconds (по умолчанию час — дальше нет смысла
    # растить, раз в час проверить "ожил ли хост" достаточно).
    zone_quarantine_growth: float = 2.0
    zone_quarantine_max_seconds: float = 3600.0
    # Границы и шаг адаптации burst_limit (см. п.1 в докстринге модуля).
    burst_limit_min: int = 3
    burst_limit_max: int = 20
    burst_limit_growth: float = 1.25
    burst_limit_shrink: float = 0.6


def _set_backoff(state: AccountState, seconds: float, config: StrategyConfig) -> None:
    capped = min(seconds, config.cooldown_max_seconds)
    state.backoff_until = datetime.now(timezone.utc) + timedelta(seconds=capped)


def _grow_burst_limit(state: AccountState, config: StrategyConfig) -> None:
    state.burst_limit = min(
        config.burst_limit_max,
        max(config.burst_limit_min, round(state.burst_limit * config.burst_limit_growth)),
    )


def _shrink_burst_limit(state: AccountState, config: StrategyConfig) -> None:
    state.burst_limit = max(
        config.burst_limit_min,
        min(config.burst_limit_max, round(state.burst_limit * config.burst_limit_shrink)),
    )


def on_successful_create(state: AccountState, config: StrategyConfig) -> None:
    """Вызывать после каждого успешного create (до проверки whitelist —
    это чисто про темп запросов, не про результат сверки)."""
    state.consecutive_errors = 0
    state.last_result = "created"
    state.creates_in_burst += 1
    if state.creates_in_burst >= state.burst_limit:
        # Самоограничение сработало раньше реального 429 — уходим в
        # тот же cooldown, что наблюдался эмпирически, и сбрасываем burst.
        _set_backoff(state, config.cooldown_429_seconds, config)
        state.creates_in_burst = 0
        state.last_result = "self_throttled"
        # Пачка была чистой (иначе бы creates_in_burst обнулился раньше на
        # 429/quota) — можно чуть смелее в следующий раз.
        _grow_burst_limit(state, config)


def on_rate_limit_429(state: AccountState, config: StrategyConfig, retry_after: float | None = None) -> None:
    state.consecutive_errors += 1
    state.creates_in_burst = 0
    state.last_result = "rate_limited"
    _shrink_burst_limit(state, config)
    base = config.cooldown_429_seconds
    growth = config.backoff_growth ** max(0, state.consecutive_errors - 1)
    seconds = max(retry_after or 0.0, base * growth)
    _set_backoff(state, seconds, config)


def on_quota_4xx(state: AccountState, config: StrategyConfig) -> None:
    state.consecutive_errors += 1
    state.creates_in_burst = 0
    state.last_result = "quota_error"
    _shrink_burst_limit(state, config)
    growth = config.backoff_growth ** max(0, state.consecutive_errors - 1)
    _set_backoff(state, config.cooldown_4xx_seconds * growth, config)


def on_zone_network_error(zone_state: ZoneState, config: StrategyConfig) -> bool:
    """Сетевая ошибка в конкретной зоне. Первые несколько раз — короткая
    растущая пауза именно для этой зоны (вдруг это разовый обрыв). После
    `network_error_escalate_after` ошибок подряд — признаём, что хост
    зоны недоступен не разово, и уводим ТОЛЬКО ЕЁ в карантин. Остальные
    зоны аккаунта это не затрагивает.

    Длина ЭТОГО карантина зависит от того, сколько раз подряд (без единого
    успеха между ними — см. on_zone_success) зона уже уходила в карантин
    до этого: 1й раз — cooldown_429_seconds (8 мин), 2й — вдвое дольше,
    3й — вчетверо, и так далее до zone_quarantine_max_seconds. Иначе при
    многочасовом простое хоста (реальный кейс — недоступность ru-9 с ночи
    до утра) роллер долбил бы мёртвый хост каждые 8 минут всю ночь просто
    зря — 3 быстрых пробных запроса + длинный сон куда бережнее.

    Возвращает True, если в этот раз произошла эскалация в полноценный
    карантин (для лога и для алерта в Telegram при затяжном простое),
    False — если это просто короткая пауза перед следующей попыткой."""
    zone_state.consecutive_errors += 1
    if zone_state.consecutive_errors >= config.network_error_escalate_after:
        zone_state.quarantine_count += 1
        growth = config.zone_quarantine_growth ** max(0, zone_state.quarantine_count - 1)
        seconds = min(config.cooldown_429_seconds * growth, config.zone_quarantine_max_seconds)
        zone_state.cooldown_until = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        zone_state.consecutive_errors = 0
        return True
    growth = config.backoff_growth ** max(0, zone_state.consecutive_errors - 1)
    seconds = min(config.network_error_base_seconds * growth, config.cooldown_max_seconds)
    zone_state.cooldown_until = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return False


def on_zone_success(zone_state: ZoneState) -> None:
    """Любой определённый ответ от зоны (успешный create, а также 429/quota —
    это тоже ответ, просто отказ) доказывает, что хост зоны отвечает, то
    есть сетевой проблемы именно с ним сейчас нет — сбрасываем карантин
    целиком, включая счётчик подряд идущих карантинов (quarantine_count) и
    флаг отправленного алерта: раз зона снова отвечает, простой закончился,
    следующий сбой (если будет) — это уже новый, отдельный эпизод."""
    zone_state.consecutive_errors = 0
    zone_state.cooldown_until = None
    zone_state.quarantine_count = 0
    zone_state.alert_sent = False
