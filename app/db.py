"""
db.py

SQLite-хранилище (через aiosqlite, WAL-режим — чтобы веб-панель и
несколько roller-воркеров могли читать/писать параллельно без блокировок
друг друга на чтении).

Таблицы:
  accounts   — аккаунты Selectel, добавляются руками через веб-форму
  attempts   — детальный лог каждой попытки create (что за IP, куда попал,
               что с ним сделали) — вкладка "логи по аккаунту"
  found_ips  — то, что осталось (IP из БС) — вкладка "найденные IP"
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Optional

import aiosqlite

from .credentials import PREFIX, decrypt_password, encrypt_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    label               TEXT NOT NULL UNIQUE,
    account_id          TEXT NOT NULL,
    username            TEXT NOT NULL,
    password            TEXT NOT NULL,
    project_id          TEXT,
    project_name        TEXT,
    selected_zones      TEXT NOT NULL DEFAULT '[]',   -- JSON-массив кодов зон
    desired_running     INTEGER NOT NULL DEFAULT 0,    -- должен ли работать (переживает рестарт)
    status              TEXT NOT NULL DEFAULT 'stopped', -- stopped|running|error|cooldown
    status_detail       TEXT NOT NULL DEFAULT '',
    cooldown_until      TEXT DEFAULT NULL,               -- ISO UTC, только пока status='cooldown' — для live-отсчёта на фронте
    total_attempts      INTEGER NOT NULL DEFAULT 0,
    total_matches       INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id          INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    zone                TEXT NOT NULL,
    ip                  TEXT,
    result              TEXT NOT NULL,        -- match | miss | error
    http_status         INTEGER,
    neutron_id          TEXT,
    detail              TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_account ON attempts(account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS found_ips (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id          INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    ip                  TEXT NOT NULL,
    zone                TEXT NOT NULL,
    city                TEXT NOT NULL,
    cidr_matched        TEXT NOT NULL,
    neutron_id          TEXT,
    notified            INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_found_ips_created ON found_ips(created_at DESC);

-- Reconciler may mutate only resources whose IDs are in this ownership ledger.
CREATE TABLE IF NOT EXISTS managed_resources (
    neutron_id TEXT PRIMARY KEY,
    account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
    account_label TEXT NOT NULL,
    project_id TEXT,
    zone TEXT NOT NULL,
    ip TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','protected','delete_pending','delete_error','deleted')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_managed_resources_state ON managed_resources(state, updated_at DESC);

-- Durable, conservative budget reservations shared by all account workers.
CREATE TABLE IF NOT EXISTS create_reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    outcome TEXT NOT NULL DEFAULT 'pending',
    resolution_note TEXT,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_create_reservations_created ON create_reservations(created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL DEFAULT 'admin',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC);

-- Canonical history of every observed address. The local CIDR match and
-- provider/API failures are separate facts; a failed check is never a MISS.
CREATE TABLE IF NOT EXISTS ip_registry (
    ip TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('pending','match','miss','error')),
    source TEXT NOT NULL DEFAULT 'local_cidr',
    matched_cidr TEXT,
    matched_zone TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    last_account_id INTEGER,
    last_region TEXT,
    next_check_at TEXT,
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ip_registry_last_seen ON ip_registry(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_registry_status_ttl ON ip_registry(status,next_check_at);

-- Scheduler/strategy state survives service restart. Keeps each account's
-- backoff separate, while project-wide request caps remain in reservations.
CREATE TABLE IF NOT EXISTS account_runtime (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    consecutive_errors INTEGER NOT NULL DEFAULT 0,
    creates_in_burst INTEGER NOT NULL DEFAULT 0,
    burst_limit INTEGER NOT NULL DEFAULT 8,
    backoff_until TEXT,
    last_request_at TEXT,
    last_success_at TEXT,
    zone_states TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    region TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ip TEXT,
    neutron_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_events_created ON operation_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operation_events_region ON operation_events(region,created_at DESC);
CREATE TABLE IF NOT EXISTS migration_flags (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS scheduler_lease (
    id INTEGER PRIMARY KEY CHECK(id=1),
    account_id INTEGER,
    lease_until TEXT
);
INSERT OR IGNORE INTO scheduler_lease(id,account_id,lease_until) VALUES(1,NULL,NULL);

CREATE TABLE IF NOT EXISTS rate_limit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    retry_after REAL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_events_time ON rate_limit_events(created_at DESC);
CREATE TABLE IF NOT EXISTS provider_failure_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    error_class TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_failure_time ON provider_failure_events(created_at DESC);
CREATE TABLE IF NOT EXISTS notification_deliveries (
    channel TEXT NOT NULL,
    period_start TEXT NOT NULL,
    delivered_at TEXT NOT NULL,
    PRIMARY KEY(channel, period_start)
);
CREATE TABLE IF NOT EXISTS service_circuit (
    id INTEGER PRIMARY KEY CHECK(id=1),
    open_until TEXT,
    reason TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO service_circuit(id,open_until,reason,updated_at) VALUES(1,NULL,'', '1970-01-01T00:00:00+00:00');
"""


class GlobalCreateRateWait(Exception):
    def __init__(self, seconds: float):
        self.seconds = max(0.1, seconds)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@asynccontextmanager
async def connect(db_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        await conn.close()


async def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    async with connect(db_path) as conn:
        await conn.executescript(SCHEMA)
        # Миграция для БД, созданных до появления cooldown_until (idempotent —
        # SQLite не умеет "ADD COLUMN IF NOT EXISTS", поэтому ловим дубликат).
        try:
            await conn.execute("ALTER TABLE accounts ADD COLUMN cooldown_until TEXT")
        except Exception:
            pass
        # One-time migration from the previous plaintext SQLite format.
        cur = await conn.execute("SELECT id,password FROM accounts WHERE password NOT LIKE ?", (PREFIX + "%",))
        legacy_passwords = await cur.fetchall()
        for row in legacy_passwords:
            await conn.execute("UPDATE accounts SET password=? WHERE id=?", (encrypt_password(row["password"]), row["id"]))
        # A process may die after a remote POST was sent but before its result
        # was persisted. Treat such reservations as uncertain and never retry
        # them automatically as if the provider had rejected the operation.
        await conn.execute("UPDATE create_reservations SET outcome='uncertain' WHERE outcome='pending'")
        # A restarted single-service process cannot still own the old lease.
        await conn.execute("UPDATE scheduler_lease SET account_id=NULL,lease_until=NULL WHERE id=1")
        for column, declaration in (("resolution_note", "TEXT"), ("resolved_at", "TEXT")):
            try:
                await conn.execute(f"ALTER TABLE create_reservations ADD COLUMN {column} {declaration}")
            except Exception:
                pass
        # Backfill the durable address registry from the pre-existing event
        # history. A failed attempt remains ERROR; it is never converted to MISS.
        await conn.execute(
            """INSERT OR IGNORE INTO ip_registry(ip,status,source,first_seen_at,last_seen_at,seen_count,
                       last_account_id,last_region,next_check_at,last_error)
               SELECT a.ip,
                      CASE (SELECT x.result FROM attempts x WHERE x.ip=a.ip ORDER BY x.id DESC LIMIT 1)
                        WHEN 'match' THEN 'match' WHEN 'miss' THEN 'miss' ELSE 'error' END,
                      'local_cidr',MIN(a.created_at),MAX(a.created_at),COUNT(*),
                      (SELECT x.account_id FROM attempts x WHERE x.ip=a.ip ORDER BY x.id DESC LIMIT 1),
                      (SELECT x.zone FROM attempts x WHERE x.ip=a.ip ORDER BY x.id DESC LIMIT 1),
                      CASE (SELECT x.result FROM attempts x WHERE x.ip=a.ip ORDER BY x.id DESC LIMIT 1)
                        WHEN 'miss' THEN datetime(MAX(a.created_at), '+24 hours')
                        WHEN 'error' THEN datetime(MAX(a.created_at), '+5 minutes') END,
                      CASE WHEN (SELECT x.result FROM attempts x WHERE x.ip=a.ip ORDER BY x.id DESC LIMIT 1)='error'
                        THEN 'Импортировано из старого журнала попыток' ELSE '' END
               FROM attempts a WHERE a.ip IS NOT NULL AND a.ip<>'' GROUP BY a.ip"""
        )
        await conn.execute(
            """INSERT OR IGNORE INTO ip_registry(ip,status,source,matched_cidr,matched_zone,first_seen_at,last_seen_at,
                       seen_count,last_account_id,last_region,last_error)
               SELECT ip,'match','local_cidr',cidr_matched,city,MIN(created_at),MAX(created_at),COUNT(*),
                      (SELECT f2.account_id FROM found_ips f2 WHERE f2.ip=found_ips.ip ORDER BY f2.id DESC LIMIT 1),
                      (SELECT f2.zone FROM found_ips f2 WHERE f2.ip=found_ips.ip ORDER BY f2.id DESC LIMIT 1),''
               FROM found_ips GROUP BY ip"""
        )
        await conn.execute(
            """UPDATE ip_registry SET status='match',source='local_cidr',
                 matched_cidr=(SELECT f.cidr_matched FROM found_ips f WHERE f.ip=ip_registry.ip ORDER BY f.id DESC LIMIT 1),
                 matched_zone=(SELECT f.city FROM found_ips f WHERE f.ip=ip_registry.ip ORDER BY f.id DESC LIMIT 1),
                 last_account_id=(SELECT f.account_id FROM found_ips f WHERE f.ip=ip_registry.ip ORDER BY f.id DESC LIMIT 1),
                 last_region=(SELECT f.zone FROM found_ips f WHERE f.ip=ip_registry.ip ORDER BY f.id DESC LIMIT 1),
                 last_error='',next_check_at=NULL
               WHERE ip IN (SELECT ip FROM found_ips)"""
        )
        cur = await conn.execute("SELECT 1 FROM migration_flags WHERE name='attempts_to_operation_events'")
        if await cur.fetchone() is None:
            await conn.execute(
                """INSERT INTO operation_events(account_id,region,outcome,ip,neutron_id,created_at)
                   SELECT account_id,zone,
                     CASE WHEN result='match' THEN 'match' WHEN result='miss' THEN 'miss'
                          WHEN http_status=429 THEN 'rate_limited'
                          WHEN http_status IS NOT NULL THEN 'http_' || http_status
                          WHEN ip IS NOT NULL THEN 'check_error' ELSE 'network_error' END,
                     ip,neutron_id,created_at FROM attempts"""
            )
            await conn.execute("INSERT INTO migration_flags(name,applied_at) VALUES('attempts_to_operation_events',?)", (now_iso(),))
        await conn.commit()


async def record_ip_observation(db_path: Path, *, ip: str, account_id: int, region: str,
                               match: Any | None, neutron_id: str | None = None,
                               miss_ttl_hours: int = 24) -> dict[str, Any]:
    """Upsert one address observation and return its durable history row.

    A match/miss here describes the local CIDR dataset only. Errors are
    explicitly recorded by record_ip_check_error and never mapped to MISS.
    Negative rows get a TTL; the background checker re-evaluates them against
    the CIDR snapshot loaded by the application.
    """
    ts = now_iso()
    status = "match" if match is not None else "miss"
    next_check = (datetime.now(timezone.utc) + timedelta(hours=max(1, miss_ttl_hours))).isoformat(timespec="seconds") if status == "miss" else None
    cidr = getattr(match, "cidr", None)
    zone = getattr(match, "zone", None)
    async with connect(db_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        await conn.execute(
            """INSERT INTO ip_registry(ip,status,source,matched_cidr,matched_zone,first_seen_at,last_seen_at,
                                      seen_count,last_account_id,last_region,next_check_at,last_error)
               VALUES(?,?,'local_cidr',?,?,?,?,1,?,?,?,'')
               ON CONFLICT(ip) DO UPDATE SET status=excluded.status, matched_cidr=excluded.matched_cidr,
                 matched_zone=excluded.matched_zone,last_seen_at=excluded.last_seen_at,
                 seen_count=ip_registry.seen_count+1,last_account_id=excluded.last_account_id,
                 last_region=excluded.last_region,next_check_at=excluded.next_check_at,last_error=''""",
            (ip, status, cidr, zone, ts, ts, account_id, region, next_check),
        )
        await conn.execute(
            "INSERT INTO operation_events(account_id,region,outcome,ip,neutron_id,created_at) VALUES(?,?,?,?,?,?)",
            (account_id, region, status, ip, neutron_id, ts),
        )
        cur = await conn.execute("SELECT * FROM ip_registry WHERE ip=?", (ip,))
        row = dict(await cur.fetchone())
        await conn.commit()
        return row


async def record_ip_check_error(db_path: Path, *, ip: str, account_id: int, region: str, error: str) -> None:
    ts = now_iso()
    retry_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
    async with connect(db_path) as conn:
        await conn.execute(
            """INSERT INTO ip_registry(ip,status,source,first_seen_at,last_seen_at,seen_count,last_account_id,last_region,next_check_at,last_error)
               VALUES(?,'error','local_cidr',?,?,1,?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET status='error',last_seen_at=excluded.last_seen_at,
                 seen_count=ip_registry.seen_count+1,last_account_id=excluded.last_account_id,
                 last_region=excluded.last_region,next_check_at=excluded.next_check_at,last_error=excluded.last_error""",
            (ip, ts, ts, account_id, region, retry_at, error[:500]),
        )
        await conn.execute(
            "INSERT INTO operation_events(account_id,region,outcome,ip,created_at) VALUES(?,?,?,?,?)",
            (account_id, region, 'check_error', ip, ts),
        )
        await conn.commit()


async def record_operation_event(db_path: Path, *, account_id: int, region: str, outcome: str,
                                ip: str | None = None, neutron_id: str | None = None) -> None:
    async with connect(db_path) as conn:
        await conn.execute(
            "INSERT INTO operation_events(account_id,region,outcome,ip,neutron_id,created_at) VALUES(?,?,?,?,?,?)",
            (account_id, region, outcome[:40], ip, neutron_id, now_iso()),
        )
        await conn.commit()


async def claim_create_turn(db_path: Path, account_id: int, *, lease_seconds: int = 60) -> tuple[bool, float]:
    """Durable fair turn across all running account workers.

    The next account is the ready one with the oldest request timestamp.
    This serializes create calls and prevents several accounts from turning
    one process-wide burst into a parallel burst against the provider.
    """
    now = datetime.now(timezone.utc)
    now_s = now.isoformat(timespec="seconds")
    async with connect(db_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        cur = await conn.execute("SELECT account_id,lease_until FROM scheduler_lease WHERE id=1")
        lease = await cur.fetchone()
        if lease and lease["account_id"] is not None and lease["account_id"] != account_id and lease["lease_until"]:
            try:
                remaining = (datetime.fromisoformat(lease["lease_until"]) - now).total_seconds()
            except ValueError:
                remaining = 0
            if remaining > 0:
                await conn.commit()
                return False, max(.25, min(remaining, 5.0))
        cur = await conn.execute(
            """SELECT a.id FROM accounts a LEFT JOIN account_runtime r ON r.account_id=a.id
               WHERE a.desired_running=1 AND a.status NOT IN ('error','stopped')
                 AND (a.cooldown_until IS NULL OR a.cooldown_until<=?)
               ORDER BY COALESCE(r.last_request_at,''),a.id LIMIT 1""",
            (now_s,),
        )
        selected = await cur.fetchone()
        if selected is None or int(selected["id"]) != account_id:
            await conn.commit()
            return False, 1.0
        until = (now + timedelta(seconds=max(10, lease_seconds))).isoformat(timespec="seconds")
        await conn.execute("UPDATE scheduler_lease SET account_id=?,lease_until=? WHERE id=1", (account_id, until))
        await conn.execute(
            """INSERT INTO account_runtime(account_id,last_request_at,updated_at) VALUES(?,?,?)
               ON CONFLICT(account_id) DO UPDATE SET last_request_at=excluded.last_request_at,updated_at=excluded.updated_at""",
            (account_id, now_s, now_s),
        )
        await conn.commit()
        return True, 0.0


async def release_create_turn(db_path: Path, account_id: int) -> None:
    async with connect(db_path) as conn:
        await conn.execute("UPDATE scheduler_lease SET account_id=NULL,lease_until=NULL WHERE id=1 AND account_id=?", (account_id,))
        await conn.commit()


async def register_rate_limit(db_path: Path, *, account_id: int, retry_after: float | None,
                              window_seconds: int = 120, global_threshold_accounts: int = 2,
                              fallback_pause_seconds: int = 480) -> str | None:
    """Open a shared API circuit only after independent accounts get 429s.

    A single account remains subject to its own backoff. Cross-account 429s
    indicate a likely project/API-wide constraint and pause all workers.
    """
    now = datetime.now(timezone.utc)
    ts = now.isoformat(timespec="seconds")
    cutoff = (now - timedelta(seconds=max(10, window_seconds))).isoformat(timespec="seconds")
    async with connect(db_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        await conn.execute("INSERT INTO rate_limit_events(account_id,retry_after,created_at) VALUES(?,?,?)",
                           (account_id, retry_after, ts))
        await conn.execute("DELETE FROM rate_limit_events WHERE created_at<?",
                           ((now - timedelta(days=14)).isoformat(timespec="seconds"),))
        cur = await conn.execute("SELECT COUNT(DISTINCT account_id) FROM rate_limit_events WHERE created_at>=?", (cutoff,))
        count = int((await cur.fetchone())[0])
        if count >= max(2, global_threshold_accounts):
            cur = await conn.execute("SELECT MAX(COALESCE(retry_after,0)) FROM rate_limit_events WHERE created_at>=?", (cutoff,))
            max_retry = float((await cur.fetchone())[0] or 0)
            pause = max(max(0, max_retry), fallback_pause_seconds)
            until = (now + timedelta(seconds=pause)).isoformat(timespec="seconds")
            reason = f"429 получен в {count} аккаунтах за {window_seconds} секунд"
            await conn.execute("UPDATE service_circuit SET open_until=?,reason=?,updated_at=? WHERE id=1", (until, reason, ts))
        cur = await conn.execute("SELECT open_until FROM service_circuit WHERE id=1")
        row = await cur.fetchone()
        await conn.commit()
        return row["open_until"] if row and row["open_until"] else None


async def get_service_circuit(db_path: Path) -> dict[str, str | None]:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT open_until,reason FROM service_circuit WHERE id=1")
        row = await cur.fetchone()
        if not row:
            return {"open_until": None, "reason": None}
        try:
            if row["open_until"] and datetime.fromisoformat(row["open_until"]) <= datetime.now(timezone.utc):
                await conn.execute("UPDATE service_circuit SET open_until=NULL,reason='' WHERE id=1")
                await conn.commit()
                return {"open_until": None, "reason": None}
        except ValueError:
            pass
        return {"open_until": row["open_until"], "reason": row["reason"]}


async def register_provider_failure(db_path: Path, *, account_id: int, error_class: str,
                                    window_seconds: int = 120, threshold_accounts: int = 2,
                                    pause_seconds: int = 60) -> str | None:
    """Pause the provider integration after cross-account transport failures."""
    now = datetime.now(timezone.utc)
    ts = now.isoformat(timespec="seconds")
    cutoff = (now - timedelta(seconds=max(10, window_seconds))).isoformat(timespec="seconds")
    async with connect(db_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        await conn.execute("INSERT INTO provider_failure_events(account_id,error_class,created_at) VALUES(?,?,?)",
                           (account_id, error_class[:80], ts))
        await conn.execute("DELETE FROM provider_failure_events WHERE created_at<?",
                           ((now - timedelta(days=14)).isoformat(timespec="seconds"),))
        cur = await conn.execute("SELECT COUNT(DISTINCT account_id) FROM provider_failure_events WHERE created_at>=?", (cutoff,))
        count = int((await cur.fetchone())[0])
        if count >= max(2, threshold_accounts):
            until = (now + timedelta(seconds=max(10, pause_seconds))).isoformat(timespec="seconds")
            reason = f"системные ошибки API в {count} аккаунтах за {window_seconds} секунд"
            await conn.execute("UPDATE service_circuit SET open_until=?,reason=?,updated_at=? WHERE id=1", (until, reason, ts))
        cur = await conn.execute("SELECT open_until FROM service_circuit WHERE id=1")
        row = await cur.fetchone()
        await conn.commit()
        return row["open_until"] if row and row["open_until"] else None


async def load_account_runtime(db_path: Path, account_id: int) -> dict[str, Any] | None:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT * FROM account_runtime WHERE account_id=?", (account_id,))
        row = await cur.fetchone()
        if not row:
            return None
        result = dict(row)
        result["zone_states"] = json.loads(result.get("zone_states") or "{}")
        return result


async def save_account_runtime(db_path: Path, account_id: int, *, consecutive_errors: int,
                              creates_in_burst: int, burst_limit: int, backoff_until: str | None,
                              last_request_at: str | None, last_success_at: str | None,
                              zone_states: dict[str, Any]) -> None:
    async with connect(db_path) as conn:
        await conn.execute(
            """INSERT INTO account_runtime(account_id,consecutive_errors,creates_in_burst,burst_limit,
                       backoff_until,last_request_at,last_success_at,zone_states,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
                 consecutive_errors=excluded.consecutive_errors,creates_in_burst=excluded.creates_in_burst,
                 burst_limit=excluded.burst_limit,backoff_until=excluded.backoff_until,
                 last_request_at=excluded.last_request_at,last_success_at=excluded.last_success_at,
                 zone_states=excluded.zone_states,updated_at=excluded.updated_at""",
            (account_id, consecutive_errors, creates_in_burst, burst_limit, backoff_until,
             last_request_at, last_success_at, json.dumps(zone_states), now_iso()),
        )
        await conn.commit()


async def get_analytics(db_path: Path, hours: int = 24, cost_per_ip_hour_rub: float = 0.0) -> dict[str, Any]:
    hours = max(1, min(hours, 720))
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    async with connect(db_path) as conn:
        cur = await conn.execute(
            "SELECT outcome,region,COUNT(*) AS total,COUNT(DISTINCT ip) AS unique_ips FROM operation_events WHERE created_at>=? GROUP BY outcome,region ORDER BY region,outcome",
            (since,),
        )
        rows = [dict(r) for r in await cur.fetchall()]
        cur = await conn.execute("SELECT status,COUNT(*) AS total FROM ip_registry GROUP BY status")
        registry = {r["status"]: r["total"] for r in await cur.fetchall()}
        cur = await conn.execute("SELECT COUNT(*) FROM ip_registry WHERE seen_count>1")
        repeat_ips = int((await cur.fetchone())[0])
        cur = await conn.execute("SELECT created_at,updated_at,state FROM managed_resources")
        resource_rows = await cur.fetchall()
        cur = await conn.execute("SELECT COUNT(DISTINCT ip) FROM found_ips")
        protected_count = int((await cur.fetchone())[0] or 0)
        bucket = "%Y-%m-%dT00:00:00Z" if hours > 72 else "%Y-%m-%dT%H:00:00Z"
        cur = await conn.execute(
            f"SELECT strftime('{bucket}',created_at) AS hour, outcome, COUNT(*) AS total FROM operation_events WHERE created_at>=? GROUP BY hour,outcome ORDER BY hour",
            (since,),
        )
        hourly_rows = [dict(r) for r in await cur.fetchall()]
        cur = await conn.execute(
            """SELECT COUNT(DISTINCT CASE WHEN outcome='match' THEN ip END),
                      COUNT(CASE WHEN outcome IN ('match','miss') THEN 1 END)
               FROM operation_events WHERE created_at>=?""", (since,),
        )
        unique_row = await cur.fetchone()
    totals: dict[str, int] = {}
    for row in rows:
        totals[row["outcome"]] = totals.get(row["outcome"], 0) + row["total"]
    attempts = totals.get("match", 0) + totals.get("miss", 0)
    hour_map: dict[str, dict[str, Any]] = {}
    for row in hourly_rows:
        point = hour_map.setdefault(row["hour"], {"hour": row["hour"], "match": 0, "miss": 0, "errors": 0, "total": 0})
        point["total"] += row["total"]
        if row["outcome"] in {"match", "miss"}:
            point[row["outcome"]] += row["total"]
        else:
            point["errors"] += row["total"]
    hourly = list(hour_map.values())
    max_hour = max((row["total"] for row in hourly), default=0)
    for row in hourly:
        row["bar"] = round(100 * row["total"] / max_hour) if max_hour else 0
    errors = sum(value for key, value in totals.items() if key not in {"match", "miss"})
    unique_matches = int(unique_row[0] or 0)
    completed_checks = int(unique_row[1] or 0)
    cost_now = datetime.now(timezone.utc)
    held_hours = held_last_hour = held_last_day = 0.0
    for resource in resource_rows:
        try:
            created = datetime.fromisoformat(resource["created_at"])
            ended = datetime.fromisoformat(resource["updated_at"]) if resource["state"] == "deleted" else cost_now
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if ended.tzinfo is None:
                ended = ended.replace(tzinfo=timezone.utc)
            ended = min(ended, cost_now)
            for cutoff, bucket in ((datetime.min.replace(tzinfo=timezone.utc), "all"),
                                   (cost_now - timedelta(hours=1), "hour"),
                                   (cost_now - timedelta(hours=24), "day")):
                started = max(created, cutoff)
                if ended > started:
                    elapsed = (ended - started).total_seconds() / 3600
                    if bucket == "all":
                        held_hours += elapsed
                    elif bucket == "hour":
                        held_last_hour += elapsed
                    else:
                        held_last_day += elapsed
        except (TypeError, ValueError):
            continue
    resource_hours = round(held_hours, 3)
    estimated_cost = round(resource_hours * max(0.0, cost_per_ip_hour_rub), 2)
    estimated_cost_last_hour = round(held_last_hour * max(0.0, cost_per_ip_hour_rub), 2)
    estimated_cost_last_24h = round(held_last_day * max(0.0, cost_per_ip_hour_rub), 2)
    return {"since": since, "rows": rows, "hourly": hourly, "registry": registry,
            "repeat_ips": repeat_ips, "totals": totals,
            "errors": errors,
            "resource_hours": resource_hours, "estimated_cost_rub": estimated_cost,
            "estimated_cost_last_hour_rub": estimated_cost_last_hour,
            "estimated_cost_last_24h_rub": estimated_cost_last_24h,
            "estimated_cost_per_match_rub": round(estimated_cost / protected_count, 2) if protected_count else None,
            "cost_per_ip_hour_rub": max(0.0, cost_per_ip_hour_rub),
            "unique_matches": unique_matches,
            "effectiveness_per_100": round(100 * unique_matches / completed_checks, 2) if completed_checks else 0,
            "match_rate": round(100 * totals.get("match", 0) / attempts, 2) if attempts else 0,
            "attempts": attempts}


async def list_ip_registry(db_path: Path, search: str = "", status: str = "", limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    async with connect(db_path) as conn:
        clauses, args = [], []
        if search:
            clauses.append("(ip LIKE ? OR last_region LIKE ? OR matched_cidr LIKE ?)")
            args.extend([f"%{search}%"] * 3)
        if status in {"pending", "match", "miss", "error"}:
            clauses.append("status=?")
            args.append(status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        cur = await conn.execute("SELECT * FROM ip_registry" + where + " ORDER BY last_seen_at DESC LIMIT ? OFFSET ?", (*args, limit, max(0, offset)))
        return [dict(r) for r in await cur.fetchall()]


async def get_ip_registry_entry(db_path: Path, ip: str) -> dict[str, Any] | None:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT * FROM ip_registry WHERE ip=?", (ip,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def count_ip_registry(db_path: Path, search: str = "", status: str = "") -> int:
    clauses, args = [], []
    if search:
        clauses.append("(ip LIKE ? OR last_region LIKE ? OR matched_cidr LIKE ?)")
        args.extend([f"%{search}%"] * 3)
    if status in {"pending", "match", "miss", "error"}:
        clauses.append("status=?")
        args.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT COUNT(*) FROM ip_registry" + where, args)
        return int((await cur.fetchone())[0])


async def list_due_ip_checks(db_path: Path, limit: int = 200) -> list[dict[str, Any]]:
    now = now_iso()
    async with connect(db_path) as conn:
        cur = await conn.execute(
            "SELECT * FROM ip_registry WHERE status IN ('miss','error') AND next_check_at IS NOT NULL AND next_check_at<=? ORDER BY next_check_at LIMIT ?",
            (now, max(1, min(limit, 1000))),
        )
        return [dict(row) for row in await cur.fetchall()]


async def refresh_ip_check(db_path: Path, *, ip: str, match: Any | None, error: str | None = None,
                           miss_ttl_hours: int = 24) -> None:
    now = datetime.now(timezone.utc)
    ts = now.isoformat(timespec="seconds")
    if error:
        status, next_check = "error", (now + timedelta(minutes=5)).isoformat(timespec="seconds")
        cidr = zone = None
    elif match is not None:
        status, next_check = "match", None
        cidr, zone = getattr(match, "cidr", None), getattr(match, "zone", None)
    else:
        status, next_check = "miss", (now + timedelta(hours=max(1, miss_ttl_hours))).isoformat(timespec="seconds")
        cidr = zone = None
    async with connect(db_path) as conn:
        await conn.execute(
            """UPDATE ip_registry SET status=?,source='local_cidr',matched_cidr=?,matched_zone=?,
                 next_check_at=?,last_error=?,last_seen_at=last_seen_at WHERE ip=?""",
            (status, cidr, zone, next_check, (error or "")[:500], ip),
        )
        await conn.commit()


async def reserve_create_operation(db_path: Path, account_id: int, *, daily_limit: int,
                                   active_limit: int, minute_limit: int,
                                   cost_per_ip_hour_rub: float = 0.0,
                                   max_estimated_daily_cost_rub: float = 0.0,
                                   max_estimated_hourly_cost_rub: float = 0.0) -> int:
    """Atomically reserve an operation and enforce service-wide safety caps.

    Reservations count even when the remote result is ambiguous; this is
    deliberate so retries cannot silently exceed the configured daily cap.
    """
    ts = now_iso()
    day = ts[:10]
    async with connect(db_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        cur = await conn.execute("SELECT created_at FROM create_reservations WHERE created_at >= ? ORDER BY created_at ASC",
                                 ((datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(timespec="seconds"),))
        recent = await cur.fetchall()
        if len(recent) >= minute_limit:
            oldest = datetime.fromisoformat(recent[0]["created_at"])
            raise GlobalCreateRateWait(60 - (datetime.now(timezone.utc) - oldest).total_seconds())
        cur = await conn.execute("SELECT COUNT(*) FROM create_reservations WHERE substr(created_at,1,10)=?", (day,))
        if int((await cur.fetchone())[0]) >= daily_limit:
            raise ValueError(f"Достигнут дневной предохранитель: не более {daily_limit} операций создания")
        cur = await conn.execute("SELECT COUNT(*) FROM managed_resources WHERE state IN ('pending','protected','delete_pending','delete_error')")
        managed_count = int((await cur.fetchone())[0])
        cur = await conn.execute("SELECT COUNT(*) FROM create_reservations WHERE outcome='uncertain'")
        uncertain_count = int((await cur.fetchone())[0])
        if managed_count + uncertain_count >= active_limit:
            raise ValueError(f"Достигнут защитный предел: {managed_count} управляемых IP и {uncertain_count} неопределённых операций (лимит {active_limit})")
        if cost_per_ip_hour_rub > 0 and (max_estimated_daily_cost_rub > 0 or max_estimated_hourly_cost_rub > 0):
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=24)
            hour_cutoff = now - timedelta(hours=1)
            cur = await conn.execute("SELECT created_at,updated_at,state FROM managed_resources")
            held_hours = 0.0
            held_hours_last_hour = 0.0
            for resource in await cur.fetchall():
                try:
                    created = datetime.fromisoformat(resource["created_at"])
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    ended = now
                    if resource["state"] == "deleted":
                        ended = datetime.fromisoformat(resource["updated_at"])
                        if ended.tzinfo is None:
                            ended = ended.replace(tzinfo=timezone.utc)
                        ended = min(ended, now)
                    started = max(created, cutoff)
                    if ended > started:
                        held_hours += (ended - started).total_seconds() / 3600
                    started_hour = max(created, hour_cutoff)
                    if ended > started_hour:
                        held_hours_last_hour += (ended - started_hour).total_seconds() / 3600
                except (TypeError, ValueError):
                    continue
            cur = await conn.execute("SELECT created_at FROM create_reservations WHERE outcome='uncertain'")
            uncertain_hours = 0.0
            uncertain_hours_last_hour = 0.0
            for reservation in await cur.fetchall():
                try:
                    created = datetime.fromisoformat(reservation["created_at"])
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    started = max(created, cutoff)
                    if now > started:
                        uncertain_hours += (now - started).total_seconds() / 3600
                    started_hour = max(created, hour_cutoff)
                    if now > started_hour:
                        uncertain_hours_last_hour += (now - started_hour).total_seconds() / 3600
                except (TypeError, ValueError):
                    continue
            estimated = (held_hours + uncertain_hours) * cost_per_ip_hour_rub
            estimated_hour = (held_hours_last_hour + uncertain_hours_last_hour) * cost_per_ip_hour_rub
            if max_estimated_daily_cost_rub > 0 and estimated + cost_per_ip_hour_rub > max_estimated_daily_cost_rub:
                raise ValueError(
                    f"Достигнут ориентировочный денежный предохранитель: около {estimated:.2f} ₽ за последние 24 часа; "
                    f"новая операция может превысить лимит {max_estimated_daily_cost_rub:.2f} ₽/сутки. "
                    "Проверьте ставку и детализацию Selectel."
                )
            if max_estimated_hourly_cost_rub > 0 and estimated_hour + cost_per_ip_hour_rub > max_estimated_hourly_cost_rub:
                raise ValueError(
                    f"Достигнут ориентировочный денежный предохранитель: около {estimated_hour:.2f} ₽ за последний час; "
                    f"новая операция может превысить лимит {max_estimated_hourly_cost_rub:.2f} ₽/час. "
                    "Проверьте ставку и детализацию Selectel."
                )
        cur = await conn.execute(
            "INSERT INTO create_reservations(account_id,created_at,outcome) VALUES(?,?, 'pending')",
            (account_id, ts),
        )
        await conn.commit()
        return int(cur.lastrowid)


async def finish_create_operation(db_path: Path, operation_id: int, outcome: str) -> None:
    async with connect(db_path) as conn:
        await conn.execute("UPDATE create_reservations SET outcome=? WHERE id=?", (outcome, operation_id))
        await conn.commit()


async def list_uncertain_operations(db_path: Path) -> list[dict[str, Any]]:
    async with connect(db_path) as conn:
        cur = await conn.execute(
            """SELECT r.*, COALESCE(a.label, 'Аккаунт #' || r.account_id) AS label
               FROM create_reservations r LEFT JOIN accounts a ON a.id=r.account_id
               WHERE r.outcome='uncertain' ORDER BY r.created_at"""
        )
        return [dict(row) for row in await cur.fetchall()]


async def resolve_uncertain_operation(db_path: Path, operation_id: int, note: str) -> bool:
    async with connect(db_path) as conn:
        cur = await conn.execute(
            "UPDATE create_reservations SET outcome='manually_resolved',resolution_note=?,resolved_at=? WHERE id=? AND outcome='uncertain'",
            (note[:500], now_iso(), operation_id),
        )
        await conn.commit()
        return cur.rowcount == 1


async def add_audit_event(db_path: Path, action: str, target: str = "", details: str = "", actor: str = "admin") -> None:
    async with connect(db_path) as conn:
        await conn.execute(
            "INSERT INTO audit_events(actor,action,target,details,created_at) VALUES(?,?,?,?,?)",
            (actor[:120], action[:120], target[:240], details[:1000], now_iso()),
        )
        await conn.commit()


async def list_audit_events(db_path: Path, limit: int = 500) -> list[dict[str, Any]]:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in await cur.fetchall()]


async def register_managed_resource(db_path: Path, *, account_id: int, account_label: str,
                                    project_id: str | None, zone: str, ip: str, neutron_id: str,
                                    state: str = "pending") -> None:
    ts = now_iso()
    async with connect(db_path) as conn:
        await conn.execute(
            """INSERT INTO managed_resources(neutron_id,account_id,account_label,project_id,zone,ip,state,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(neutron_id) DO UPDATE SET ip=excluded.ip, zone=excluded.zone, state=excluded.state, updated_at=excluded.updated_at""",
            (neutron_id, account_id, account_label, project_id, zone, ip, state, ts, ts),
        )
        await conn.commit()


async def update_managed_resource_state(db_path: Path, neutron_id: str, state: str) -> None:
    async with connect(db_path) as conn:
        await conn.execute("UPDATE managed_resources SET state=?,updated_at=? WHERE neutron_id=?", (state, now_iso(), neutron_id))
        await conn.commit()


async def list_managed_resources(db_path: Path, account_id: int, *, states: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    async with connect(db_path) as conn:
        if states:
            marks = ",".join("?" for _ in states)
            cur = await conn.execute(
                f"SELECT * FROM managed_resources WHERE account_id=? AND state IN ({marks}) ORDER BY created_at",
                (account_id, *states),
            )
        else:
            cur = await conn.execute("SELECT * FROM managed_resources WHERE account_id=? ORDER BY created_at", (account_id,))
        return [dict(row) for row in await cur.fetchall()]


async def list_all_managed_resources(db_path: Path) -> list[dict[str, Any]]:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT * FROM managed_resources ORDER BY updated_at DESC")
        return [dict(row) for row in await cur.fetchall()]


async def get_managed_resource(db_path: Path, neutron_id: str) -> dict[str, Any] | None:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT * FROM managed_resources WHERE neutron_id=?", (neutron_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def count_live_managed_resources(db_path: Path, account_id: int) -> int:
    async with connect(db_path) as conn:
        cur = await conn.execute(
            "SELECT COUNT(*) FROM managed_resources WHERE account_id=? AND state IN ('pending','protected','delete_pending','delete_error')",
            (account_id,),
        )
        return int((await cur.fetchone())[0])


async def safety_summary(db_path: Path) -> dict[str, int]:
    today = now_iso()[:10]
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT COUNT(*) FROM managed_resources WHERE state IN ('pending','protected','delete_pending','delete_error')")
        managed = int((await cur.fetchone())[0])
        cur = await conn.execute("SELECT COUNT(*) FROM create_reservations WHERE outcome='uncertain'")
        uncertain = int((await cur.fetchone())[0])
        cur = await conn.execute("SELECT COUNT(*) FROM create_reservations WHERE substr(created_at,1,10)=?", (today,))
        today_creates = int((await cur.fetchone())[0])
        cur = await conn.execute("SELECT COUNT(*) FROM managed_resources WHERE state='delete_error'")
        delete_errors = int((await cur.fetchone())[0])
        return {"managed": managed, "uncertain": uncertain, "today_creates": today_creates,
                "delete_errors": delete_errors}


# ---------------------------------------------------------------- accounts

@dataclass
class AccountRow:
    id: int
    label: str
    account_id: str
    username: str
    password: str = field(repr=False)
    project_id: str | None
    project_name: str | None
    selected_zones: list[str]
    desired_running: bool
    status: str
    status_detail: str
    cooldown_until: str | None
    total_attempts: int
    total_matches: int
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> "AccountRow":
        keys = row.keys()
        return cls(
            id=row["id"],
            label=row["label"],
            account_id=row["account_id"],
            username=row["username"],
            password=decrypt_password(row["password"]),
            project_id=row["project_id"],
            project_name=row["project_name"],
            selected_zones=json.loads(row["selected_zones"] or "[]"),
            desired_running=bool(row["desired_running"]),
            status=row["status"],
            status_detail=row["status_detail"],
            cooldown_until=row["cooldown_until"] if "cooldown_until" in keys else None,
            total_attempts=row["total_attempts"],
            total_matches=row["total_matches"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


async def create_account(
    db_path: Path,
    *,
    label: str,
    account_id: str,
    username: str,
    password: str,
    project_id: str = "",
    project_name: str = "",
    selected_zones: list[str] | None = None,
) -> int:
    ts = now_iso()
    async with connect(db_path) as conn:
        cur = await conn.execute(
            """INSERT INTO accounts
               (label, account_id, username, password, project_id, project_name,
                selected_zones, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                label, account_id, username, encrypt_password(password),
                project_id or None, project_name or None,
                json.dumps(selected_zones or []),
                ts, ts,
            ),
        )
        await conn.commit()
        return cur.lastrowid


async def list_accounts(db_path: Path) -> list[AccountRow]:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT * FROM accounts ORDER BY id")
        rows = await cur.fetchall()
        return [AccountRow.from_row(r) for r in rows]


async def get_account(db_path: Path, account_pk: int) -> Optional[AccountRow]:
    async with connect(db_path) as conn:
        cur = await conn.execute("SELECT * FROM accounts WHERE id = ?", (account_pk,))
        row = await cur.fetchone()
        return AccountRow.from_row(row) if row else None


async def update_account(
    db_path: Path,
    account_pk: int,
    *,
    label: str,
    account_id: str,
    username: str,
    password: str | None,
    project_id: str = "",
    project_name: str = "",
) -> None:
    """Обновляет данные ранее добавленного аккаунта (опечатался при
    добавлении — не нужно удалять и создавать заново). password=None или
    пустая строка — пароль НЕ меняется, оставляем прежний (чтобы не
    заставлять перевводить его каждый раз ради правки логина/ID)."""
    async with connect(db_path) as conn:
        if password:
            await conn.execute(
                """UPDATE accounts
                   SET label = ?, account_id = ?, username = ?, password = ?,
                       project_id = ?, project_name = ?, updated_at = ?
                   WHERE id = ?""",
                (label, account_id, username, encrypt_password(password), project_id or None, project_name or None, now_iso(), account_pk),
            )
        else:
            await conn.execute(
                """UPDATE accounts
                   SET label = ?, account_id = ?, username = ?,
                       project_id = ?, project_name = ?, updated_at = ?
                   WHERE id = ?""",
                (label, account_id, username, project_id or None, project_name or None, now_iso(), account_pk),
            )
        await conn.commit()


async def update_account_zones(db_path: Path, account_pk: int, selected_zones: list[str]) -> None:
    async with connect(db_path) as conn:
        await conn.execute(
            "UPDATE accounts SET selected_zones = ?, updated_at = ? WHERE id = ?",
            (json.dumps(selected_zones), now_iso(), account_pk),
        )
        await conn.commit()


async def set_account_desired_running(db_path: Path, account_pk: int, desired_running: bool) -> None:
    async with connect(db_path) as conn:
        await conn.execute(
            "UPDATE accounts SET desired_running = ?, updated_at = ? WHERE id = ?",
            (int(desired_running), now_iso(), account_pk),
        )
        await conn.commit()


async def update_account_status(
    db_path: Path, account_pk: int, status: str, detail: str = "", *, cooldown_until: str | None = None
) -> None:
    """cooldown_until — ISO UTC момент окончания cooldown (только для status='cooldown'),
    чтобы фронт мог сам тикать обратный отсчёт, а не ждать следующего update из воркера.
    Для любого другого статуса передавать None — явно сбрасывает старое значение."""
    async with connect(db_path) as conn:
        await conn.execute(
            "UPDATE accounts SET status = ?, status_detail = ?, cooldown_until = ?, updated_at = ? WHERE id = ?",
            (status, detail, cooldown_until, now_iso(), account_pk),
        )
        await conn.commit()


async def bump_account_counters(db_path: Path, account_pk: int, *, attempts: int = 0, matches: int = 0) -> None:
    async with connect(db_path) as conn:
        await conn.execute(
            """UPDATE accounts
               SET total_attempts = total_attempts + ?, total_matches = total_matches + ?, updated_at = ?
               WHERE id = ?""",
            (attempts, matches, now_iso(), account_pk),
        )
        await conn.commit()


async def delete_account(db_path: Path, account_pk: int) -> None:
    async with connect(db_path) as conn:
        cur = await conn.execute(
            "SELECT COUNT(*) FROM managed_resources WHERE account_id=? AND state IN ('pending','protected','delete_pending','delete_error')",
            (account_pk,),
        )
        count = int((await cur.fetchone())[0])
        if count:
            raise ValueError(f"Аккаунт нельзя удалить: за ним числится {count} активных или защищённых Floating IP. Сначала разрешите их судьбу вручную.")
        await conn.execute("DELETE FROM accounts WHERE id = ?", (account_pk,))
        await conn.commit()


# ---------------------------------------------------------------- attempts

async def log_attempt(
    db_path: Path,
    *,
    account_id: int,
    zone: str,
    ip: str | None,
    result: str,
    http_status: int | None = None,
    neutron_id: str | None = None,
    detail: str = "",
) -> None:
    async with connect(db_path) as conn:
        await conn.execute(
            """INSERT INTO attempts (account_id, zone, ip, result, http_status, neutron_id, detail, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (account_id, zone, ip, result, http_status, neutron_id, detail, now_iso()),
        )
        await conn.commit()


async def list_attempts_with_accounts(db_path: Path, limit: int = 400) -> list[dict[str, Any]]:
    """Как list_attempts(account_id=None), но с подмешанным label аккаунта —
    для общей вкладки логов по всем аккаунтам сразу."""
    async with connect(db_path) as conn:
        cur = await conn.execute(
            """SELECT attempts.*, accounts.label AS account_label
               FROM attempts JOIN accounts ON accounts.id = attempts.account_id
               ORDER BY attempts.id DESC LIMIT ?""",
            (limit,),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def list_attempts(db_path: Path, account_id: int | None = None, limit: int = 200) -> list[dict[str, Any]]:
    async with connect(db_path) as conn:
        if account_id is not None:
            cur = await conn.execute(
                "SELECT * FROM attempts WHERE account_id = ? ORDER BY id DESC LIMIT ?",
                (account_id, limit),
            )
        else:
            cur = await conn.execute("SELECT * FROM attempts ORDER BY id DESC LIMIT ?", (limit,))
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


# --------------------------------------------------------------- found_ips

async def add_found_ip(
    db_path: Path,
    *,
    account_id: int,
    ip: str,
    zone: str,
    city: str,
    cidr_matched: str,
    neutron_id: str | None,
) -> int:
    async with connect(db_path) as conn:
        cur = await conn.execute(
            """INSERT INTO found_ips (account_id, ip, zone, city, cidr_matched, neutron_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (account_id, ip, zone, city, cidr_matched, neutron_id, now_iso()),
        )
        await conn.commit()
        return cur.lastrowid


async def list_found_ips(db_path: Path, search: str = "", limit: int = 500) -> list[dict[str, Any]]:
    async with connect(db_path) as conn:
        if search:
            like = f"%{search}%"
            cur = await conn.execute(
                """SELECT found_ips.*, accounts.label AS account_label
                   FROM found_ips JOIN accounts ON accounts.id = found_ips.account_id
                   WHERE found_ips.ip LIKE ? OR accounts.label LIKE ? OR found_ips.zone LIKE ?
                   ORDER BY found_ips.id DESC LIMIT ?""",
                (like, like, like, limit),
            )
        else:
            cur = await conn.execute(
                """SELECT found_ips.*, accounts.label AS account_label
                   FROM found_ips JOIN accounts ON accounts.id = found_ips.account_id
                   ORDER BY found_ips.id DESC LIMIT ?""",
                (limit,),
            )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def found_ip_exists(db_path: Path, account_id: int, ip: str) -> bool:
    """Использует реконсилятор (roller.py) перед тем, как записать найденный
    при сверке список IP из Selectel в found_ips — чтобы не задублировать
    запись, если этот IP уже был правильно распознан основным циклом."""
    async with connect(db_path) as conn:
        cur = await conn.execute(
            "SELECT 1 FROM found_ips WHERE account_id = ? AND ip = ? LIMIT 1",
            (account_id, ip),
        )
        row = await cur.fetchone()
        return row is not None


async def mark_found_ip_notified(db_path: Path, found_ip_pk: int) -> None:
    async with connect(db_path) as conn:
        await conn.execute("UPDATE found_ips SET notified = 1 WHERE id = ?", (found_ip_pk,))
        await conn.commit()
