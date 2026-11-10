"""PostgreSQL: pool kết nối async, phân tách truy cập tenant và system per SPEC §3.

- Mặc định mọi truy vấn là tenant-scoped:
    SET LOCAL ROLE websigner_tenant;
    SELECT set_config('app.tenant_id', $1, true);
  Đòi hỏi phải có tenant_id (từ contextvar hoặc tham số org_id).
- Truy cập hệ thống (cross-tenant) được đặt tên rõ ràng:
    system_connection, system_transaction, system_fetchone, system_fetchall, system_execute,
    hoặc qua namespace db.system.*.
"""

from __future__ import annotations

import contextvars
import logging
import pathlib
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from . import config

logger = logging.getLogger("websigner.db")

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parent / "migrations"

_pool: AsyncConnectionPool | None = None

Conn = AsyncConnection

_current_tenant_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_tenant_id", default=None
)


def current_tenant_id() -> str | None:
    return _current_tenant_id.get()


def set_tenant_id(org_id: str | None) -> contextvars.Token[str | None]:
    return _current_tenant_id.set(org_id)


def reset_tenant_id(token: contextvars.Token[str | None]) -> None:
    _current_tenant_id.reset(token)


class TenantScope:
    def __init__(self, org_id: str) -> None:
        self.org_id = org_id
        self.token: contextvars.Token[str | None] | None = None

    def __enter__(self) -> TenantScope:
        self.token = _current_tenant_id.set(self.org_id)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.token is not None:
            _current_tenant_id.reset(self.token)

    async def __aenter__(self) -> TenantScope:
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


def tenant_scope(org_id: str) -> TenantScope:
    return TenantScope(org_id)


async def open_pool(url: str | None = None) -> None:
    global _pool
    if _pool is not None:
        return
    pool = AsyncConnectionPool(
        url or config.DATABASE_URL,
        min_size=2,
        max_size=config.DB_POOL_SIZE,
        kwargs={"row_factory": dict_row, "autocommit": True, "options": "-c TimeZone=UTC"},
        open=False,
    )
    await pool.open(wait=True, timeout=15)
    _pool = pool
    await migrate()


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def _require_pool() -> AsyncConnectionPool:
    if _pool is None:
        raise RuntimeError("Chưa mở kết nối cơ sở dữ liệu")
    return _pool

def is_pool_open() -> bool:
    return _pool is not None


async def take_rate_limit(key: str, per_minute: int, burst: int | None = None) -> float | None:
    row = await system_fetchone(
        "SELECT take_rate_limit(%s, %s, %s) AS wait",
        (key, per_minute, burst),
    )
    if not row or row["wait"] is None or row["wait"] <= 0.0:
        return None
    return float(row["wait"])


# -----------------------------------------------------------------------------
# Lối vào mặc định: Tenant-Scoped (SPEC §3)
# -----------------------------------------------------------------------------


@asynccontextmanager
async def transaction(org_id: str | None = None) -> AsyncIterator[Conn]:
    target_org = org_id or current_tenant_id()
    if not target_org:
        raise RuntimeError("Tenant scope required: no active tenant_id")
    async with _require_pool().connection() as conn:
        async with conn.transaction():
            await conn.execute("SET LOCAL ROLE websigner_tenant")
            await conn.execute("SELECT set_config('app.tenant_id', %s, true)", (target_org,))
            yield conn


@asynccontextmanager
async def connection(org_id: str | None = None) -> AsyncIterator[Conn]:
    """Mở kết nối có giới hạn RLS cho tenant."""
    async with transaction(org_id=org_id) as conn:
        yield conn


async def fetchone(
    sql: str, params: Any = None, *, conn: Conn | None = None, org_id: str | None = None
) -> dict | None:
    if conn is not None:
        cur = await conn.execute(sql, params)
        return await cur.fetchone()
    async with transaction(org_id=org_id) as own:
        cur = await own.execute(sql, params)
        return await cur.fetchone()


async def fetchall(
    sql: str, params: Any = None, *, conn: Conn | None = None, org_id: str | None = None
) -> list[dict]:
    if conn is not None:
        cur = await conn.execute(sql, params)
        return await cur.fetchall()
    async with transaction(org_id=org_id) as own:
        cur = await own.execute(sql, params)
        return await cur.fetchall()


async def execute(
    sql: str, params: Any = None, *, conn: Conn | None = None, org_id: str | None = None
) -> int:
    """-> số dòng bị ảnh hưởng."""
    if conn is not None:
        cur = await conn.execute(sql, params)
        return cur.rowcount
    async with transaction(org_id=org_id) as own:
        cur = await own.execute(sql, params)
        return cur.rowcount


# -----------------------------------------------------------------------------
# Lối vào hệ thống: Cross-Tenant / System Scoped (SPEC §3)
# -----------------------------------------------------------------------------


@asynccontextmanager
async def system_connection() -> AsyncIterator[Conn]:
    async with _require_pool().connection() as conn:
        yield conn


@asynccontextmanager
async def system_transaction() -> AsyncIterator[Conn]:
    async with _require_pool().connection() as conn:
        async with conn.transaction():
            yield conn


async def system_fetchone(sql: str, params: Any = None, *, conn: Conn | None = None) -> dict | None:
    if conn is not None:
        cur = await conn.execute(sql, params)
        return await cur.fetchone()
    async with system_connection() as own:
        cur = await own.execute(sql, params)
        return await cur.fetchone()


async def system_fetchall(sql: str, params: Any = None, *, conn: Conn | None = None) -> list[dict]:
    if conn is not None:
        cur = await conn.execute(sql, params)
        return await cur.fetchall()
    async with system_connection() as own:
        cur = await own.execute(sql, params)
        return await cur.fetchall()


async def system_execute(sql: str, params: Any = None, *, conn: Conn | None = None) -> int:
    if conn is not None:
        cur = await conn.execute(sql, params)
        return cur.rowcount
    async with system_transaction() as own:
        cur = await own.execute(sql, params)
        return cur.rowcount


class _SystemNamespace:
    connection = staticmethod(system_connection)
    transaction = staticmethod(system_transaction)
    fetchone = staticmethod(system_fetchone)
    fetchall = staticmethod(system_fetchall)
    execute = staticmethod(system_execute)


system = _SystemNamespace()


# -----------------------------------------------------------------------------
# Trình chạy migration
# -----------------------------------------------------------------------------


async def migrate() -> None:
    """Chạy các tệp ``migrations/NNN_*.sql`` chưa áp dụng bằng kết nối system."""
    async with system_connection() as conn:
        await conn.execute("SELECT pg_advisory_lock(hashtext('websigner_migrations'))")
        try:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                " version text PRIMARY KEY,"
                " applied_at timestamptz NOT NULL DEFAULT now())"
            )
            cur = await conn.execute("SELECT version FROM schema_migrations")
            applied = {row["version"] for row in await cur.fetchall()}
            for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
                if path.stem in applied:
                    continue
                logger.info("Áp dụng migration %s", path.name)
                async with conn.transaction():
                    await conn.execute(path.read_text(encoding="utf-8"))
                    await conn.execute(
                        "INSERT INTO schema_migrations (version) VALUES (%s)", (path.stem,)
                    )
        finally:
            await conn.execute("SELECT pg_advisory_unlock(hashtext('websigner_migrations'))")
