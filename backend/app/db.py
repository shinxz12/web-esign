"""PostgreSQL: pool kết nối async, vài hàm truy vấn mỏng và trình chạy migration.

Không ORM. Mỗi module nghiệp vụ tự viết SQL của nó; ở đây chỉ có đường ống.
Kết nối mở ở chế độ autocommit — câu lệnh lẻ tự commit, còn chỗ nào cần
nhiều câu lệnh nguyên tử thì dùng ``transaction()``.
"""

from __future__ import annotations

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


async def open_pool(url: str | None = None) -> None:
    global _pool
    if _pool is not None:
        return
    pool = AsyncConnectionPool(
        url or config.DATABASE_URL,
        min_size=2,
        max_size=config.DB_POOL_SIZE,
        # Mọi thời điểm trả ra API đều ở UTC, không phụ thuộc cấu hình máy chủ DB.
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


@asynccontextmanager
async def connection() -> AsyncIterator[Conn]:
    async with _require_pool().connection() as conn:
        yield conn


@asynccontextmanager
async def transaction() -> AsyncIterator[Conn]:
    async with _require_pool().connection() as conn:
        async with conn.transaction():
            yield conn


async def fetchone(sql: str, params: Any = None, *, conn: Conn | None = None) -> dict | None:
    if conn is not None:
        cur = await conn.execute(sql, params)
        return await cur.fetchone()
    async with connection() as own:
        cur = await own.execute(sql, params)
        return await cur.fetchone()


async def fetchall(sql: str, params: Any = None, *, conn: Conn | None = None) -> list[dict]:
    if conn is not None:
        cur = await conn.execute(sql, params)
        return await cur.fetchall()
    async with connection() as own:
        cur = await own.execute(sql, params)
        return await cur.fetchall()


async def execute(sql: str, params: Any = None, *, conn: Conn | None = None) -> int:
    """-> số dòng bị ảnh hưởng."""
    if conn is not None:
        cur = await conn.execute(sql, params)
        return cur.rowcount
    async with connection() as own:
        cur = await own.execute(sql, params)
        return cur.rowcount


async def migrate() -> None:
    """Chạy các tệp ``migrations/NNN_*.sql`` chưa áp dụng, theo thứ tự tên.

    Khoá advisory để nhiều tiến trình khởi động cùng lúc không chạy chồng nhau.
    """
    async with connection() as conn:
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
