"""Việc nền chạy cùng tiến trình backend: webhook, email, hết hạn, dọn dẹp.

Hàng đợi nằm trong PostgreSQL và lấy việc bằng ``FOR UPDATE SKIP LOCKED``,
nên chạy thêm tiến trình worker cũng không gửi trùng.
"""

from __future__ import annotations

import asyncio
import logging
import time

from . import db, documents, mailer, security, webhooks

logger = logging.getLogger("websigner.worker")

POLL_SECONDS = 2.0
HOUSEKEEPING_SECONDS = 300.0


async def _housekeeping() -> None:
    await db.execute("DELETE FROM sessions WHERE expires_at < now()")
    await db.execute("DELETE FROM user_tokens WHERE expires_at < now()")
    await db.execute("DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours'")
    # Lịch sử gửi webhook giữ 30 ngày là đủ để tra soát.
    await db.execute(
        "DELETE FROM webhook_deliveries WHERE status <> 'pending' AND created_at < now() - interval '30 days'"
    )
    await db.execute("DELETE FROM emails WHERE status = 'sent' AND created_at < now() - interval '30 days'")
    security.limiter.prune()


async def run_once() -> int:
    work = await documents.expire_due()
    work += await webhooks.deliver_due()
    work += await mailer.send_due()
    return work


async def run_forever() -> None:
    last_housekeeping = 0.0
    while True:
        try:
            busy = await run_once()
            if time.monotonic() - last_housekeeping > HOUSEKEEPING_SECONDS:
                await _housekeeping()
                last_housekeeping = time.monotonic()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Vòng worker lỗi; thử lại ở chu kỳ sau")
            busy = 0
        if not busy:
            await webhooks.wait_for_work(POLL_SECONDS)
