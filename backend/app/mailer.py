"""Email qua SMTP, gửi bất đồng bộ từ hàng đợi trong cơ sở dữ liệu.

Chưa cấu hình ``WEBSIGNER_SMTP_URL`` thì không xếp hàng gì cả: hệ thống tích
hợp tự gửi ``signing_url`` lấy từ API cho người ký (mô hình nhúng).
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid
from urllib.parse import unquote, urlsplit

from . import config, db

logger = logging.getLogger("websigner.mailer")

# Giãn dần: 1 phút, 5 phút, 30 phút, 2 giờ, rồi bỏ.
RETRY_DELAYS = (60, 300, 1800, 7200)


def enabled() -> bool:
    return config.SMTP_URL is not None


async def enqueue(conn: db.Conn, to: str | None, subject: str, body: str) -> bool:
    """Xếp email vào hàng đợi trong transaction của người gọi. -> đã xếp hay chưa."""
    if not enabled() or not to:
        return False
    await conn.execute(
        "INSERT INTO emails (to_addr, subject, body) VALUES (%s, %s, %s)",
        (to, subject, body),
    )
    return True


def _send_sync(to: str, subject: str, body: str) -> None:
    parts = urlsplit(config.SMTP_URL or "")
    host = parts.hostname or "localhost"
    scheme = parts.scheme.lower()
    message = EmailMessage()
    message["From"] = config.MAIL_FROM
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = make_msgid(domain="websigner")
    message.set_content(body)

    context = ssl.create_default_context()
    if scheme == "smtps":
        client: smtplib.SMTP = smtplib.SMTP_SSL(host, parts.port or 465, timeout=20, context=context)
    else:
        client = smtplib.SMTP(host, parts.port or 25, timeout=20)
    with client:
        if scheme == "smtp+starttls":
            client.starttls(context=context)
        if parts.username:
            client.login(unquote(parts.username), unquote(parts.password or ""))
        client.send_message(message)


async def send_due(limit: int = 20) -> int:
    """Gửi các email tới hạn. Nhiều tiến trình chạy cùng lúc cũng không gửi trùng."""
    if not enabled():
        return 0
    async with db.transaction() as conn:
        cur = await conn.execute(
            "SELECT id, to_addr, subject, body, attempts FROM emails "
            "WHERE status = 'pending' AND next_attempt_at <= now() "
            "ORDER BY next_attempt_at LIMIT %s FOR UPDATE SKIP LOCKED",
            (limit,),
        )
        rows = await cur.fetchall()
        if not rows:
            return 0
        # Giữ chỗ 10 phút: tiến trình chết giữa chừng thì lần sau gửi lại.
        await conn.execute(
            "UPDATE emails SET next_attempt_at = now() + interval '10 minutes' "
            "WHERE id = ANY(%s)",
            ([r["id"] for r in rows],),
        )

    for row in rows:
        try:
            await asyncio.to_thread(_send_sync, row["to_addr"], row["subject"], row["body"])
        except Exception as exc:  # SMTP có cả chục loại lỗi, loại nào cũng thử lại
            attempts = row["attempts"] + 1
            give_up = attempts > len(RETRY_DELAYS)
            logger.warning("Gửi email #%s thất bại (%s): %s", row["id"], attempts, exc)
            await db.execute(
                "UPDATE emails SET attempts = %s, last_error = %s, status = %s, "
                "next_attempt_at = now() + make_interval(secs => %s) WHERE id = %s",
                (
                    attempts,
                    str(exc)[:500],
                    "failed" if give_up else "pending",
                    0 if give_up else RETRY_DELAYS[attempts - 1],
                    row["id"],
                ),
            )
        else:
            await db.execute(
                "UPDATE emails SET status = 'sent', sent_at = now(), "
                "attempts = attempts + 1 WHERE id = %s",
                (row["id"],),
            )
    return len(rows)
