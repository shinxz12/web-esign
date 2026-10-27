"""Thiết bị đã cài agent, và những trình duyệt đã được kích hoạt trên thiết bị đó.

Mô hình plugin: agent thuộc về **máy**, không thuộc về tài khoản nào. Người dùng
cài agent một lần; agent tự mở trình duyệt mặc định đúng một lần để đổi lấy
cookie ``ws_device``. Từ đó mọi trang trên domain này đều tự thấy token đang
cắm — không còn phải gõ mã ghép cặp.

Ba bí mật, ba vai khác nhau:

``device_token``
    agent giữ trong ``~/.websigner/agent.json``. Chứng minh "tôi là máy X".
``ticket``
    sống 2 phút, dùng một lần, đi qua thanh địa chỉ. Chỉ để đổi lấy cookie.
``browser_token``
    nằm trong cookie ``ws_device``. Chứng minh "trình duyệt này đã được máy X
    xác nhận". Thu hồi riêng được, không lộ ``device_token`` ra trình duyệt.

Chỉ lưu SHA-256 của token: đọc được cơ sở dữ liệu cũng không giả mạo được agent.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from . import db
from .config import DATA_DIR
from .security import token_hash

logger = logging.getLogger("websigner.devices")

LEGACY_REGISTRY = DATA_DIR / "devices.json"

# Đủ cho trình duyệt mặc định khởi động nguội; ngắn hơn thì máy chậm sẽ hỏng.
TICKET_TTL_SECONDS = 120.0

# Ticket nằm trong RAM: mất khi restart là đúng — nó chỉ sống vài giây.
_tickets: dict[str, tuple[str, float]] = {}


class DeviceError(RuntimeError):
    """Token thiết bị không hợp lệ hoặc đã bị thu hồi."""


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    platform: str
    created_at: datetime
    last_seen: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "platform": self.platform,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "last_seen": self.last_seen.isoformat(timespec="seconds"),
        }


def _device(row: dict) -> Device:
    return Device(row["id"], row["name"], row["platform"], row["created_at"], row["last_seen"])


async def register(token: str, name: str, platform: str) -> Device:
    """Ghi danh máy chạy agent. Gọi lại với cùng token thì cập nhật, không nhân bản."""
    row = await db.fetchone(
        "INSERT INTO devices (id, token_hash, name, platform) VALUES (%s, %s, %s, %s) "
        "ON CONFLICT (token_hash) DO UPDATE SET name = EXCLUDED.name, "
        "platform = EXCLUDED.platform, last_seen = now() RETURNING *",
        (secrets.token_hex(8), token_hash(token), name, platform),
    )
    return _device(row)


async def by_token(token: str) -> Device:
    row = await db.fetchone("SELECT * FROM devices WHERE token_hash = %s", (token_hash(token),))
    if row is None:
        raise DeviceError("Thiết bị chưa đăng ký hoặc đã bị thu hồi")
    return _device(row)


async def by_id(device_id: str) -> Device | None:
    row = await db.fetchone("SELECT * FROM devices WHERE id = %s", (device_id,))
    return _device(row) if row else None


async def touch(device_id: str) -> None:
    """Ghi nhận agent vừa kết nối — để biết máy nào còn sống."""
    await db.execute("UPDATE devices SET last_seen = now() WHERE id = %s", (device_id,))


def issue_ticket(device_id: str) -> str:
    """Vé một lần để đổi lấy cookie thiết bị."""
    _expire_tickets()
    ticket = secrets.token_urlsafe(24)
    _tickets[ticket] = (device_id, time.monotonic() + TICKET_TTL_SECONDS)
    return ticket


async def claim_ticket(ticket: str) -> str:
    """-> device_id. Vé bị xoá ngay cả khi lỗi: dùng một lần là một lần."""
    _expire_tickets()
    entry = _tickets.pop(ticket, None)
    if entry is None:
        raise DeviceError("Liên kết kích hoạt đã hết hạn hoặc đã dùng rồi")
    device_id, _ = entry
    if await by_id(device_id) is None:
        raise DeviceError("Thiết bị đã bị thu hồi")
    return device_id


def _expire_tickets() -> None:
    now = time.monotonic()
    for ticket, (_, expires) in list(_tickets.items()):
        if expires <= now:
            _tickets.pop(ticket, None)


async def bind_browser(browser_token: str, device_id: str) -> None:
    await db.execute(
        "INSERT INTO device_browsers (token_hash, device_id) VALUES (%s, %s) "
        "ON CONFLICT (token_hash) DO UPDATE SET device_id = EXCLUDED.device_id, activated_at = now()",
        (token_hash(browser_token), device_id),
    )


async def browser_device(browser_token: str | None) -> Device | None:
    """Thiết bị mà trình duyệt này đã kích hoạt, None nếu chưa/đã bị thu hồi."""
    if not browser_token:
        return None
    row = await db.fetchone(
        "SELECT d.* FROM device_browsers b JOIN devices d ON d.id = b.device_id "
        "WHERE b.token_hash = %s",
        (token_hash(browser_token),),
    )
    return _device(row) if row else None


async def unbind_browser(browser_token: str | None) -> None:
    if browser_token:
        await db.execute("DELETE FROM device_browsers WHERE token_hash = %s", (token_hash(browser_token),))


async def forget(device_id: str) -> None:
    """Thu hồi máy: mọi trình duyệt đã kích hoạt theo nó mất hiệu lực ngay (cascade)."""
    await db.execute("DELETE FROM devices WHERE id = %s", (device_id,))


async def import_legacy_registry() -> int:
    """Chuyển ``devices.json`` của bản chạy bằng tệp sang cơ sở dữ liệu, một lần.

    Bản cũ lưu SHA-256 hex của cùng token, nên agent đã cài vẫn nối được mà
    không phải ghi danh lại. Xong thì đổi tên tệp để không nhập lần nữa.
    """
    if not LEGACY_REGISTRY.is_file():
        return 0
    data = json.loads(LEGACY_REGISTRY.read_text(encoding="utf-8"))
    imported = 0
    async with db.transaction() as conn:
        for device_id, record in (data.get("devices") or {}).items():
            cur = await conn.execute(
                "INSERT INTO devices (id, token_hash, name, platform, created_at, last_seen) "
                "VALUES (%s, %s, %s, %s, COALESCE(%s::timestamptz, now()), COALESCE(%s::timestamptz, now())) "
                "ON CONFLICT DO NOTHING",
                (
                    device_id,
                    bytes.fromhex(record["token_hash"]),
                    record.get("name") or "agent",
                    record.get("platform") or "?",
                    record.get("created_at") or None,
                    record.get("last_seen") or None,
                ),
            )
            imported += cur.rowcount
        for browser_hash, binding in (data.get("browsers") or {}).items():
            await conn.execute(
                "INSERT INTO device_browsers (token_hash, device_id) "
                "SELECT %s, id FROM devices WHERE id = %s ON CONFLICT DO NOTHING",
                (bytes.fromhex(browser_hash), binding.get("device_id")),
            )
    LEGACY_REGISTRY.rename(LEGACY_REGISTRY.with_suffix(".json.imported"))
    logger.info("Đã chuyển %d thiết bị từ %s sang cơ sở dữ liệu", imported, LEGACY_REGISTRY.name)
    return imported
