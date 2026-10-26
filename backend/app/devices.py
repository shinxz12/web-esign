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

Chỉ lưu bản băm của token: đọc được tệp registry cũng không giả mạo được agent.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .store import DATA_DIR

REGISTRY = DATA_DIR / "devices.json"

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
    created_at: str
    last_seen: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "platform": self.platform,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _load() -> dict[str, Any]:
    if not REGISTRY.is_file():
        return {"devices": {}, "browsers": {}}
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    data.setdefault("devices", {})
    data.setdefault("browsers", {})
    return data


def _save(data: dict[str, Any]) -> None:
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    tmp = REGISTRY.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(REGISTRY)


def _device(device_id: str, record: dict[str, Any]) -> Device:
    return Device(
        id=device_id,
        name=record.get("name") or "agent",
        platform=record.get("platform") or "?",
        created_at=record.get("created_at") or "",
        last_seen=record.get("last_seen") or "",
    )


def register(token: str, name: str, platform: str) -> Device:
    """Ghi danh máy chạy agent. Gọi lại với cùng token thì cập nhật, không nhân bản."""
    data = _load()
    token_hash = _digest(token)
    for device_id, record in data["devices"].items():
        if secrets.compare_digest(record.get("token_hash", ""), token_hash):
            record.update(name=name, platform=platform, last_seen=_now())
            _save(data)
            return _device(device_id, record)

    device_id = secrets.token_hex(8)
    record = {
        "token_hash": token_hash,
        "name": name,
        "platform": platform,
        "created_at": _now(),
        "last_seen": _now(),
    }
    data["devices"][device_id] = record
    _save(data)
    return _device(device_id, record)


def by_token(token: str) -> Device:
    data = _load()
    token_hash = _digest(token)
    for device_id, record in data["devices"].items():
        if secrets.compare_digest(record.get("token_hash", ""), token_hash):
            return _device(device_id, record)
    raise DeviceError("Thiết bị chưa đăng ký hoặc đã bị thu hồi")


def by_id(device_id: str) -> Device | None:
    record = _load()["devices"].get(device_id)
    return _device(device_id, record) if record else None


def touch(device_id: str) -> None:
    """Ghi nhận agent vừa kết nối — để trang quản lý biết máy nào còn sống."""
    data = _load()
    record = data["devices"].get(device_id)
    if record is None:
        return
    record["last_seen"] = _now()
    _save(data)


def issue_ticket(device_id: str) -> str:
    """Vé một lần để đổi lấy cookie thiết bị."""
    _expire_tickets()
    ticket = secrets.token_urlsafe(24)
    _tickets[ticket] = (device_id, time.monotonic() + TICKET_TTL_SECONDS)
    return ticket


def claim_ticket(ticket: str) -> str:
    """-> device_id. Vé bị xoá ngay cả khi lỗi: dùng một lần là một lần."""
    _expire_tickets()
    entry = _tickets.pop(ticket, None)
    if entry is None:
        raise DeviceError("Liên kết kích hoạt đã hết hạn hoặc đã dùng rồi")
    device_id, _ = entry
    if by_id(device_id) is None:
        raise DeviceError("Thiết bị đã bị thu hồi")
    return device_id


def _expire_tickets() -> None:
    now = time.monotonic()
    for ticket, (_, expires) in list(_tickets.items()):
        if expires <= now:
            _tickets.pop(ticket, None)


def bind_browser(browser_token: str, device_id: str) -> None:
    data = _load()
    data["browsers"][_digest(browser_token)] = {
        "device_id": device_id,
        "activated_at": _now(),
    }
    _save(data)


def browser_device(browser_token: str | None) -> Device | None:
    """Thiết bị mà trình duyệt này đã kích hoạt, None nếu chưa/đã bị thu hồi."""
    if not browser_token:
        return None
    binding = _load()["browsers"].get(_digest(browser_token))
    return by_id(binding["device_id"]) if binding else None


def unbind_browser(browser_token: str | None) -> None:
    if not browser_token:
        return
    data = _load()
    if data["browsers"].pop(_digest(browser_token), None) is not None:
        _save(data)


def forget(device_id: str) -> None:
    """Thu hồi máy: mọi trình duyệt đã kích hoạt theo nó mất hiệu lực ngay."""
    data = _load()
    data["devices"].pop(device_id, None)
    data["browsers"] = {
        key: value
        for key, value in data["browsers"].items()
        if value.get("device_id") != device_id
    }
    _save(data)
