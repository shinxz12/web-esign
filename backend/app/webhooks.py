"""Webhook: báo cho hệ thống tích hợp biết tài liệu đổi trạng thái.

* Outbox: sự kiện được ghi vào ``webhook_deliveries`` **cùng transaction**
  với thay đổi nghiệp vụ — không có chuyện tài liệu hoàn tất mà webhook mất.
* Ký: header ``WebSigner-Signature: t=<unix>,v1=<hex>``, HMAC-SHA256 trên
  ``"<t>." + body`` bằng secret riêng của endpoint (giống Stripe).
* Chống SSRF: chỉ gọi HTTPS tới địa chỉ công cộng. Kiểm tra IP **lúc kết nối**
  (resolver riêng), nên DNS rebinding cũng không lọt vào mạng nội bộ.
* Thử lại giãn dần tới ~1 ngày rồi đánh dấu thất bại; gửi lại tay được.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import ResolveResult
from aiohttp.resolver import ThreadedResolver

from . import config, db, plans, security
from .errors import ApiError, not_found

logger = logging.getLogger("websigner.webhooks")

EVENT_TYPES = (
    "document.sent",
    "document.completed",
    "document.declined",
    "document.voided",
    "document.expired",
    "recipient.viewed",
    "recipient.signed",
    "recipient.approved",
    "recipient.declined",
)
TEST_EVENT = "webhook.test"

# 10 giây, 1 phút, 5 phút, 30 phút, 2 giờ, 6 giờ, 12 giờ -> tổng ~21 giờ.
RETRY_DELAYS = (10, 60, 300, 1800, 7200, 21600, 43200)
TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)


# --------------------------------------------------------------------------
# Chống SSRF
# --------------------------------------------------------------------------


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


class PublicOnlyResolver(ThreadedResolver):
    """Từ chối kết nối nếu tên miền trỏ tới bất kỳ địa chỉ nội bộ nào."""

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        results = await super().resolve(host, port, family)
        for result in results:
            if not _is_public(result["host"]):
                raise OSError(f"{host} trỏ tới địa chỉ nội bộ {result['host']}")
        return results


def validate_url(url: str) -> str:
    url = url.strip()
    parts = urlsplit(url)
    allowed = ("https", "http") if config.WEBHOOK_ALLOW_PRIVATE else ("https",)
    if parts.scheme not in allowed or not parts.hostname:
        raise ApiError(400, "invalid_url", "URL webhook phải là https://…")
    if parts.username or parts.password:
        raise ApiError(400, "invalid_url", "URL webhook không được chứa thông tin đăng nhập")
    if len(url) > 2000:
        raise ApiError(400, "invalid_url", "URL webhook quá dài")
    if not config.WEBHOOK_ALLOW_PRIVATE:
        host = parts.hostname
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and not _is_public(host):
            raise ApiError(400, "invalid_url", "URL webhook không được trỏ vào mạng nội bộ")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ApiError(400, "invalid_url", "URL webhook không được trỏ vào mạng nội bộ")
    return url


def _validate_events(events: list[str]) -> list[str]:
    if not events or events == ["*"]:
        return ["*"]
    unknown = sorted(set(events) - set(EVENT_TYPES))
    if unknown:
        raise ApiError(400, "invalid_events", f"Sự kiện không hỗ trợ: {', '.join(unknown)}")
    return sorted(set(events))


# --------------------------------------------------------------------------
# Quản lý endpoint
# --------------------------------------------------------------------------


def endpoint_view(row: dict, *, reveal_secret: bool = False) -> dict:
    view = {
        "id": row["id"],
        "url": row["url"],
        "description": row["description"],
        "events": row["events"],
        "enabled": row["enabled"],
        "created_at": row["created_at"].isoformat(),
    }
    if reveal_secret:
        view["secret"] = security.webhook_secret(row["id"], row["secret_version"])
    return view


async def create_endpoint(
    org: dict, url: str, events: list[str], description: str | None
) -> dict:
    plan = plans.get(org["plan"])
    url = validate_url(url)
    events = _validate_events(events)
    async with db.transaction() as conn:
        cur = await conn.execute(
            "SELECT count(*) AS n FROM webhook_endpoints WHERE org_id = %s", (org["id"],)
        )
        if (await cur.fetchone())["n"] >= plan.max_webhooks:
            raise ApiError(
                402, "quota_exceeded", f"Gói {plan.name} tối đa {plan.max_webhooks} webhook"
            )
        cur = await conn.execute(
            "INSERT INTO webhook_endpoints (id, org_id, url, description, events) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING *",
            (security.new_id("wh"), org["id"], url, description, events),
        )
        return endpoint_view(await cur.fetchone(), reveal_secret=True)


async def _endpoint(org_id: str, endpoint_id: str) -> dict:
    row = await db.fetchone(
        "SELECT * FROM webhook_endpoints WHERE id = %s AND org_id = %s", (endpoint_id, org_id)
    )
    if row is None:
        raise not_found("Không tìm thấy webhook")
    return row


async def get_endpoint(org_id: str, endpoint_id: str) -> dict:
    return endpoint_view(await _endpoint(org_id, endpoint_id), reveal_secret=True)


async def list_endpoints(org_id: str) -> list[dict]:
    rows = await db.fetchall(
        "SELECT * FROM webhook_endpoints WHERE org_id = %s ORDER BY created_at", (org_id,)
    )
    return [endpoint_view(r) for r in rows]


async def update_endpoint(org_id: str, endpoint_id: str, changes: dict[str, Any]) -> dict:
    row = await _endpoint(org_id, endpoint_id)
    url = validate_url(changes["url"]) if changes.get("url") is not None else row["url"]
    events = _validate_events(changes["events"]) if changes.get("events") is not None else row["events"]
    description = changes.get("description", row["description"])
    enabled = changes["enabled"] if changes.get("enabled") is not None else row["enabled"]
    updated = await db.fetchone(
        "UPDATE webhook_endpoints SET url = %s, events = %s, description = %s, enabled = %s "
        "WHERE id = %s RETURNING *",
        (url, events, description, enabled, endpoint_id),
    )
    return endpoint_view(updated)


async def rotate_secret(org_id: str, endpoint_id: str) -> dict:
    await _endpoint(org_id, endpoint_id)
    row = await db.fetchone(
        "UPDATE webhook_endpoints SET secret_version = secret_version + 1 WHERE id = %s RETURNING *",
        (endpoint_id,),
    )
    return endpoint_view(row, reveal_secret=True)


async def delete_endpoint(org_id: str, endpoint_id: str) -> None:
    if not await db.execute(
        "DELETE FROM webhook_endpoints WHERE id = %s AND org_id = %s", (endpoint_id, org_id)
    ):
        raise not_found("Không tìm thấy webhook")


def delivery_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "event_id": row["event_id"],
        "event_type": row["event_type"],
        "status": row["status"],
        "attempts": row["attempts"],
        "next_attempt_at": row["next_attempt_at"].isoformat() if row["status"] == "pending" else None,
        "last_status_code": row["last_status_code"],
        "last_error": row["last_error"],
        "created_at": row["created_at"].isoformat(),
        "delivered_at": row["delivered_at"].isoformat() if row["delivered_at"] else None,
        "payload": row["payload"],
    }


async def list_deliveries(org_id: str, endpoint_id: str, limit: int = 50) -> list[dict]:
    await _endpoint(org_id, endpoint_id)
    rows = await db.fetchall(
        "SELECT * FROM webhook_deliveries WHERE endpoint_id = %s "
        "ORDER BY created_at DESC LIMIT %s",
        (endpoint_id, limit),
    )
    return [delivery_view(r) for r in rows]


async def retry_delivery(org_id: str, endpoint_id: str, delivery_id: str) -> dict:
    await _endpoint(org_id, endpoint_id)
    row = await db.fetchone(
        "UPDATE webhook_deliveries SET status = 'pending', next_attempt_at = now() "
        "WHERE id = %s AND endpoint_id = %s RETURNING *",
        (delivery_id, endpoint_id),
    )
    if row is None:
        raise not_found("Không tìm thấy lần gửi")
    wake()
    return delivery_view(row)


async def send_test(org: dict, endpoint_id: str) -> dict:
    endpoint = await _endpoint(org["id"], endpoint_id)
    event = _event(TEST_EVENT, {"organization": {"id": org["id"], "name": org["name"]}})
    row = await db.fetchone(
        "INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING *",
        (security.new_id("whd"), endpoint["id"], event["id"], TEST_EVENT, json.dumps(event)),
    )
    wake()
    return delivery_view(row)


# --------------------------------------------------------------------------
# Phát sự kiện và gửi
# --------------------------------------------------------------------------

_wakeup = asyncio.Event()


def wake() -> None:
    """Đánh thức worker ngay thay vì chờ chu kỳ quét kế tiếp."""
    _wakeup.set()


async def wait_for_work(timeout: float) -> None:
    try:
        await asyncio.wait_for(_wakeup.wait(), timeout)
    except asyncio.TimeoutError:
        pass
    _wakeup.clear()


def _event(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": security.new_id("evt"),
        "type": event_type,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "data": data,
    }


async def enqueue(conn: db.Conn, org_id: str, event_type: str, data: dict[str, Any]) -> None:
    """Xếp sự kiện cho mọi endpoint đang bật có đăng ký loại này."""
    cur = await conn.execute(
        "SELECT id FROM webhook_endpoints WHERE org_id = %s AND enabled "
        "AND ('*' = ANY(events) OR %s = ANY(events))",
        (org_id, event_type),
    )
    endpoints = await cur.fetchall()
    if not endpoints:
        return
    event = _event(event_type, data)
    payload = json.dumps(event, ensure_ascii=False)
    for endpoint in endpoints:
        await conn.execute(
            "INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload) "
            "VALUES (%s, %s, %s, %s, %s)",
            (security.new_id("whd"), endpoint["id"], event["id"], event_type, payload),
        )


def _connector() -> aiohttp.TCPConnector:
    if config.WEBHOOK_ALLOW_PRIVATE:
        return aiohttp.TCPConnector(limit=20)
    return aiohttp.TCPConnector(limit=20, resolver=PublicOnlyResolver(), use_dns_cache=False)


async def _post(session: aiohttp.ClientSession, row: dict) -> tuple[int | None, str | None]:
    url = row["url"]
    host = urlsplit(url).hostname or ""
    if not config.WEBHOOK_ALLOW_PRIVATE:
        # IP ghi thẳng trong URL không đi qua resolver: phải tự chặn.
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and not _is_public(host):
            return None, "URL trỏ vào mạng nội bộ"

    body = json.dumps(row["payload"], ensure_ascii=False, separators=(",", ":")).encode()
    timestamp = int(time.time())
    secret = security.webhook_secret(row["endpoint_id"], row["secret_version"])
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "WebSigner-Webhooks/1.0",
        "WebSigner-Event": row["event_type"],
        "WebSigner-Event-Id": row["event_id"],
        "WebSigner-Delivery": row["id"],
        "WebSigner-Signature": f"t={timestamp},v1={security.sign_webhook(secret, timestamp, body)}",
    }
    try:
        async with session.post(url, data=body, headers=headers, allow_redirects=False) as resp:
            await resp.content.read(1024)  # đọc ít, đủ để giải phóng kết nối
            if 200 <= resp.status < 300:
                return resp.status, None
            return resp.status, f"HTTP {resp.status}"
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"[:500]


async def deliver_due(limit: int = 50) -> int:
    async with db.transaction() as conn:
        cur = await conn.execute(
            "SELECT d.*, e.url, e.secret_version FROM webhook_deliveries d "
            "JOIN webhook_endpoints e ON e.id = d.endpoint_id "
            "WHERE d.status = 'pending' AND d.next_attempt_at <= now() "
            "ORDER BY d.next_attempt_at LIMIT %s FOR UPDATE OF d SKIP LOCKED",
            (limit,),
        )
        rows = await cur.fetchall()
        if not rows:
            return 0
        await conn.execute(
            "UPDATE webhook_deliveries SET next_attempt_at = now() + interval '5 minutes' "
            "WHERE id = ANY(%s)",
            ([r["id"] for r in rows],),
        )

    async with aiohttp.ClientSession(connector=_connector(), timeout=TIMEOUT) as session:
        results = await asyncio.gather(*(_post(session, row) for row in rows))

    for row, (status_code, error) in zip(rows, results):
        attempts = row["attempts"] + 1
        if error is None:
            await db.execute(
                "UPDATE webhook_deliveries SET status = 'succeeded', attempts = %s, "
                "last_status_code = %s, last_error = NULL, delivered_at = now() WHERE id = %s",
                (attempts, status_code, row["id"]),
            )
            continue
        give_up = attempts > len(RETRY_DELAYS)
        logger.info("Webhook %s lần %s thất bại: %s", row["id"], attempts, error)
        await db.execute(
            "UPDATE webhook_deliveries SET status = %s, attempts = %s, last_status_code = %s, "
            "last_error = %s, next_attempt_at = now() + make_interval(secs => %s) WHERE id = %s",
            (
                "failed" if give_up else "pending",
                attempts,
                status_code,
                error,
                0 if give_up else RETRY_DELAYS[attempts - 1],
                row["id"],
            ),
        )
    return len(rows)
