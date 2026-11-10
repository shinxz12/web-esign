"""Relay giữa browser và agent qua WebSocket và PostgreSQL LISTEN/NOTIFY.

Khi backend chạy N>1 tiến trình sau load balancer:
- Agent kết nối WebSocket vào Instance A.
- Browser gửi request HTTP vào Instance B.
- Instance B chuyển tiếp yêu cầu tới Instance A qua bảng agent_relay_requests và
  PostgreSQL NOTIFY (chỉ mang request_id).
- Instance A gửi gói tin qua WebSocket tới Agent, nhận phản hồi, ghi kết quả vào
  PostgreSQL và NOTIFY lại Instance B.
- Trường hợp Agent kết nối trực tiếp trên cùng một tiến trình, relay thực hiện
  gọi WebSocket thẳng trong bộ nhớ.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import WebSocket
import psycopg
from psycopg.rows import dict_row

from . import config, db

logger = logging.getLogger("websigner.relay")

REQUEST_TIMEOUT = 180.0  # người dùng còn phải nhập PIN của token
INSTANCE_ID = secrets.token_hex(6)


class AgentUnavailable(RuntimeError):
    pass


class AgentError(RuntimeError):
    pass


@dataclass
class AgentSession:
    code: str
    name: str
    platform: str
    websocket: WebSocket | None = None
    device_id: str | None = None
    instance_id: str = ""
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    pending: dict[str, asyncio.Future] = field(default_factory=dict)
    certificates: dict[str, dict[str, Any]] = field(default_factory=dict)

    async def call(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self.websocket is not None:
            request_id = secrets.token_hex(8)
            future: asyncio.Future = asyncio.get_running_loop().create_future()
            self.pending[request_id] = future
            try:
                await self.websocket.send_json(
                    {"id": request_id, "type": kind, **payload}
                )
                return await asyncio.wait_for(future, timeout=REQUEST_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise AgentError("Agent không phản hồi (hết thời gian chờ)") from exc
            finally:
                self.pending.pop(request_id, None)
        else:
            return await hub.call_remote(self, kind, payload)

    def resolve(self, message: dict[str, Any]) -> None:
        future = self.pending.get(message.get("id", ""))
        if future is None or future.done():
            return
        if message.get("ok"):
            future.set_result(message.get("data") or {})
        else:
            future.set_exception(
                AgentError(message.get("error") or "Agent báo lỗi không rõ")
            )

    async def save_certificates(self, certs: dict[str, dict[str, Any]]) -> None:
        self.certificates = certs
        if db.is_pool_open():
            await db.system_execute(
                "UPDATE agent_sessions SET certificates = %s WHERE id = %s",
                (json.dumps(certs), self.id),
            )

    async def refresh_certificates(self) -> None:
        if db.is_pool_open():
            row = await db.system_fetchone(
                "SELECT certificates FROM agent_sessions WHERE id = %s",
                (self.id,),
            )
            if row and row.get("certificates"):
                self.certificates = row["certificates"]


class AgentHub:
    def __init__(self) -> None:
        self.instance_id = INSTANCE_ID
        self._local_sessions: dict[str, AgentSession] = {}
        self._local_by_code: dict[str, AgentSession] = {}
        self._local_by_device: dict[str, AgentSession] = {}
        self._pending_responses: dict[str, asyncio.Future] = {}
        self._forwarded_requests: dict[str, str] = {}  # req_id -> session_id
        self._listener_task: asyncio.Task | None = None
        self._listener_stop: asyncio.Event | None = None

    async def register(self, session: AgentSession) -> None:
        session.instance_id = self.instance_id
        if not session.id:
            session.id = secrets.token_hex(8)

        # 1. Thu hồi các phiên cũ trùng mã ghép cặp hoặc trùng thiết bị
        if db.is_pool_open():
            rows = await db.system_fetchall(
                "SELECT id, instance_id FROM agent_sessions WHERE code = %s OR (device_id IS NOT NULL AND device_id = %s)",
                (session.code, session.device_id),
            )
            for r in rows:
                old_id, old_inst = r["id"], r["instance_id"]
                if old_inst == self.instance_id:
                    old_sess = self._local_sessions.get(old_id)
                    if old_sess and old_sess is not session:
                        self._drop(old_sess)
                else:
                    await db.system_execute("SELECT pg_notify('agent_control', %s)", (old_id,))
            await db.system_execute(
                "DELETE FROM agent_sessions WHERE code = %s OR (device_id IS NOT NULL AND device_id = %s)",
                (session.code, session.device_id),
            )

            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
            await db.system_execute(
                "INSERT INTO agent_sessions (id, code, device_id, name, platform, instance_id, certificates, expires_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    session.id,
                    session.code,
                    session.device_id,
                    session.name,
                    session.platform,
                    session.instance_id,
                    json.dumps(session.certificates),
                    expires_at,
                ),
            )

        # 2. Lưu vào RAM local
        self._local_sessions[session.id] = session
        self._local_by_code[session.code] = session
        if session.device_id:
            prev = self._local_by_device.get(session.device_id)
            if prev is not None and prev is not session:
                self._drop(prev)
            self._local_by_device[session.device_id] = session

    async def unregister(self, session: AgentSession) -> None:
        self._local_sessions.pop(session.id, None)
        if self._local_by_code.get(session.code) is session:
            self._local_by_code.pop(session.code, None)
        if session.device_id and self._local_by_device.get(session.device_id) is session:
            self._local_by_device.pop(session.device_id, None)

        if db.is_pool_open():
            await db.system_execute("DELETE FROM agent_sessions WHERE id = %s", (session.id,))
            await db.system_execute(
                "UPDATE agent_relay_requests SET status = 'error', error = 'Agent đã ngắt kết nối' "
                "WHERE session_id = %s AND status = 'pending'",
                (session.id,),
            )
        self._drop(session)

    def _drop(self, session: AgentSession) -> None:
        for future in list(session.pending.values()):
            if not future.done():
                future.set_exception(AgentError("Agent đã ngắt kết nối"))
        session.pending.clear()
        if session.websocket is not None:
            try:
                asyncio.create_task(
                    session.websocket.close(code=4409, reason="Phiên mới thay thế")
                )
            except Exception:
                pass
            session.websocket = None

    async def get(self, code: str) -> AgentSession:
        local = self._local_by_code.get(code)
        if local is not None and local.websocket is not None:
            return local

        if db.is_pool_open():
            row = await db.system_fetchone(
                "SELECT * FROM agent_sessions WHERE code = %s AND expires_at > now()",
                (code,),
            )
            if row:
                return AgentSession(
                    id=row["id"],
                    code=row["code"],
                    name=row["name"],
                    platform=row["platform"],
                    device_id=row["device_id"],
                    instance_id=row["instance_id"],
                    certificates=row["certificates"] or {},
                    websocket=None,
                )

        raise AgentUnavailable(
            "Không tìm thấy agent với mã này. Kiểm tra agent đã chạy chưa."
        )

    async def for_device(self, device_id: str) -> AgentSession:
        local = self._local_by_device.get(device_id)
        if local is not None and local.websocket is not None:
            return local

        if db.is_pool_open():
            row = await db.system_fetchone(
                "SELECT * FROM agent_sessions WHERE device_id = %s AND expires_at > now()",
                (device_id,),
            )
            if row:
                return AgentSession(
                    id=row["id"],
                    code=row["code"],
                    name=row["name"],
                    platform=row["platform"],
                    device_id=row["device_id"],
                    instance_id=row["instance_id"],
                    certificates=row["certificates"] or {},
                    websocket=None,
                )

        raise AgentUnavailable("Agent trên máy này chưa chạy")

    async def device_online(self, device_id: str) -> bool:
        if device_id in self._local_by_device:
            return True
        if db.is_pool_open():
            row = await db.system_fetchone(
                "SELECT 1 FROM agent_sessions WHERE device_id = %s AND expires_at > now()",
                (device_id,),
            )
            return row is not None
        return False

    @property
    def online(self) -> int:
        return len(self._local_by_code)

    async def handle_agent_message(self, session: AgentSession, message: dict[str, Any]) -> None:
        req_id = message.get("id", "")
        if req_id in self._forwarded_requests:
            self._forwarded_requests.pop(req_id, None)
            if db.is_pool_open():
                if message.get("ok"):
                    await db.system_execute(
                        "UPDATE agent_relay_requests SET status = 'completed', response = %s WHERE id = %s",
                        (json.dumps(message.get("data") or {}), req_id),
                    )
                else:
                    await db.system_execute(
                        "UPDATE agent_relay_requests SET status = 'error', error = %s WHERE id = %s",
                        (message.get("error") or "Agent báo lỗi không rõ", req_id),
                    )
                await db.system_execute("SELECT pg_notify('agent_responses', %s)", (req_id,))
        else:
            session.resolve(message)

    async def call_remote(self, session: AgentSession, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        request_id = secrets.token_hex(8)
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending_responses[request_id] = future

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=REQUEST_TIMEOUT + 10)
        await db.system_execute(
            "INSERT INTO agent_relay_requests (id, session_id, target_instance, kind, payload, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (request_id, session.id, session.instance_id, kind, json.dumps(payload), expires_at),
        )
        await db.system_execute("SELECT pg_notify('agent_requests', %s)", (request_id,))

        try:
            deadline = time.monotonic() + REQUEST_TIMEOUT
            while time.monotonic() < deadline:
                chunk = min(2.0, max(0.1, deadline - time.monotonic()))
                try:
                    return await asyncio.wait_for(asyncio.shield(future), timeout=chunk)
                except asyncio.TimeoutError:
                    if future.done():
                        return future.result()
                    # Fallback poll phòng trường hợp NOTIFY bị lỡ
                    row = await db.system_fetchone(
                        "SELECT status, response, error FROM agent_relay_requests WHERE id = %s",
                        (request_id,),
                    )
                    if row and row["status"] == "completed":
                        return row["response"] or {}
                    elif row and row["status"] == "error":
                        raise AgentError(row["error"] or "Agent báo lỗi không rõ")
            raise AgentError("Agent không phản hồi (hết thời gian chờ)")
        except asyncio.TimeoutError:
            raise AgentError("Agent không phản hồi (hết thời gian chờ)")
        finally:
            self._pending_responses.pop(request_id, None)
            with contextlib.suppress(Exception):
                await db.system_execute("DELETE FROM agent_relay_requests WHERE id = %s", (request_id,))

    async def start_listener(self) -> None:
        if self._listener_task is not None:
            return
        self._listener_stop = asyncio.Event()
        self._listener_task = asyncio.create_task(self._listen_loop(), name="relay-listener")

    async def stop_listener(self) -> None:
        if self._listener_stop is not None:
            self._listener_stop.set()
        if self._listener_task is not None:
            self._listener_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._listener_task
            self._listener_task = None
        if db.is_pool_open():
            with contextlib.suppress(Exception):
                await db.system_execute(
                    "DELETE FROM agent_sessions WHERE instance_id = %s",
                    (self.instance_id,),
                )

    async def _listen_loop(self) -> None:
        while self._listener_stop is not None and not self._listener_stop.is_set():
            conn: psycopg.AsyncConnection | None = None
            try:
                conn = await psycopg.AsyncConnection.connect(
                    config.DATABASE_URL,
                    autocommit=True,
                    row_factory=dict_row,
                )
                await conn.execute("LISTEN agent_requests; LISTEN agent_responses; LISTEN agent_control;")
                while self._listener_stop is not None and not self._listener_stop.is_set():
                    async for notify in conn.notifies(timeout=1.0):
                        await self._on_notify(notify.channel, notify.payload)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                if self._listener_stop is not None and not self._listener_stop.is_set():
                    logger.exception("Relay listener lỗi kết nối: %r; thử lại sau 1s", exc)
                    await asyncio.sleep(1.0)
            finally:
                if conn is not None:
                    with contextlib.suppress(Exception):
                        await conn.close()

    async def _on_notify(self, channel: str, payload: str) -> None:
        if channel == "agent_requests":
            request_id = payload
            row = await db.system_fetchone(
                "SELECT * FROM agent_relay_requests WHERE id = %s AND target_instance = %s AND status = 'pending'",
                (request_id, self.instance_id),
            )
            if not row:
                return

            local_sess = self._local_sessions.get(row["session_id"])
            if local_sess is None or local_sess.websocket is None:
                await db.system_execute(
                    "UPDATE agent_relay_requests SET status = 'error', error = %s WHERE id = %s",
                    ("Agent đã ngắt kết nối", request_id),
                )
                await db.system_execute("SELECT pg_notify('agent_responses', %s)", (request_id,))
                return

            self._forwarded_requests[request_id] = local_sess.id
            try:
                await local_sess.websocket.send_json(
                    {"id": request_id, "type": row["kind"], **row["payload"]}
                )
            except Exception as exc:
                self._forwarded_requests.pop(request_id, None)
                await db.system_execute(
                    "UPDATE agent_relay_requests SET status = 'error', error = %s WHERE id = %s",
                    (f"Lỗi gửi tới agent: {exc}", request_id),
                )
                await db.system_execute("SELECT pg_notify('agent_responses', %s)", (request_id,))

        elif channel == "agent_responses":
            request_id = payload
            fut = self._pending_responses.get(request_id)
            if fut and not fut.done():
                row = await db.system_fetchone(
                    "SELECT status, response, error FROM agent_relay_requests WHERE id = %s",
                    (request_id,),
                )
                if row:
                    if row["status"] == "completed":
                        fut.set_result(row["response"] or {})
                    elif row["status"] == "error":
                        fut.set_exception(AgentError(row["error"] or "Agent báo lỗi không rõ"))

        elif channel == "agent_control":
            session_id = payload
            local_sess = self._local_sessions.get(session_id)
            if local_sess:
                self._drop(local_sess)


hub = AgentHub()
