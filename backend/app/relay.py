"""Relay giữa browser và agent.

Agent **chủ động** mở WebSocket ra backend và giữ kết nối. Browser không bao
giờ gọi trực tiếp vào máy người dùng, nên không dính Local Network Access của
Chrome 142+ hay chặn mixed-content của Safari.

Hai cách tìm ra agent:

* theo ``device_id`` — trình duyệt đã kích hoạt cookie thiết bị, không gõ gì;
* theo mã ghép cặp 6 số — đường dự phòng khi chưa kích hoạt được.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket

REQUEST_TIMEOUT = 180.0  # người dùng còn phải nhập PIN của token


class AgentUnavailable(RuntimeError):
    pass


class AgentError(RuntimeError):
    pass


@dataclass
class AgentSession:
    code: str
    name: str
    platform: str
    websocket: WebSocket
    # Máy đã ghi danh. None khi agent cũ chỉ biết mã ghép cặp.
    device_id: str | None = None
    pending: dict[str, asyncio.Future] = field(default_factory=dict)
    # Chứng thư agent đã khai báo, khoá theo cert_id. Server giữ bản DER để
    # browser không bao giờ phải gửi chứng thư lên — tránh bị tráo.
    certificates: dict[str, dict[str, Any]] = field(default_factory=dict)

    async def call(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
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


class AgentHub:
    def __init__(self) -> None:
        self._by_code: dict[str, AgentSession] = {}
        self._by_device: dict[str, AgentSession] = {}

    def register(self, session: AgentSession) -> None:
        self._by_code[session.code] = session
        if session.device_id:
            previous = self._by_device.get(session.device_id)
            # Cài lại agent / nối lại sau khi rớt: bản cũ phải nhường chỗ, nếu
            # không browser vẫn hỏi cái websocket đã chết.
            if previous is not None and previous is not session:
                self._drop(previous)
            self._by_device[session.device_id] = session

    def unregister(self, session: AgentSession) -> None:
        if self._by_code.get(session.code) is session:
            self._by_code.pop(session.code, None)
        if session.device_id and self._by_device.get(session.device_id) is session:
            self._by_device.pop(session.device_id, None)
        self._drop(session)

    def _drop(self, session: AgentSession) -> None:
        for future in session.pending.values():
            if not future.done():
                future.set_exception(AgentError("Agent đã ngắt kết nối"))
        if session.websocket is not None:
            try:
                asyncio.create_task(
                    session.websocket.close(code=4409, reason="Phiên mới thay thế")
                )
            except Exception:
                pass
    def get(self, code: str) -> AgentSession:
        session = self._by_code.get(code)
        if session is None:
            raise AgentUnavailable(
                "Không tìm thấy agent với mã này. Kiểm tra agent đã chạy chưa."
            )
        return session

    def for_device(self, device_id: str) -> AgentSession:
        session = self._by_device.get(device_id)
        if session is None:
            raise AgentUnavailable("Agent trên máy này chưa chạy")
        return session

    def device_online(self, device_id: str) -> bool:
        return device_id in self._by_device

    @property
    def online(self) -> int:
        return len(self._by_code)


hub = AgentHub()
