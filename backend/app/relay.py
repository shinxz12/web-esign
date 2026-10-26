"""Relay giữa browser và agent.

Agent **chủ động** mở WebSocket ra backend và giữ kết nối. Browser không bao
giờ gọi trực tiếp vào máy người dùng, nên không dính Local Network Access của
Chrome 142+ hay chặn mixed-content của Safari.

Ghép cặp bằng mã 6 số do agent sinh và in ra màn hình; người dùng gõ mã đó vào
web. Mã là bí mật chia sẻ duy nhất cho phiên làm việc.
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
        self._agents: dict[str, AgentSession] = {}

    def register(self, session: AgentSession) -> None:
        self._agents[session.code] = session

    def unregister(self, code: str) -> None:
        session = self._agents.pop(code, None)
        if session is None:
            return
        for future in session.pending.values():
            if not future.done():
                future.set_exception(AgentError("Agent đã ngắt kết nối"))

    def get(self, code: str) -> AgentSession:
        session = self._agents.get(code)
        if session is None:
            raise AgentUnavailable(
                "Không tìm thấy agent với mã này. Kiểm tra agent đã chạy chưa."
            )
        return session

    @property
    def online(self) -> int:
        return len(self._agents)


hub = AgentHub()
