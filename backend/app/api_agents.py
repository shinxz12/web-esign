"""Agent trên máy người ký: ghi danh thiết bị, kích hoạt trình duyệt, relay WebSocket.

Agent **chủ động** nối ra server; trình duyệt không bao giờ gọi vào máy người
dùng. Thiết bị thuộc về máy, không thuộc tổ chức nào: một người ký cầm token
ký được tài liệu của mọi tổ chức mời họ.
"""

from __future__ import annotations

import base64
import logging
import secrets

from fastapi import APIRouter, Body, Path, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import devices, security, signing
from .config import CERTS_DIR
from .errors import ApiError
from .relay import AgentError, AgentSession, AgentUnavailable, hub
from .web import base_url, is_https

logger = logging.getLogger("websigner")

router = APIRouter(tags=["Agent & thiết bị"])

DEVICE_COOKIE = "ws_device"


class DeviceRegistration(BaseModel):
    """Agent tự ghi danh máy khi khởi động."""

    token: str = Field(min_length=20, max_length=200)
    name: str = Field(default="agent", max_length=120)
    platform: str = Field(default="?", max_length=60)


class DeviceToken(BaseModel):
    token: str = Field(min_length=20, max_length=200)


async def _agent_certificates(session: AgentSession) -> list[dict]:
    """Hỏi agent danh sách chứng thư và nhớ bản DER để browser không gửi lên."""
    data = await session.call("list_certificates", {})
    session.certificates = {c["id"]: c for c in data.get("certificates", [])}

    def public(entry: dict) -> dict:
        """Bỏ phần nặng, thêm MST để trang web xem trước đúng hình sẽ ký."""
        cert = signing.load_cert_chain(base64.b64decode(entry["cert_b64"]), [])[0]
        return {
            **{k: v for k, v in entry.items() if k not in ("cert_b64", "chain_b64")},
            "tax_code": signing.subject_tax_code(cert),
        }

    return [public(c) for c in session.certificates.values()]


@router.get("/api/agents/{code}/certificates", summary="Đường dự phòng: tìm agent bằng mã ghép cặp")
async def agent_certificates(request: Request, code: str) -> dict:
    # Mã 6 số: chặn dò hàng loạt. Lớp chặn thật vẫn là hộp thoại xác nhận + PIN.
    security.enforce_rate(f"pair:{request.client.host if request.client else '-'}", 120)
    try:
        session = hub.get(code)
        certificates = await _agent_certificates(session)
    except AgentUnavailable as exc:
        raise ApiError(404, "agent_unavailable", str(exc)) from exc
    except AgentError as exc:
        raise ApiError(502, "agent_error", str(exc)) from exc
    return {"agent": session.name, "platform": session.platform, "certificates": certificates}


def _activation_url(request: Request, device_id: str) -> str:
    """URL agent sẽ mở trong trình duyệt mặc định để cấp cookie thiết bị."""
    return f"{base_url(request)}/activate?t={devices.issue_ticket(device_id)}"


@router.post("/api/devices", status_code=201, summary="Agent ghi danh máy")
async def register_device(request: Request, registration: DeviceRegistration = Body(...)) -> dict:
    security.enforce_rate(f"device:{request.client.host if request.client else '-'}", 30)
    device = await devices.register(registration.token, registration.name, registration.platform)
    return {"device": device.to_dict(), "activate_url": _activation_url(request, device.id)}


@router.post("/api/devices/activation", summary="Agent xin vé kích hoạt thêm một trình duyệt")
async def new_activation(request: Request, body: DeviceToken = Body(...)) -> dict:
    try:
        device = await devices.by_token(body.token)
    except devices.DeviceError as exc:
        raise ApiError(404, "unknown_device", str(exc)) from exc
    return {"device": device.to_dict(), "activate_url": _activation_url(request, device.id)}


@router.get("/activate", include_in_schema=False)
async def activate(request: Request, t: str = "") -> Response:
    """Đổi vé một lần lấy cookie thiết bị rồi báo đã kích hoạt."""
    try:
        device_id = await devices.claim_ticket(t)
    except devices.DeviceError as exc:
        raise ApiError(400, "invalid_ticket", str(exc)) from exc

    browser = request.cookies.get(DEVICE_COOKIE) or secrets.token_urlsafe(24)
    await devices.bind_browser(browser, device_id)
    response = RedirectResponse("/activated.html", status_code=303)
    response.set_cookie(
        DEVICE_COOKIE,
        browser,
        httponly=True,
        samesite="lax",
        secure=is_https(request),
        max_age=365 * 24 * 3600,
        path="/",
    )
    logger.info("Trình duyệt mới kích hoạt cho thiết bị %s", device_id)
    return response


@router.get("/api/agents", summary="Agent của máy mà trình duyệt này đã kích hoạt")
async def device_agent(request: Request) -> dict:
    device = await devices.browser_device(request.cookies.get(DEVICE_COOKIE))
    if device is None:
        return {"device": None, "online": False, "certificates": []}
    try:
        session = hub.for_device(device.id)
        certificates = await _agent_certificates(session)
    except AgentUnavailable:
        return {"device": device.to_dict(), "online": False, "certificates": []}
    except AgentError as exc:
        raise ApiError(502, "agent_error", str(exc)) from exc
    return {
        "device": device.to_dict(),
        "online": True,
        "agent": session.name,
        "platform": session.platform,
        "certificates": certificates,
    }


@router.delete("/api/devices/browser", status_code=204, summary="Quên máy này trên trình duyệt đang dùng")
async def forget_browser(request: Request) -> Response:
    await devices.unbind_browser(request.cookies.get(DEVICE_COOKIE))
    response = Response(status_code=204)
    response.delete_cookie(DEVICE_COOKIE, path="/")
    return response


@router.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket) -> None:
    await websocket.accept()
    session: AgentSession | None = None
    try:
        hello = await websocket.receive_json()
        if hello.get("type") != "hello" or not hello.get("code"):
            await websocket.close(code=4400, reason="Thiếu gói hello")
            return

        # Agent nào đã ghi danh máy thì kèm device_token; agent cũ thì không,
        # và vẫn dùng được qua mã ghép cặp.
        device_id: str | None = None
        if hello.get("device_token"):
            try:
                device_id = (await devices.by_token(str(hello["device_token"]))).id
                await devices.touch(device_id)
            except devices.DeviceError as exc:
                await websocket.close(code=4401, reason=str(exc))
                return

        session = AgentSession(
            code=str(hello["code"])[:16],
            name=str(hello.get("name") or "agent")[:120],
            platform=str(hello.get("platform") or "?")[:60],
            websocket=websocket,
            device_id=device_id,
        )
        hub.register(session)
        logger.info("Agent %s (thiết bị %s) đã kết nối", session.name, device_id or "—")
        await websocket.send_json({"type": "ready"})

        while True:
            session.resolve(await websocket.receive_json())
    except WebSocketDisconnect:
        pass
    finally:
        if session is not None:
            hub.unregister(session)
            logger.info("Agent %s đã ngắt", session.name)


@router.get("/crl/{filename}", include_in_schema=False)
def crl(filename: str = Path(pattern=r"^[A-Za-z0-9._-]+\.crl$")) -> FileResponse:
    """Phục vụ CRL của CA test để kiểm tra thu hồi chạy thật qua HTTP."""
    path = CERTS_DIR / filename
    if not path.is_file():
        raise ApiError(404, "not_found", "Không có CRL này")
    return FileResponse(path, media_type="application/pkix-crl")
