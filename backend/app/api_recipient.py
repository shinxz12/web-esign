"""Phía người nhận: mọi thứ đi qua liên kết ``/s/<token>``.

Token là quyền truy cập (capability): ai có liên kết thì xem được tài liệu.
Ký thì còn cần chứng thư số đúng người (MST/tên) trên USB token của họ.
"""

from __future__ import annotations

import io

from fastapi import APIRouter, Body, Depends, File, Request, Response, UploadFile
from pydantic import BaseModel, Field

from . import devices, documents, signflow, signing
from .auth import client_ip, user_agent
from .errors import ApiError
from .relay import AgentUnavailable, hub
from .web import base_url, check_same_origin, pdf_response


def _same_origin_for_writes(request: Request) -> None:
    # Trang ký có thể nằm trong iframe của đối tác, nhưng mọi thao tác ghi vẫn
    # phải do chính trang ký gửi lên (Origin = Web Signer), không phải trang khác.
    if request.method not in ("GET", "HEAD"):
        check_same_origin(request)


router = APIRouter(
    prefix="/api/sign",
    tags=["Người nhận (liên kết ký)"],
    dependencies=[Depends(_same_origin_for_writes)],
)

DEVICE_COOKIE = "ws_device"
MAX_LOGO_BYTES = 2 * 1024 * 1024


class DeclineRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


def _payload(doc: dict, recipient: dict, recipients: list[dict]) -> dict:
    return {
        "document": documents.document_view(doc, recipients, org_view=False),
        "recipient": documents.recipient_view(recipient, doc, org_view=False, base_url=None),
        "turn": documents.turn(doc, recipient, recipients),
        "profile": signing.default_profile().value,
        # Trang ký báo kết quả (postMessage) cho đúng các origin này khi bị nhúng.
        "embed_origins": list(doc["org_embed_origins"] or []),
    }


@router.get("/{token}", summary="Tài liệu, vai trò và lượt của người nhận")
async def recipient_info(request: Request, token: str) -> dict:
    doc, recipient, recipients = await documents.by_token(token)
    await documents.record_view(doc, recipient, ip=client_ip(request), user_agent=user_agent(request))
    return _payload(doc, recipient, recipients)


@router.get("/{token}/file", summary="PDF bản mới nhất")
async def recipient_file(token: str, download: bool = False) -> Response:
    doc, _, _ = await documents.by_token(token)
    data, served = await documents.revision_file(doc, None)
    return pdf_response(doc, data, served, download=download)


@router.get("/{token}/verify", summary="Xác thực chữ ký trong bản mới nhất")
async def recipient_verify(token: str) -> list[dict]:
    doc, _, _ = await documents.by_token(token)
    return await documents.verify_report(doc)


async def _agent_session(request: Request, body: signflow.SignRequest):
    """Agent nào sẽ ký: ưu tiên mã người dùng gõ, sau đó tới cookie thiết bị."""
    try:
        if body.agent_code:
            return hub.get(body.agent_code)
        device = await devices.browser_device(request.cookies.get(DEVICE_COOKIE))
        if device is None:
            raise AgentUnavailable(
                "Trình duyệt này chưa gắn với máy nào. Mở agent trên máy có "
                "token để kích hoạt, hoặc nhập mã ghép cặp."
            )
        return hub.for_device(device.id)
    except AgentUnavailable as exc:
        raise ApiError(404, "agent_unavailable", str(exc)) from exc


@router.post("/{token}/sign", summary="Ký số bằng chứng thư trên agent")
async def recipient_sign(request: Request, token: str, body: signflow.SignRequest = Body(...)) -> dict:
    session = await _agent_session(request, body)
    await signflow.sign(
        token,
        body,
        session,
        base_url=base_url(request),
        ip=client_ip(request),
        user_agent=user_agent(request),
    )
    return _payload(*await documents.by_token(token))


@router.post("/{token}/handwrite", summary="Ký tay: đóng ảnh chữ ký vào tài liệu (không cần token)")
async def recipient_handwrite(
    request: Request, token: str, body: signflow.HandwriteRequest = Body(...)
) -> dict:
    await signflow.handwrite(
        token, body, base_url=base_url(request), ip=client_ip(request), user_agent=user_agent(request)
    )
    return _payload(*await documents.by_token(token))


@router.post("/{token}/approve", summary="Duyệt (vai trò người duyệt)")
async def recipient_approve(request: Request, token: str) -> dict:
    _, recipient, _ = await documents.by_token(token)
    await documents.approve(
        recipient, base_url=base_url(request), ip=client_ip(request), user_agent=user_agent(request)
    )
    return _payload(*await documents.by_token(token))


@router.post("/{token}/decline", summary="Từ chối — cả tài liệu dừng lại")
async def recipient_decline(request: Request, token: str, body: DeclineRequest) -> dict:
    _, recipient, _ = await documents.by_token(token)
    await documents.decline(
        recipient, body.reason.strip(), ip=client_ip(request), user_agent=user_agent(request)
    )
    return _payload(*await documents.by_token(token))


# --------------------------------------------------------------------------
# Logo / con dấu của người nhận
# --------------------------------------------------------------------------


@router.post("/{token}/logo", summary="Tải logo/con dấu vẽ vào hình chữ ký")
async def upload_logo(token: str, file: UploadFile = File(...)) -> dict:
    _, recipient, _ = await documents.by_token(token)
    data = await file.read(MAX_LOGO_BYTES + 1)
    if len(data) > MAX_LOGO_BYTES:
        raise ApiError(400, "logo_too_large", "Logo quá lớn, tối đa 2 MB")
    try:
        from PIL import Image

        image = Image.open(io.BytesIO(data))
        image.verify()  # chỉ nhận ảnh thật, không nhận tệp giả đuôi ảnh
    except Exception as exc:
        raise ApiError(400, "invalid_image", f"Không đọc được ảnh: {exc}") from exc
    if image.format not in ("PNG", "JPEG", "GIF", "WEBP"):
        raise ApiError(400, "invalid_image", "Logo phải là PNG, JPEG, GIF hoặc WEBP")
    await documents.save_logo(recipient["id"], data, image.format)
    return {"ok": True, "size": len(data), "format": image.format}


@router.get("/{token}/logo", summary="Đã có logo chưa")
async def has_logo(token: str) -> dict:
    _, recipient, _ = await documents.by_token(token)
    return {"has_logo": await documents.load_logo(recipient["id"]) is not None}


@router.get("/{token}/logo/image", summary="Ảnh logo để xem trước")
async def logo_image(token: str) -> Response:
    _, recipient, _ = await documents.by_token(token)
    logo = await documents.load_logo(recipient["id"])
    if logo is None:
        raise ApiError(404, "not_found", "Chưa có logo")
    data, fmt = logo
    return Response(data, media_type=f"image/{fmt.lower()}", headers={"Cache-Control": "no-store"})


@router.delete("/{token}/logo", status_code=204, summary="Bỏ logo")
async def delete_logo(token: str) -> Response:
    _, recipient, _ = await documents.by_token(token)
    await documents.delete_logo(recipient["id"])
    return Response(status_code=204)
