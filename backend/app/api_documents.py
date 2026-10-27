"""API tài liệu ``/v1`` — cho hệ thống tích hợp (khoá API) và giao diện (phiên).

Xác thực: ``Authorization: Bearer wsk_live_…`` hoặc cookie phiên + ``X-CSRF-Token``.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Body, Depends, File, Form, Query, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, ValidationError

from . import audit, db, documents, plans
from .auth import Principal, client_ip, principal, user_agent
from .documents import DocumentPatch, DocumentSpec, RecipientSpec
from .errors import ApiError
from .web import base_url, pdf_response, read_upload

router = APIRouter(prefix="/v1", tags=["Tài liệu (API tích hợp)"])


class VoidRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


async def _idempotent_replay(who: Principal, key: str, fingerprint: bytes) -> str | None:
    """-> doc_id của lần gọi trước với cùng khoá, None nếu đây là lần đầu."""
    if not 1 <= len(key) <= 200:
        raise ApiError(400, "invalid_idempotency_key", "Idempotency-Key dài 1–200 ký tự")
    inserted = await db.fetchone(
        "INSERT INTO idempotency_keys (org_id, key, fingerprint) VALUES (%s, %s, %s) "
        "ON CONFLICT DO NOTHING RETURNING key",
        (who.org_id, key, fingerprint),
    )
    if inserted is not None:
        return None
    row = await db.fetchone(
        "SELECT fingerprint, response_body FROM idempotency_keys WHERE org_id = %s AND key = %s",
        (who.org_id, key),
    )
    if row is None:  # vừa bị dọn — coi như lần đầu
        return await _idempotent_replay(who, key, fingerprint)
    if bytes(row["fingerprint"]) != fingerprint:
        raise ApiError(422, "idempotency_mismatch", "Idempotency-Key đã dùng cho một request khác")
    if row["response_body"] is None:
        raise ApiError(409, "idempotency_in_progress", "Request với Idempotency-Key này đang được xử lý")
    return row["response_body"]["document_id"]


@router.post("/documents", status_code=201, summary="Tải PDF lên và tạo tài liệu ký")
async def create_document(
    request: Request,
    file: UploadFile = File(..., description="Tệp PDF"),
    data: str = Form(
        "{}",
        description="JSON: title, message, external_ref, metadata, expires_at | expires_in_days, "
        "recipients[{name, email, tax_code, role, order, field{page, box}}], send",
    ),
    who: Principal = Depends(principal),
):
    try:
        spec = DocumentSpec.model_validate_json(data)
    except ValidationError as exc:
        raise ApiError(422, "validation_error", f"Trường data không hợp lệ: {exc.errors(include_url=False)}") from None
    content = await read_upload(file, who.plan.max_file_mb * 1024 * 1024)

    key = request.headers.get("idempotency-key")
    if key:
        fingerprint = hashlib.sha256(data.encode() + b"\0" + hashlib.sha256(content).digest()).digest()
        replay = await _idempotent_replay(who, key, fingerprint)
        if replay is not None:
            view = await documents.get_view(who, replay, base_url(request))
            return JSONResponse(view, status_code=201, headers={"Idempotent-Replayed": "true"})
    try:
        view = await documents.create(
            who,
            file.filename or "tai-lieu.pdf",
            content,
            spec,
            base_url=base_url(request),
            ip=client_ip(request),
            user_agent=user_agent(request),
        )
    except BaseException:
        if key:
            await db.execute(
                "DELETE FROM idempotency_keys WHERE org_id = %s AND key = %s", (who.org_id, key)
            )
        raise
    if key:
        await db.execute(
            "UPDATE idempotency_keys SET response_status = 201, response_body = %s "
            "WHERE org_id = %s AND key = %s",
            (Jsonb({"document_id": view["id"]}), who.org_id, key),
        )
    return view


@router.get("/documents", summary="Danh sách tài liệu, mới nhất trước")
async def list_documents(
    status: str | None = Query(None, description="draft | in_progress | completed | declined | voided | expired"),
    q: str | None = Query(None, max_length=200, description="Tìm theo tiêu đề, tên tệp, external_ref"),
    external_ref: str | None = Query(None, max_length=200),
    limit: int = Query(20, ge=1, le=100),
    cursor: str | None = Query(None, max_length=200, description="next_cursor của trang trước"),
    who: Principal = Depends(principal),
):
    return await documents.list_documents(
        who.org_id, status=status, q=q, external_ref=external_ref, limit=limit, cursor=cursor
    )


@router.get("/documents/{doc_id}", summary="Chi tiết tài liệu, kèm signing_url của người nhận")
async def get_document(request: Request, doc_id: str, who: Principal = Depends(principal)):
    return await documents.get_view(who, doc_id, base_url(request))


@router.patch("/documents/{doc_id}", summary="Sửa bản nháp")
async def update_document(
    request: Request, doc_id: str, patch: DocumentPatch, who: Principal = Depends(principal)
):
    return await documents.update_draft(who, doc_id, patch, base_url=base_url(request))


@router.put("/documents/{doc_id}/recipients", summary="Thay toàn bộ người nhận của bản nháp")
async def set_recipients(
    request: Request,
    doc_id: str,
    recipients: list[RecipientSpec] = Body(...),
    who: Principal = Depends(principal),
):
    return await documents.replace_recipients(who, doc_id, recipients, base_url=base_url(request))


@router.post("/documents/{doc_id}/send", summary="Gửi tài liệu cho người nhận")
async def send_document(request: Request, doc_id: str, who: Principal = Depends(principal)):
    return await documents.send(
        who, doc_id, base_url=base_url(request), ip=client_ip(request), user_agent=user_agent(request)
    )


@router.post("/documents/{doc_id}/void", summary="Huỷ tài liệu đang ký hoặc bản nháp")
async def void_document(
    request: Request, doc_id: str, body: VoidRequest, who: Principal = Depends(principal)
):
    return await documents.void(
        who, doc_id, body.reason.strip(), ip=client_ip(request), user_agent=user_agent(request)
    )


@router.delete("/documents/{doc_id}", status_code=204, summary="Xoá tài liệu (không xoá được khi đang ký)")
async def delete_document(doc_id: str, who: Principal = Depends(principal)):
    await documents.delete(who, doc_id)
    return Response(status_code=204)


@router.get("/documents/{doc_id}/file", summary="Tải PDF (mặc định bản mới nhất)")
async def document_file(
    request: Request,
    doc_id: str,
    revision: int | None = Query(None, ge=0),
    download: bool = False,
    who: Principal = Depends(principal),
):
    doc = await documents.load(who.org_id, doc_id)
    data, served = await documents.revision_file(doc, revision)
    if download:
        async with db.transaction() as conn:
            await audit.append(
                conn,
                doc_id,
                "document.downloaded",
                who.actor,
                {"revision": served},
                ip=client_ip(request),
                user_agent=user_agent(request),
            )
    return pdf_response(doc, data, served, download=download)


@router.get("/documents/{doc_id}/audit", summary="Nhật ký kiểm toán dạng chuỗi băm")
async def document_audit(doc_id: str, who: Principal = Depends(principal)):
    return await documents.audit_trail(who, doc_id)


@router.get("/documents/{doc_id}/verify", summary="Xác thực các chữ ký số trong bản mới nhất")
async def verify_document(doc_id: str, who: Principal = Depends(principal)):
    return await documents.verify_report(await documents.load(who.org_id, doc_id))


@router.post("/documents/{doc_id}/recipients/{recipient_id}/remind", summary="Gửi lại email mời")
async def remind_recipient(
    request: Request, doc_id: str, recipient_id: str, who: Principal = Depends(principal)
):
    return await documents.remind(who, doc_id, recipient_id, base_url=base_url(request))


@router.post(
    "/documents/{doc_id}/recipients/{recipient_id}/rotate-link",
    summary="Thu hồi liên kết ký cũ và cấp liên kết mới",
)
async def rotate_recipient_link(
    request: Request, doc_id: str, recipient_id: str, who: Principal = Depends(principal)
):
    return await documents.rotate_link(who, doc_id, recipient_id, base_url=base_url(request))


@router.get("/usage", summary="Hạn mức gói và lượt dùng tháng này")
async def usage(who: Principal = Depends(principal)):
    return await plans.usage(who.org_id, who.plan)
