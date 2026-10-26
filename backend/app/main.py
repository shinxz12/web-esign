"""Web Signer — ký số PDF bằng USB token qua trình duyệt.

Tài liệu không bao giờ rời server: browser chỉ gửi vị trí khung chữ ký, agent
chỉ nhận vài trăm byte signed attributes để đưa cho token ký.

Phân quyền không dùng bảng người dùng:
  * chủ tài liệu giữ cookie `ws_owner`;
  * mỗi người ký nhận một liên kết mời `/s/<invite_token>`;
  * danh tính người ký là chứng thư số của họ, đối chiếu theo MST.
"""

from __future__ import annotations

import base64
import logging
import pathlib
import secrets
from datetime import datetime, timezone

from fastapi import (
    Body,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Path,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import signing, store, trust, verify
from .relay import AgentError, AgentSession, AgentUnavailable, hub

logger = logging.getLogger("websigner")

WEB_DIR = pathlib.Path(__file__).resolve().parents[2] / "web"
OWNER_COOKIE = "ws_owner"
DOC_ID = Path(pattern="^[0-9a-f]{16}$")

app = FastAPI(title="Web Signer", version="0.2.0")


@app.on_event("startup")
def _startup() -> None:
    store.init()
    logger.info("Font hình chữ ký: %s", signing.find_font() or "mặc định")
    logger.info("Hồ sơ chữ ký mặc định: %s", signing.default_profile().value)
    logger.info("TSA: %s", trust.tsa_url() or "không dùng")


@app.middleware("http")
async def attach_owner_token(request: Request, call_next):
    """Cấp cookie chủ sở hữu cho khách mới, giữ nguyên với khách cũ."""
    token = request.cookies.get(OWNER_COOKIE)
    fresh = not token
    request.state.owner_token = token or secrets.token_urlsafe(24)
    response = await call_next(request)
    if fresh:
        response.set_cookie(
            OWNER_COOKIE,
            request.state.owner_token,
            httponly=True,
            samesite="lax",
            max_age=365 * 24 * 3600,
            path="/",
        )
    return response


def owner_token(request: Request) -> str:
    return request.state.owner_token


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------


class SignRequest(BaseModel):
    agent_code: str = Field(min_length=4, max_length=16)
    cert_id: str
    page: int = Field(ge=0)
    box: tuple[float, float, float, float]
    reason: str | None = None
    location: str | None = None


class SignerInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    tax_code: str | None = Field(default=None, max_length=20)


# --------------------------------------------------------------------------
# Tài liệu (chủ sở hữu)
# --------------------------------------------------------------------------


def _owned(doc_id: str, owner: str) -> store.DocumentMeta:
    """404 cả khi không tồn tại lẫn khi không phải chủ — không lộ sự tồn tại."""
    try:
        meta = store.load_meta(doc_id)
    except (store.DocumentNotFound, FileNotFoundError):
        raise HTTPException(404, "Không tìm thấy tài liệu") from None
    if not secrets.compare_digest(meta.owner_token, owner):
        raise HTTPException(404, "Không tìm thấy tài liệu")
    return meta


@app.get("/api/session")
def api_session(owner: str = Depends(owner_token)) -> dict:
    return {
        "profile": signing.default_profile().value,
        "timestamping": bool(trust.tsa_url()),
    }


@app.get("/api/documents")
def api_list_documents(owner: str = Depends(owner_token)) -> list[dict]:
    return [m.to_dict(redact_invites=False) for m in store.list_documents(owner)]


@app.post("/api/documents", status_code=201)
async def api_upload(
    file: UploadFile = File(...), owner: str = Depends(owner_token)
) -> dict:
    content = await file.read()
    if not content.startswith(b"%PDF-"):
        raise HTTPException(400, "Tệp tải lên không phải PDF")
    meta = store.create(file.filename or "tai-lieu.pdf", content, owner)
    return meta.to_dict(redact_invites=False)


@app.get("/api/documents/{doc_id}")
def api_document(doc_id: str = DOC_ID, owner: str = Depends(owner_token)) -> dict:
    return _owned(doc_id, owner).to_dict(redact_invites=False)


@app.put("/api/documents/{doc_id}/signers")
def api_set_signers(
    doc_id: str = DOC_ID,
    people: list[SignerInput] = Body(...),
    owner: str = Depends(owner_token),
) -> dict:
    _owned(doc_id, owner)
    try:
        meta = store.set_signers(doc_id, [p.model_dump() for p in people])
    except store.WorkflowError as exc:
        raise HTTPException(409, str(exc)) from exc
    return meta.to_dict(redact_invites=False)


@app.get("/api/documents/{doc_id}/file")
def api_document_file(doc_id: str = DOC_ID, owner: str = Depends(owner_token)):
    _owned(doc_id, owner)
    return _pdf_response(doc_id)


@app.get("/api/documents/{doc_id}/download")
def api_download(doc_id: str = DOC_ID, owner: str = Depends(owner_token)):
    meta = _owned(doc_id, owner)
    return _pdf_response(doc_id, download_name=meta.name)


@app.get("/api/documents/{doc_id}/verify")
async def api_verify(doc_id: str = DOC_ID, owner: str = Depends(owner_token)):
    _owned(doc_id, owner)
    return await _verify_report(doc_id)


@app.delete("/api/documents/{doc_id}", status_code=204)
def api_delete(doc_id: str = DOC_ID, owner: str = Depends(owner_token)) -> Response:
    _owned(doc_id, owner)
    store.delete(doc_id)
    return Response(status_code=204)


@app.post("/api/documents/{doc_id}/sign")
async def api_sign_as_owner(
    doc_id: str = DOC_ID,
    request: SignRequest = Body(...),
    owner: str = Depends(owner_token),
) -> dict:
    meta = _owned(doc_id, owner)
    if meta.ordered_workflow:
        raise HTTPException(
            409,
            "Tài liệu dùng luồng ký có thứ tự — hãy ký qua liên kết của người ký",
        )
    return (await _perform_signing(meta, request, slot=None)).to_dict(
        redact_invites=False
    )


# --------------------------------------------------------------------------
# Người ký (liên kết mời)
# --------------------------------------------------------------------------


def _invited(invite: str) -> tuple[store.DocumentMeta, store.SignerSlot]:
    try:
        return store.find_by_invite(invite)
    except store.WorkflowError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/sign/{invite}")
def api_invite(invite: str) -> dict:
    meta, slot = _invited(invite)
    nxt = meta.next_slot
    return {
        "document": meta.to_dict(),
        "slot": {"order": slot.order, "name": slot.name, "tax_code": slot.tax_code},
        "my_turn": nxt is not None and nxt.order == slot.order,
        "already_signed": slot.done,
        "waiting_for": nxt.name if nxt and nxt.order != slot.order else None,
    }


@app.get("/api/sign/{invite}/file")
def api_invite_file(invite: str):
    meta, _ = _invited(invite)
    return _pdf_response(meta.id)


@app.get("/api/sign/{invite}/verify")
async def api_invite_verify(invite: str):
    meta, _ = _invited(invite)
    return await _verify_report(meta.id)


@app.post("/api/sign/{invite}/sign")
async def api_invite_sign(invite: str, request: SignRequest = Body(...)) -> dict:
    meta, slot = _invited(invite)
    if slot.done:
        raise HTTPException(409, "Bạn đã ký tài liệu này rồi")
    nxt = meta.next_slot
    if nxt is None or nxt.order != slot.order:
        raise HTTPException(
            409, f"Chưa tới lượt bạn — đang chờ {nxt.name if nxt else '—'} ký"
        )
    return (await _perform_signing(meta, request, slot=slot)).to_dict()


# --------------------------------------------------------------------------
# Lõi ký, dùng chung cho cả hai đường
# --------------------------------------------------------------------------


async def _perform_signing(
    meta: store.DocumentMeta,
    request: SignRequest,
    slot: store.SignerSlot | None,
) -> store.DocumentMeta:
    try:
        session = hub.get(request.agent_code)
    except AgentUnavailable as exc:
        raise HTTPException(404, str(exc)) from exc

    cert_entry = session.certificates.get(request.cert_id)
    if cert_entry is None:
        raise HTTPException(
            409, "Chưa nạp danh sách chứng thư của agent, hãy kết nối lại"
        )

    cert_der = base64.b64decode(cert_entry["cert_b64"])
    chain_der = [base64.b64decode(c) for c in cert_entry.get("chain_b64", [])]
    cert = signing.load_cert_chain(cert_der, chain_der)[0]
    cert_cn = signing.subject_cn(cert)
    cert_mst = signing.subject_tax_code(cert)

    # Đúng lượt chưa đủ: chứng thư phải đúng người được mời.
    if slot is not None and not slot.accepts(cert_cn, cert_mst):
        expected = f"MST {slot.tax_code}" if slot.tax_code else slot.name
        raise HTTPException(
            403,
            f"Chứng thư của «{cert_cn}» không khớp người được mời ký ({expected})",
        )

    profile = signing.default_profile()
    appearance = signing.SignatureAppearance(
        page=request.page,
        box=request.box,
        reason=request.reason or None,
        location=request.location or None,
    )
    field_name = f"Sig{len(meta.signatures) + 1}"

    # Pha 1 — tài liệu ở lại server.
    try:
        prepared = await signing.prepare(
            store.current_pdf(meta.id),
            cert_der,
            chain_der,
            appearance,
            field_name,
            profile,
        )
    except signing.SigningError as exc:
        raise HTTPException(400, f"Không chuẩn bị được chữ ký: {exc}") from exc

    # Chỉ signed attributes đi ra ngoài.
    try:
        result = await session.call(
            "sign",
            {
                "cert_id": request.cert_id,
                "algo": prepared.algo.value,
                "algo_params": prepared.algo_params,
                "document_name": meta.name,
                "document_digest": prepared.document_digest.hex(),
                "tbs_digest": prepared.tbs_digest.hex(),
                "tbs_b64": base64.b64encode(prepared.signed_attrs_der).decode(),
            },
        )
    except AgentError as exc:
        raise HTTPException(502, str(exc)) from exc

    # Pha 2 — nhúng CMS, dấu thời gian và DSS vào chỗ đã chừa.
    try:
        signed_pdf = await signing.finalize(
            prepared, cert_der, chain_der, base64.b64decode(result["signature_b64"])
        )
    except signing.SigningError as exc:
        raise HTTPException(400, f"Không hoàn tất được chữ ký: {exc}") from exc

    record = store.SignatureRecord(
        field_name=field_name,
        signer=cert_cn,
        tax_code=cert_mst,
        signed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        page=request.page,
        reason=request.reason,
        location=request.location,
        profile=profile.value,
    )
    return store.commit_signature(meta.id, signed_pdf, record, slot)


def _pdf_response(doc_id: str, download_name: str | None = None) -> Response:
    headers = {"Cache-Control": "no-store"}
    if download_name:
        stem = download_name.removesuffix(".pdf")
        headers["Content-Disposition"] = f'attachment; filename="{stem}-da-ky.pdf"'
    return Response(store.current_pdf(doc_id), media_type="application/pdf", headers=headers)


async def _verify_report(doc_id: str) -> list[dict]:
    reports = await verify.verify(store.current_pdf(doc_id))
    return [r.to_dict() for r in reports]


# --------------------------------------------------------------------------
# Agent
# --------------------------------------------------------------------------


@app.get("/api/agents/{code}/certificates")
async def api_certificates(code: str) -> dict:
    """Hỏi agent xem token đang cắm có những chứng thư nào."""
    try:
        session = hub.get(code)
        data = await session.call("list_certificates", {})
    except AgentUnavailable as exc:
        raise HTTPException(404, str(exc)) from exc
    except AgentError as exc:
        raise HTTPException(502, str(exc)) from exc

    session.certificates = {c["id"]: c for c in data.get("certificates", [])}
    return {
        "agent": session.name,
        "platform": session.platform,
        "certificates": [
            {k: v for k, v in c.items() if k not in ("cert_b64", "chain_b64")}
            for c in session.certificates.values()
        ],
    }


@app.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket) -> None:
    await websocket.accept()
    session: AgentSession | None = None
    try:
        hello = await websocket.receive_json()
        if hello.get("type") != "hello" or not hello.get("code"):
            await websocket.close(code=4400, reason="Thiếu gói hello")
            return
        session = AgentSession(
            code=str(hello["code"]),
            name=str(hello.get("name") or "agent"),
            platform=str(hello.get("platform") or "?"),
            websocket=websocket,
        )
        hub.register(session)
        logger.info("Agent %s (%s) đã kết nối", session.name, session.code)
        await websocket.send_json({"type": "ready"})

        while True:
            session.resolve(await websocket.receive_json())
    except WebSocketDisconnect:
        pass
    finally:
        if session is not None:
            hub.unregister(session.code)
            logger.info("Agent %s đã ngắt", session.code)


# --------------------------------------------------------------------------
# CRL và giao diện
# --------------------------------------------------------------------------


@app.get("/crl/{filename}")
def api_crl(filename: str = Path(pattern=r"^[A-Za-z0-9._-]+\.crl$")) -> FileResponse:
    """Phục vụ CRL của CA test để kiểm tra thu hồi chạy thật qua HTTP."""
    path = store.CERTS_DIR / filename
    if not path.is_file():
        raise HTTPException(404, "Không có CRL này")
    return FileResponse(path, media_type="application/pkix-crl")


@app.get("/s/{invite}")
def signer_page(invite: str) -> FileResponse:
    """Trang ký dành cho người được mời — cùng giao diện, khác chế độ."""
    return FileResponse(WEB_DIR / "index.html")


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
