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
import io
import logging
import os
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
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import devices, signing, store, trust, verify
from .relay import AgentError, AgentSession, AgentUnavailable, hub

# uvicorn chỉ cấu hình logger của nó; root logger không có handler nên log của
# ứng dụng sẽ rơi vào hư vô nếu không tự gắn.
logging.basicConfig(
    level=os.environ.get("WEBSIGNER_LOG_LEVEL", "INFO").upper(),
    format="%(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("websigner")

WEB_DIR = pathlib.Path(__file__).resolve().parents[2] / "web"
OWNER_COOKIE = "ws_owner"
DEVICE_COOKIE = "ws_device"
DOC_ID = Path(pattern="^[0-9a-f]{16}$")

app = FastAPI(title="Web Signer", version="0.2.0")


@app.on_event("startup")
def _startup() -> None:
    store.init()
    trust.seed_trust_store()
    material = trust.load_trust_material()
    logger.info(
        "Trust store %s: %d root, %d CA trung gian",
        trust.TRUST_DIR,
        len(material.roots),
        len(material.intermediates),
    )
    for root in material.roots:
        logger.info("  root: %s", root.subject.native.get("common_name"))
    logger.info("Font hình chữ ký: %s", signing.find_font() or "mặc định")
    logger.info("Hồ sơ chữ ký mặc định: %s", signing.default_profile().value)
    logger.info("TSA: %s", trust.tsa_url() or "không dùng")


@app.middleware("http")
async def attach_owner_token(request: Request, call_next):
    """Cấp cookie chủ sở hữu cho khách mới, giữ nguyên với khách cũ."""
    token = request.cookies.get(OWNER_COOKIE)
    fresh = not token
    request.state.owner_token = token or secrets.token_urlsafe(24)
    # Cookie thiết bị chỉ do /activate cấp, middleware không tự sinh.
    request.state.device_token = request.cookies.get(DEVICE_COOKIE)
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


def device_token(request: Request) -> str | None:
    return request.state.device_token


def current_device(request: Request) -> devices.Device | None:
    return devices.browser_device(request.state.device_token)


def owner_token(request: Request) -> str:
    return request.state.owner_token


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------


class SignRequest(BaseModel):
    # Bỏ trống khi trình duyệt đã kích hoạt cookie thiết bị: server tự tìm
    # agent của máy đó. Mã ghép cặp chỉ còn là đường dự phòng.
    agent_code: str | None = Field(default=None, min_length=4, max_length=16)
    cert_id: str
    page: int = Field(ge=0)
    box: tuple[float, float, float, float]
    check_mark: bool = True
    color: str = signing.DEFAULT_STAMP_COLOR
    show_border: bool = False
    use_logo: bool = True


class SignerInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    tax_code: str | None = Field(default=None, max_length=20)


class DeviceRegistration(BaseModel):
    """Agent tự ghi danh máy khi khởi động."""

    token: str = Field(min_length=20, max_length=200)
    name: str = Field(default="agent", max_length=120)
    platform: str = Field(default="?", max_length=60)


class DeviceToken(BaseModel):
    token: str = Field(min_length=20, max_length=200)


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
    http: Request,
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
    session = _agent_session(http, request)
    return (
        await _perform_signing(
            meta, request, slot=None, logo_key=owner, session=session
        )
    ).to_dict(redact_invites=False)


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
async def api_invite_sign(
    http: Request, invite: str, request: SignRequest = Body(...)
) -> dict:
    meta, slot = _invited(invite)
    if slot.done:
        raise HTTPException(409, "Bạn đã ký tài liệu này rồi")
    nxt = meta.next_slot
    if nxt is None or nxt.order != slot.order:
        raise HTTPException(
            409, f"Chưa tới lượt bạn — đang chờ {nxt.name if nxt else '—'} ký"
        )
    session = _agent_session(http, request)
    return (
        await _perform_signing(
            meta, request, slot=slot, logo_key=invite, session=session
        )
    ).to_dict()


async def _store_logo(key: str, file: UploadFile) -> dict:
    """Logo/con dấu dùng cho mọi chữ ký của người này."""
    data = await file.read()
    if len(data) > 2 * 1024 * 1024:
        raise HTTPException(400, "Logo quá lớn, tối đa 2 MB")
    try:
        from PIL import Image

        image = Image.open(io.BytesIO(data))
        image.verify()  # chỉ nhận ảnh thật, không nhận tệp giả đuôi ảnh
    except Exception as exc:
        raise HTTPException(400, f"Không đọc được ảnh: {exc}") from exc
    store.save_logo(key, data)
    return {"ok": True, "size": len(data), "format": image.format}


@app.post("/api/logo")
async def api_upload_logo(
    file: UploadFile = File(...), owner: str = Depends(owner_token)
) -> dict:
    return await _store_logo(owner, file)


@app.delete("/api/logo", status_code=204)
def api_delete_logo(owner: str = Depends(owner_token)) -> Response:
    store.delete_logo(owner)
    return Response(status_code=204)


@app.get("/api/logo")
def api_has_logo(owner: str = Depends(owner_token)) -> dict:
    return {"has_logo": store.load_logo(owner) is not None}


def _logo_response(key: str) -> Response:
    """Ảnh thô cho phần xem trước hình chữ ký trên trình duyệt."""
    from PIL import Image

    data = store.load_logo(key)
    if data is None:
        raise HTTPException(404, "Chưa có logo")
    fmt = Image.open(io.BytesIO(data)).format
    return Response(
        data,
        media_type=Image.MIME.get(fmt, "application/octet-stream"),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/logo/image")
def api_logo_image(owner: str = Depends(owner_token)) -> Response:
    return _logo_response(owner)


@app.post("/api/sign/{invite}/logo")
async def api_upload_invite_logo(invite: str, file: UploadFile = File(...)) -> dict:
    _invited(invite)
    return await _store_logo(invite, file)


@app.get("/api/sign/{invite}/logo")
def api_has_invite_logo(invite: str) -> dict:
    _invited(invite)
    return {"has_logo": store.load_logo(invite) is not None}


@app.get("/api/sign/{invite}/logo/image")
def api_invite_logo_image(invite: str) -> Response:
    _invited(invite)
    return _logo_response(invite)


@app.delete("/api/sign/{invite}/logo", status_code=204)
def api_delete_invite_logo(invite: str) -> Response:
    _invited(invite)
    store.delete_logo(invite)
    return Response(status_code=204)


# --------------------------------------------------------------------------
# Lõi ký, dùng chung cho cả hai đường
# --------------------------------------------------------------------------


def _agent_session(http: Request, request: SignRequest) -> AgentSession:
    """Agent nào sẽ ký: ưu tiên mã người dùng gõ, sau đó tới cookie thiết bị."""
    try:
        if request.agent_code:
            return hub.get(request.agent_code)
        device = current_device(http)
        if device is None:
            raise AgentUnavailable(
                "Trình duyệt này chưa gắn với máy nào. Mở agent trên máy có "
                "token để kích hoạt, hoặc nhập mã ghép cặp."
            )
        return hub.for_device(device.id)
    except AgentUnavailable as exc:
        raise HTTPException(404, str(exc)) from exc


async def _perform_signing(
    meta: store.DocumentMeta,
    request: SignRequest,
    slot: store.SignerSlot | None,
    logo_key: str,
    session: AgentSession,
) -> store.DocumentMeta:
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
        check_mark=request.check_mark,
        logo=store.load_logo(logo_key) if request.use_logo else None,
        color=request.color,
        show_border=request.show_border,
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


@app.get("/api/agents/{code}/certificates")
async def api_certificates(code: str) -> dict:
    """Đường dự phòng: tìm agent bằng mã ghép cặp người dùng gõ tay."""
    try:
        session = hub.get(code)
        certificates = await _agent_certificates(session)
    except AgentUnavailable as exc:
        raise HTTPException(404, str(exc)) from exc
    except AgentError as exc:
        raise HTTPException(502, str(exc)) from exc

    return {
        "agent": session.name,
        "platform": session.platform,
        "certificates": certificates,
    }


# --------------------------------------------------------------------------
# Thiết bị: agent ghi danh máy, trình duyệt kích hoạt một lần bằng cookie
# --------------------------------------------------------------------------


def _activation_url(request: Request, device_id: str) -> str:
    """URL agent sẽ mở trong trình duyệt mặc định để cấp cookie thiết bị."""
    base = os.environ.get("WEBSIGNER_PUBLIC_URL", "").rstrip("/") or str(
        request.base_url
    ).rstrip("/")
    return f"{base}/activate?t={devices.issue_ticket(device_id)}"


@app.post("/api/devices", status_code=201)
def api_register_device(
    http: Request, registration: DeviceRegistration = Body(...)
) -> dict:
    device = devices.register(
        registration.token, registration.name, registration.platform
    )
    return {
        "device": device.to_dict(),
        "activate_url": _activation_url(http, device.id),
    }


@app.post("/api/devices/activation")
def api_new_activation(http: Request, body: DeviceToken = Body(...)) -> dict:
    """Agent xin vé mới để kích hoạt thêm một trình duyệt."""
    try:
        device = devices.by_token(body.token)
    except devices.DeviceError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {
        "device": device.to_dict(),
        "activate_url": _activation_url(http, device.id),
    }


@app.get("/activate")
def api_activate(http: Request, t: str = "") -> Response:
    """Đổi vé một lần lấy cookie thiết bị rồi trả người dùng về trang ký."""
    try:
        device_id = devices.claim_ticket(t)
    except devices.DeviceError as exc:
        raise HTTPException(400, str(exc)) from exc

    browser = http.state.device_token or secrets.token_urlsafe(24)
    devices.bind_browser(browser, device_id)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        DEVICE_COOKIE,
        browser,
        httponly=True,
        samesite="lax",
        secure=http.url.scheme == "https",
        max_age=365 * 24 * 3600,
        path="/",
    )
    logger.info("Trình duyệt mới kích hoạt cho thiết bị %s", device_id)
    return response


@app.get("/api/agents")
async def api_device_agent(http: Request) -> dict:
    """Agent của máy mà trình duyệt này đã kích hoạt — không cần gõ mã."""
    device = current_device(http)
    if device is None:
        return {"device": None, "online": False, "certificates": []}
    try:
        session = hub.for_device(device.id)
        certificates = await _agent_certificates(session)
    except AgentUnavailable:
        return {"device": device.to_dict(), "online": False, "certificates": []}
    except AgentError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {
        "device": device.to_dict(),
        "online": True,
        "agent": session.name,
        "platform": session.platform,
        "certificates": certificates,
    }


@app.delete("/api/devices/browser", status_code=204)
def api_forget_browser(http: Request) -> Response:
    """Quên liên kết với máy này trên đúng trình duyệt đang dùng."""
    devices.unbind_browser(http.state.device_token)
    response = Response(status_code=204)
    response.delete_cookie(DEVICE_COOKIE, path="/")
    return response


@app.websocket("/ws/agent")
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
                device_id = devices.by_token(str(hello["device_token"])).id
                devices.touch(device_id)
            except devices.DeviceError as exc:
                await websocket.close(code=4401, reason=str(exc))
                return

        session = AgentSession(
            code=str(hello["code"]),
            name=str(hello.get("name") or "agent"),
            platform=str(hello.get("platform") or "?"),
            websocket=websocket,
            device_id=device_id,
        )
        hub.register(session)
        logger.info(
            "Agent %s (mã %s, thiết bị %s) đã kết nối",
            session.name,
            session.code,
            device_id or "—",
        )
        await websocket.send_json({"type": "ready"})

        while True:
            session.resolve(await websocket.receive_json())
    except WebSocketDisconnect:
        pass
    finally:
        if session is not None:
            hub.unregister(session)
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
