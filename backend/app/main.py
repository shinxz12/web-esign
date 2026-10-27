"""Web Signer — nền tảng ký số PDF bằng USB token qua trình duyệt.

Ba cửa vào, ba cách xác thực:

* ``/v1/…``        hệ thống tích hợp (``Authorization: Bearer wsk_live_…``) và
                   giao diện quản trị (cookie phiên + ``X-CSRF-Token``);
* ``/api/sign/…``  người nhận, qua liên kết ``/s/<token>`` riêng từng người;
* ``/ws/agent``    agent trên máy người ký, nối ra bằng WebSocket.

Tài liệu không bao giờ rời server: agent chỉ nhận vài trăm byte signed
attributes để đưa cho token ký.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import pathlib

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import (
    api_account,
    api_agents,
    api_documents,
    api_recipient,
    config,
    db,
    devices,
    documents,
    signing,
    storage,
    trust,
    worker,
)
from .errors import ApiError
from .web import BodyLimit, RedactSecrets, SecurityHeaders, csp

# uvicorn chỉ cấu hình logger của nó; root logger không có handler nên log của
# ứng dụng sẽ rơi vào hư vô nếu không tự gắn.
logging.basicConfig(
    level=os.environ.get("WEBSIGNER_LOG_LEVEL", "INFO").upper(),
    format="%(levelname)-8s %(name)s: %(message)s",
)
logging.getLogger("uvicorn.access").addFilter(RedactSecrets())
logger = logging.getLogger("websigner")

WEB_DIR = pathlib.Path(__file__).resolve().parents[2] / "web"


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    config.secret_key()  # thiếu/sai khoá thì chết ngay lúc khởi động, không phải lúc ký
    config.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    await db.open_pool()
    await devices.import_legacy_registry()

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
    logger.info("SMTP: %s", "bật" if config.SMTP_URL else "tắt (hệ thống tích hợp tự gửi signing_url)")
    logger.info("Lưu PDF: %s", storage.backend_name())

    background = asyncio.create_task(worker.run_forever(), name="websigner-worker")
    try:
        yield
    finally:
        background.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await background
        await db.close_pool()


app = FastAPI(
    title="Web Signer",
    version="1.0.0",
    summary="Nền tảng ký số PDF (PAdES) bằng USB token cho hệ thống tích hợp",
    lifespan=lifespan,
)
app.add_middleware(BodyLimit, max_bytes=config.MAX_UPLOAD_MB_HARD * 1024 * 1024)
app.add_middleware(SecurityHeaders)


@app.exception_handler(ApiError)
async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        {"detail": exc.message, "code": exc.code}, status_code=exc.status, headers=exc.headers
    )


@app.exception_handler(StarletteHTTPException)
async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(
        {"detail": exc.detail, "code": f"http_{exc.status_code}"},
        status_code=exc.status_code,
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        {"detail": jsonable_encoder(exc.errors()), "code": "validation_error"}, status_code=422
    )


app.include_router(api_documents.router)
app.include_router(api_account.router)
app.include_router(api_recipient.router)
app.include_router(api_agents.router)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    await db.fetchone("SELECT 1")
    return {"ok": True}


@app.get("/s/{token}", include_in_schema=False)
async def signer_page(token: str) -> FileResponse:
    """Trang ký dành cho người nhận — token đọc từ đường dẫn ở phía trình duyệt.

    Chỉ origin mà tổ chức gửi tài liệu đã khai mới nhúng được trang này vào
    iframe (CSP ``frame-ancestors``); còn lại bị chặn như mọi trang khác.
    """
    origins = await documents.embed_origins_for_token(token)
    headers = {"Cache-Control": "no-store", "Content-Security-Policy": csp(origins)}
    if not origins:
        headers["X-Frame-Options"] = "DENY"
    return FileResponse(WEB_DIR / "sign.html", headers=headers)


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
