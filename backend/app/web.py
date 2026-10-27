"""Phần HTTP dùng chung: URL gốc, đọc tệp tải lên có trần, header bảo mật,
giới hạn kích thước request, và che token trong access log."""

from __future__ import annotations

import logging
import re
from urllib.parse import quote

from fastapi import Request, Response, UploadFile

from . import config
from .errors import ApiError

# pdf.js chạy từ /vendor (không CDN): trang ký không nạp script của bên thứ ba.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "worker-src 'self' blob:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)
# Swagger/ReDoc của FastAPI nạp từ CDN; không áp CSP chặt cho hai trang này.
_CSP_EXEMPT = ("/docs", "/redoc")


def base_url(request: Request) -> str:
    return config.public_url() or str(request.base_url).rstrip("/")


def is_https(request: Request) -> bool:
    url = config.public_url()
    return request.url.scheme == "https" or bool(url and url.startswith("https://"))


def pdf_response(doc: dict, data: bytes, revision: int, *, download: bool) -> Response:
    """PDF tải về/hiển thị; bản đã ký mang hậu tố ``-da-ky``. Tên tệp tiếng Việt theo RFC 5987."""
    stem = doc["filename"].removesuffix(".pdf")
    name = f"{stem}-da-ky.pdf" if revision else doc["filename"]
    fallback = name.encode("ascii", "ignore").decode().replace('"', "") or "tai-lieu.pdf"
    disposition = "attachment" if download else "inline"
    return Response(
        data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"{disposition}; filename=\"{fallback}\"; filename*=utf-8''{quote(name)}",
            "Cache-Control": "no-store",
        },
    )


async def read_upload(file: UploadFile, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while chunk := await file.read(1 << 20):
        size += len(chunk)
        if size > max_bytes:
            raise ApiError(
                413, "file_too_large", f"Tệp vượt quá {max_bytes // (1024 * 1024)} MB của gói dịch vụ"
            )
        chunks.append(chunk)
    return b"".join(chunks)


class SecurityHeaders:
    """ASGI thuần: thêm header vào mọi phản hồi HTTP mà không bọc lại body."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path: str = scope["path"]

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"cross-origin-opener-policy": b"same-origin",
                }
                embeddable = path.startswith("/s/") and config.FRAME_ANCESTORS
                if not path.startswith(_CSP_EXEMPT):
                    ancestors = config.FRAME_ANCESTORS if embeddable else "'none'"
                    extra[b"content-security-policy"] = (
                        f"{CONTENT_SECURITY_POLICY}; frame-ancestors {ancestors}".encode()
                    )
                if not embeddable:
                    extra[b"x-frame-options"] = b"DENY"
                if path.startswith(("/api/", "/v1/")):
                    extra[b"cache-control"] = b"no-store"
                if scope.get("scheme") == "https":
                    extra[b"strict-transport-security"] = b"max-age=31536000"
                present = {name.lower() for name, _ in headers}
                headers += [(k, v) for k, v in extra.items() if k not in present]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodyLimit:
    """Chặn request quá lớn trước khi multipart kịp ghi nó ra đĩa."""

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for name, value in scope.get("headers", []):
            if name == b"content-length" and value.isdigit() and int(value) > self.max_bytes:
                body = b'{"detail":"Request qu\xc3\xa1 l\xe1\xbb\x9bn","code":"request_too_large"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise ApiError(413, "request_too_large", "Request quá lớn")
            return message

        await self.app(scope, limited_receive, send)


_SECRET_PATHS = re.compile(r"(/s/|/api/sign/|[?&]t=)[A-Za-z0-9_\-]{12,}")


class RedactSecrets(logging.Filter):
    """Liên kết ký và vé kích hoạt là bí mật nằm trong URL — không để lọt vào log."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) >= 3:
            args = list(record.args)
            if isinstance(args[2], str):
                args[2] = _SECRET_PATHS.sub(r"\1***", args[2])
                record.args = tuple(args)
        return True
