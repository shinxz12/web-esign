"""Cấu hình đọc từ biến môi trường — gom một chỗ để không module nào tự đoán."""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import pathlib
import secrets

logger = logging.getLogger("websigner.config")

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA_DIR = pathlib.Path(os.environ.get("WEBSIGNER_DATA", REPO_ROOT / "data")).resolve()
DOCUMENTS_DIR = DATA_DIR / "documents"
CERTS_DIR = DATA_DIR / "certs"  # khoá/chứng thư test + CRL phục vụ qua HTTP

DATABASE_URL = os.environ.get(
    "WEBSIGNER_DATABASE_URL", "postgresql://127.0.0.1:5432/websigner"
)
DB_POOL_SIZE = int(os.environ.get("WEBSIGNER_DB_POOL_SIZE", "10"))

# Tự đăng ký tổ chức mới qua giao diện. Tắt khi chỉ cấp tài khoản bằng CLI.
ALLOW_SIGNUP = os.environ.get("WEBSIGNER_ALLOW_SIGNUP", "1").lower() not in ("0", "false", "no")

# smtp://host:25 · smtp+starttls://user:pass@host:587 · smtps://user:pass@host:465
SMTP_URL = os.environ.get("WEBSIGNER_SMTP_URL") or None
MAIL_FROM = os.environ.get("WEBSIGNER_MAIL_FROM", "Web Signer <no-reply@localhost>")

# Webhook chỉ được gọi tới địa chỉ công cộng qua HTTPS. Bật cờ này cho môi
# trường phát triển/test, nơi người nhận webhook chạy ở 127.0.0.1.
WEBHOOK_ALLOW_PRIVATE = os.environ.get("WEBSIGNER_WEBHOOK_ALLOW_PRIVATE", "").lower() in (
    "1",
    "true",
    "yes",
)

SESSION_TTL_DAYS = 14
MAX_UPLOAD_MB_HARD = 60  # trần tuyệt đối của mọi request, trước cả hạn mức gói


def public_url() -> str | None:
    value = os.environ.get("WEBSIGNER_PUBLIC_URL", "").rstrip("/")
    return value or None


@functools.cache
def secret_key() -> bytes:
    """Khoá gốc của server: sinh token liên kết ký và secret webhook.

    Đổi khoá này là mọi liên kết ký và secret webhook đã phát đều đổi theo —
    phải giữ ổn định. Ưu tiên biến môi trường; không có thì sinh một lần vào
    ``<data>/secret.key`` (quyền 600).
    """
    env = os.environ.get("WEBSIGNER_SECRET_KEY")
    if env:
        if len(env) < 32:
            raise RuntimeError("WEBSIGNER_SECRET_KEY phải dài ít nhất 32 ký tự")
        return hashlib.sha256(env.encode()).digest()

    path = DATA_DIR / "secret.key"
    if not path.is_file():
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(secrets.token_hex(32))
        logger.warning(
            "Chưa đặt WEBSIGNER_SECRET_KEY — đã sinh khoá vào %s. "
            "Sao lưu tệp này cùng cơ sở dữ liệu.",
            path,
        )
    return hashlib.sha256(path.read_text().strip().encode()).digest()
