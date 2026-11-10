"""Quản lý bí mật và mã hoá theo SPEC §5 và §8:
- AES-256-GCM với Key Encryption Key (KEK) từ biến môi trường WEBSIGNER_KEK.
- Sinh secret webhook ngẫu nhiên (whsec_<base64>) cho từng endpoint.
- Sinh khoá liên kết ký riêng cho từng tổ chức (per-org signing-link key).
- Chuẩn hoá chữ ký Standard Webhooks (SPEC §8) và tương thích ngược (scheme='legacy').
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

logger = logging.getLogger("websigner.secrets")

DEFAULT_KEK_ID = "k1"
DEV_KEK_ID = "dev-fallback"


def is_dev_mode() -> bool:
    """Kiểm tra xem hệ thống có đang ở chế độ dev/test được phép dùng KEK dẫn xuất không."""
    if os.environ.get("WEBSIGNER_ALLOW_DEV_KEK", "").lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    if config.WEBHOOK_ALLOW_PRIVATE:
        return True
    pub = config.public_url()
    if not pub or not pub.lower().startswith("https://"):
        return True
    return False


def current_kek_id() -> str:
    if os.environ.get("WEBSIGNER_KEK"):
        return os.environ.get("WEBSIGNER_KEK_ID", DEFAULT_KEK_ID)
    if is_dev_mode():
        return os.environ.get("WEBSIGNER_KEK_ID", DEV_KEK_ID)
    return os.environ.get("WEBSIGNER_KEK_ID", DEFAULT_KEK_ID)


def validate_kek() -> None:
    """Kiểm tra cấu hình KEK khi khởi động máy chủ (gọi trong lifespan).

    Không bao giờ âm thầm dẫn xuất KEK trong môi trường production.
    Bắt buộc phải có WEBSIGNER_KEK hợp lệ (32 bytes base64), trừ khi ở chế độ dev/test rõ ràng.
    """
    raw = os.environ.get("WEBSIGNER_KEK")
    if raw:
        try:
            b = base64.b64decode(raw)
            if len(b) != 32:
                raise RuntimeError("WEBSIGNER_KEK phải là chuỗi base64 giải mã đúng 32 bytes")
        except Exception as exc:
            raise RuntimeError(f"WEBSIGNER_KEK không hợp lệ: {exc}") from exc
        return

    if not is_dev_mode():
        raise RuntimeError(
            "WEBSIGNER_KEK là bắt buộc (thiếu biến môi trường WEBSIGNER_KEK trong môi trường production)"
        )
    logger.warning("CẢNH BÁO: Đang dùng khoá KEK dẫn xuất tạm thời ('%s') cho môi trường dev/test", DEV_KEK_ID)


def get_kek(kek_id: str | None = None) -> bytes:
    """Lấy khoá KEK (32 bytes) cho kek_id tương ứng.

    Nếu kek_id trùng với current_kek_id (hoặc None), ưu tiên WEBSIGNER_KEK.
    Nếu kek_id khác (khoá cũ trong quá trình rotation), tìm trong WEBSIGNER_OLD_KEKS.
    Trong chế độ dev/test, chỉ dẫn xuất fallback khi kek_id là DEV_KEK_ID (hoặc None khi chưa cấu hình KEK).
    Không bao giờ âm thầm dẫn xuất cho ID 'k1' khi thiếu WEBSIGNER_KEK.
    """
    cur_kid = current_kek_id()
    target_kid = kek_id or cur_kid

    # 1. Kiểm tra WEBSIGNER_KEK
    env_kek = os.environ.get("WEBSIGNER_KEK")
    if env_kek:
        try:
            kek_bytes = base64.b64decode(env_kek)
            if len(kek_bytes) == 32:
                if kek_id is None or kek_id == cur_kid or kek_id == os.environ.get("WEBSIGNER_KEK_ID", DEFAULT_KEK_ID):
                    return kek_bytes
        except Exception:
            logger.warning("WEBSIGNER_KEK không phải chuỗi base64 hợp lệ 32 bytes")

    # 2. Kiểm tra WEBSIGNER_OLD_KEKS
    old_keks = os.environ.get("WEBSIGNER_OLD_KEKS", "")
    if old_keks and target_kid:
        for entry in old_keks.split(","):
            kid, _, b64 = entry.strip().partition(":")
            if kid == target_kid and b64:
                try:
                    k = base64.b64decode(b64)
                    if len(k) == 32:
                        return k
                except Exception:
                    pass

    # 3. Fallback cho dev/test với ID riêng biệt dev-fallback
    if is_dev_mode():
        if target_kid == DEV_KEK_ID or (env_kek is None and target_kid == cur_kid):
            seed = b"WEBSIGNER_KEK:" + target_kid.encode() + b":" + config.secret_key()
            return hashlib.sha256(seed).digest()

    raise RuntimeError(f"Không tìm thấy KEK hợp lệ cho kek_id='{target_kid}'")

def encrypt(plaintext: bytes, kek_id: str | None = None) -> tuple[bytes, str]:
    """Mã hoá AES-256-GCM. Trả về (nonce + ciphertext + tag, kek_id)."""
    kid = kek_id or current_kek_id()
    key = get_kek(kid)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = nonce + aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, kid


def decrypt(ciphertext: bytes, kek_id: str) -> bytes:
    """Giải mã AES-256-GCM từ (nonce + ciphertext + tag)."""
    key = get_kek(kek_id)
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    data = ciphertext[12:]
    return aesgcm.decrypt(nonce, data, None)


# -----------------------------------------------------------------------------
# Webhook Secrets (whsec_<base64>)
# -----------------------------------------------------------------------------


def new_webhook_secret() -> str:
    """Sinh bí mật webhook ngẫu nhiên 32 bytes dạng whsec_<base64>."""
    raw = secrets.token_bytes(32)
    return "whsec_" + base64.b64encode(raw).decode("ascii")


def encrypt_secret(secret_str: str, kek_id: str | None = None) -> tuple[bytes, str]:
    return encrypt(secret_str.encode("utf-8"), kek_id)


def decrypt_secret(ciphertext: bytes, kek_id: str) -> str:
    return decrypt(ciphertext, kek_id).decode("utf-8")


def decode_webhook_secret_bytes(secret: str) -> bytes:
    """Giải mã phần base64 sau tiền tố 'whsec_' thành 32 byte bí mật."""
    raw = secret.removeprefix("whsec_")
    padded = raw + "=" * (-len(raw) % 4)
    if "-" in raw or "_" in raw:
        return base64.urlsafe_b64decode(padded)
    return base64.b64decode(padded)


def sign_standard_webhook(secret: str, event_id: str, timestamp: int, body: bytes) -> str:
    """Ký Standard Webhooks: v1,<base64(HMAC-SHA256(secret_bytes, "{id}.{timestamp}.{body}"))>."""
    secret_bytes = decode_webhook_secret_bytes(secret)
    msg = f"{event_id}.{timestamp}.".encode("utf-8") + body
    sig = base64.b64encode(hmac.new(secret_bytes, msg, hashlib.sha256).digest()).decode("ascii")
    return f"v1,{sig}"


# -----------------------------------------------------------------------------
# Per-org Signing Key
# -----------------------------------------------------------------------------


def new_signing_key() -> str:
    """Sinh khoá HMAC ngẫu nhiên cho liên kết ký của tổ chức."""
    return secrets.token_urlsafe(32)


def recipient_token_for_org(org: dict[str, Any], recipient_id: str, version: int) -> str:
    """Sinh token liên kết ký.

    Nếu tổ chức dùng scheme='kek' thì dùng khoá riêng của tổ chức đó;
    nếu scheme='legacy' thì dùng khoá toàn hệ thống (tương thích ngược).
    """
    if org.get("signing_key_scheme") == "kek" and org.get("signing_key_ciphertext"):
        try:
            key = decrypt_secret(org["signing_key_ciphertext"], org["signing_key_kek_id"])
            msg = f"recipient|{recipient_id}|{version}".encode()
            digest = hmac.new(key.encode(), msg, hashlib.sha256).digest()
            return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        except Exception as exc:
            logger.warning("Lỗi giải mã signing key của org %s: %s; chuyển sang fallback", org.get("id"), exc)

    return config_recipient_token(recipient_id, version)


def config_recipient_token(recipient_id: str, version: int) -> str:
    message = f"recipient|{recipient_id}|{version}".encode()
    digest = hmac.new(config.secret_key(), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
