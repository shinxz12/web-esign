"""Mật khẩu, token, chữ ký HMAC và giới hạn tần suất.

Quy ước token:

* token ngẫu nhiên (phiên, khoá API, thiết bị, lời mời): server chỉ lưu
  SHA-256. Token 256 bit không dò được nên không cần băm chậm.
* token suy ra (liên kết ký, secret webhook): ``HMAC(khoá server, mục đích,
  id, phiên bản)``. Server tính lại được để hiển thị lần nữa mà không phải lưu
  bản rõ; tăng phiên bản là thu hồi bản cũ.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

from . import config
from .errors import ApiError


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def derive_token(purpose: str, *parts: object) -> str:
    message = "|".join([purpose, *map(str, parts)]).encode()
    digest = hmac.new(config.secret_key(), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def recipient_token(recipient_id: str, version: int) -> str:
    return derive_token("recipient", recipient_id, version)


def webhook_secret(endpoint_id: str, version: int) -> str:
    return "whsec_" + derive_token("webhook", endpoint_id, version)


def sign_webhook(secret: str, timestamp: int, body: bytes) -> str:
    """Giống Stripe: HMAC-SHA256 trên ``"<t>." + body``, hex."""
    return hmac.new(
        secret.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256
    ).hexdigest()


# --------------------------------------------------------------------------
# Mật khẩu: scrypt (thư viện chuẩn), chạy ngoài event loop
# --------------------------------------------------------------------------

_SCRYPT_N_LOG2, _SCRYPT_R, _SCRYPT_P = 15, 8, 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_LENGTH = 10


def _scrypt(password: str, salt: bytes, n_log2: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=1 << n_log2,
        r=r,
        p=p,
        maxmem=_SCRYPT_MAXMEM,
        dklen=32,
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password_sync(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, _SCRYPT_N_LOG2, _SCRYPT_R, _SCRYPT_P)
    return f"scrypt${_SCRYPT_N_LOG2}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password_sync(password: str, encoded: str | None) -> bool:
    if not encoded:
        # Vẫn tốn đúng chừng ấy thời gian: không lộ email nào tồn tại.
        _scrypt(password, b"\0" * 16, _SCRYPT_N_LOG2, _SCRYPT_R, _SCRYPT_P)
        return False
    try:
        scheme, n_log2, r, p, salt, digest = encoded.split("$")
        if scheme != "scrypt":
            return False
        actual = _scrypt(password, base64.b64decode(salt), int(n_log2), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, base64.b64decode(digest))


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(hash_password_sync, password)


async def verify_password(password: str, encoded: str | None) -> bool:
    return await asyncio.to_thread(verify_password_sync, password, encoded)


def check_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ApiError(
            400, "weak_password", f"Mật khẩu phải dài ít nhất {MIN_PASSWORD_LENGTH} ký tự"
        )
    if len(password) > 256:
        raise ApiError(400, "weak_password", "Mật khẩu quá dài")


# --------------------------------------------------------------------------
# Giới hạn tần suất: token bucket trong bộ nhớ tiến trình
# --------------------------------------------------------------------------


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Đủ cho một tiến trình backend (agent relay cũng đòi đúng một tiến trình)."""

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}

    def hit(self, key: str, per_minute: int, burst: int | None = None) -> float | None:
        """-> None nếu được phép, ngược lại số giây phải chờ."""
        capacity = float(burst or per_minute)
        rate = per_minute / 60.0
        now = time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = _Bucket(capacity, now)
        else:
            bucket.tokens = min(capacity, bucket.tokens + (now - bucket.updated) * rate)
            bucket.updated = now
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return None
        return (1 - bucket.tokens) / rate

    def prune(self, idle_seconds: float = 600) -> None:
        cutoff = time.monotonic() - idle_seconds
        for key in [k for k, b in self._buckets.items() if b.updated < cutoff]:
            self._buckets.pop(key, None)


limiter = RateLimiter()


def enforce_rate(key: str, per_minute: int, burst: int | None = None) -> None:
    wait = limiter.hit(key, per_minute, burst)
    if wait is not None:
        retry = max(1, int(wait + 0.999))
        raise ApiError(
            429,
            "rate_limited",
            f"Quá nhiều yêu cầu, thử lại sau {retry} giây",
            headers={"Retry-After": str(retry)},
        )
