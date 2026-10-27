"""Ai đang gọi: khoá API (hệ thống tích hợp) hoặc phiên đăng nhập (giao diện).

Cùng một bộ endpoint ``/v1`` phục vụ cả hai. Khác biệt duy nhất: phiên dùng
cookie nên mọi request thay đổi dữ liệu phải kèm ``X-CSRF-Token``; khoá API
nằm trong header ``Authorization`` nên trình duyệt không tự gửi kèm được.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from . import accounts, plans, security
from .errors import ApiError

SESSION_COOKIE = "ws_session"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class Principal:
    org: dict
    plan: plans.Plan
    user: dict | None = None
    api_key_id: str | None = None
    session_token: str | None = None
    csrf_token: str | None = None

    @property
    def org_id(self) -> str:
        return self.org["id"]

    @property
    def actor(self) -> str:
        if self.user is not None:
            return f"user:{self.user['id']}"
        return f"api_key:{self.api_key_id}"

    @property
    def is_admin(self) -> bool:
        return self.user is not None and self.user["role"] in ("owner", "admin")


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def user_agent(request: Request) -> str | None:
    value = request.headers.get("user-agent")
    return value[:300] if value else None


def _org(ctx: dict) -> dict:
    return {
        "id": ctx["org_id"],
        "name": ctx["org_name"],
        "plan": ctx["org_plan"],
        "created_at": ctx["org_created_at"],
        "embed_origins": ctx["org_embed_origins"],
    }


async def _from_api_key(request: Request, header: str) -> Principal:
    scheme, _, secret = header.partition(" ")
    if scheme.lower() != "bearer" or not secret.strip():
        raise ApiError(401, "unauthenticated", "Header Authorization phải là 'Bearer <khoá API>'")
    ctx = await accounts.api_key_context(secret.strip())
    if ctx is None:
        raise ApiError(401, "invalid_api_key", "Khoá API không hợp lệ hoặc đã bị thu hồi")
    plan = plans.get(ctx["org_plan"])
    security.enforce_rate(f"key:{ctx['key_id']}", plan.api_requests_per_minute)
    return Principal(org=_org(ctx), plan=plan, api_key_id=ctx["key_id"])


async def _from_session(request: Request) -> Principal:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise ApiError(401, "unauthenticated", "Chưa đăng nhập")
    ctx = await accounts.session_context(token)
    if ctx is None:
        raise ApiError(401, "unauthenticated", "Phiên đăng nhập đã hết hạn")
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not accounts.constant_time_equal(sent, ctx["csrf_token"]):
            raise ApiError(403, "csrf_failed", "Thiếu hoặc sai X-CSRF-Token")
    user = {k: ctx[k] for k in ("id", "email", "name", "role", "password_hash", "created_at")}
    return Principal(
        org=_org(ctx),
        plan=plans.get(ctx["org_plan"]),
        user=user,
        session_token=token,
        csrf_token=ctx["csrf_token"],
    )


async def principal(request: Request) -> Principal:
    """Khoá API hoặc phiên đăng nhập — dùng cho API tài liệu ``/v1``."""
    header = request.headers.get("authorization")
    if header:
        return await _from_api_key(request, header)
    return await _from_session(request)


async def dashboard_user(request: Request) -> Principal:
    """Chỉ phiên đăng nhập. Khoá API không tự tạo khoá API hay mời người được."""
    if request.headers.get("authorization"):
        raise ApiError(403, "session_required", "Thao tác này chỉ làm được trên giao diện quản trị")
    return await _from_session(request)


async def org_admin(request: Request) -> Principal:
    who = await dashboard_user(request)
    if not who.is_admin:
        raise ApiError(403, "forbidden", "Cần quyền quản trị tổ chức")
    return who
