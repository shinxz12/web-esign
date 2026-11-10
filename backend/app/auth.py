"""Ai đang gọi: khoá API (hệ thống tích hợp), phiên đăng nhập (giao diện) hoặc đối tác (partner).

SPEC §1:
- Khoá tenant: wsk_live_<random>
- Khoá partner: wsp_live_<random> (quản trị tenant con qua /v1/partner/* hoặc uỷ quyền qua On-Behalf-Of)
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from . import accounts, db, plans, security
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
    partner: dict | None = None
    session_token: str | None = None
    csrf_token: str | None = None

    @property
    def org_id(self) -> str:
        return self.org.get("id", "")

    @property
    def is_partner(self) -> bool:
        return self.partner is not None

    @property
    def actor(self) -> str:
        if self.partner is not None:
            return f"partner:{self.partner['id']}"
        if self.user is not None:
            return f"user:{self.user['id']}"
        return f"api_key:{self.api_key_id}"

    @property
    def is_admin(self) -> bool:
        return self.user is not None and self.user.get("role") in ("owner", "admin")


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
        "embed_origins": list(ctx.get("org_embed_origins") or []),
        "settings": dict(ctx.get("org_settings") or {}),
        "signing_key_ciphertext": ctx.get("org_signing_key_ciphertext"),
        "signing_key_kek_id": ctx.get("org_signing_key_kek_id"),
        "signing_key_scheme": ctx.get("org_signing_key_scheme", "legacy"),
    }


async def partner_context(secret: str) -> dict | None:
    if not secret.startswith("wsp_live_"):
        return None
    return await db.system_fetchone(
        "SELECT * FROM partners WHERE key_hash = %s",
        (security.token_hash(secret),),
    )


async def _from_api_key(request: Request, header: str) -> Principal:
    scheme, _, secret = header.partition(" ")
    if scheme.lower() != "bearer" or not secret.strip():
        raise ApiError(401, "unauthenticated", "Header Authorization phải là 'Bearer <khoá API>'")
    raw_secret = secret.strip()

    if raw_secret.startswith("wsp_live_"):
        partner = await partner_context(raw_secret)
        if partner is None:
            raise ApiError(401, "invalid_api_key", "Khoá đối tác không hợp lệ hoặc đã bị thu hồi")
        if request.url.path.startswith("/v1/partner"):
            return Principal(
                org={"id": "", "name": "", "plan": "enterprise", "created_at": partner["created_at"], "embed_origins": []},
                plan=plans.get("enterprise"),
                partner=partner,
            )
        # Gọi /v1/* thông thường: yêu cầu On-Behalf-Of
        tenant_id = request.headers.get("on-behalf-of", "").strip()
        if not tenant_id:
            raise ApiError(400, "on_behalf_of_required", "Khoá đối tác gọi API tài liệu cần header On-Behalf-Of")
        tenant = await db.system_fetchone(
            "SELECT * FROM organizations WHERE id = %s AND partner_id = %s",
            (tenant_id, partner["id"]),
        )
        if tenant is None:
            # SPEC §1: 404 (never 403): existence is not leaked
            raise ApiError(404, "not_found", "Không tìm thấy tổ chức")
        db.set_tenant_id(tenant["id"])
        plan = plans.get(tenant["plan"])
        await security.enforce_rate(f"partner:{partner['id']}:tenant:{tenant['id']}", plan.api_requests_per_minute)
        return Principal(
            org={
                "id": tenant["id"],
                "name": tenant["name"],
                "plan": tenant["plan"],
                "created_at": tenant["created_at"],
                "embed_origins": list(tenant.get("embed_origins") or []),
                "settings": dict(tenant.get("settings") or {}),
                "signing_key_ciphertext": tenant.get("signing_key_ciphertext"),
                "signing_key_kek_id": tenant.get("signing_key_kek_id"),
                "signing_key_scheme": tenant.get("signing_key_scheme", "legacy"),
            },
            plan=plan,
            partner=partner,
        )

    # Khoá tenant wsk_live_...
    if request.url.path.startswith("/v1/partner"):
        raise ApiError(403, "partner_only", "Chỉ khoá đối tác mới được gọi API partner")

    ctx = await accounts.api_key_context(raw_secret)
    if ctx is None:
        raise ApiError(401, "invalid_api_key", "Khoá API không hợp lệ hoặc đã bị thu hồi")
    db.set_tenant_id(ctx["org_id"])
    plan = plans.get(ctx["org_plan"])
    await security.enforce_rate(f"key:{ctx['key_id']}", plan.api_requests_per_minute)
    return Principal(org=_org(ctx), plan=plan, api_key_id=ctx["key_id"])


async def _from_session(request: Request) -> Principal:
    if request.url.path.startswith("/v1/partner"):
        raise ApiError(403, "partner_only", "Chỉ khoá đối tác mới được gọi API partner")
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
    db.set_tenant_id(ctx["org_id"])
    user = {k: ctx[k] for k in ("id", "email", "name", "role", "password_hash", "created_at")}
    return Principal(
        org=_org(ctx),
        plan=plans.get(ctx["org_plan"]),
        user=user,
        session_token=token,
        csrf_token=ctx["csrf_token"],
    )


async def principal(request: Request) -> Principal:
    """Khoá API, đối tác (On-Behalf-Of) hoặc phiên đăng nhập — dùng cho API tài liệu ``/v1``."""
    header = request.headers.get("authorization")
    if header:
        return await _from_api_key(request, header)
    return await _from_session(request)


async def partner_principal(request: Request) -> Principal:
    """Chỉ khoá đối tác (wsp_live_...) — dùng cho API ``/v1/partner/*``."""
    header = request.headers.get("authorization")
    if not header:
        raise ApiError(401, "unauthenticated", "Header Authorization phải là 'Bearer <khoá đối tác>'")
    scheme, _, secret = header.partition(" ")
    raw_secret = secret.strip()
    if scheme.lower() != "bearer" or not raw_secret.startswith("wsp_live_"):
        raise ApiError(403, "partner_only", "Chỉ khoá đối tác mới được gọi API partner")
    partner = await partner_context(raw_secret)
    if partner is None:
        raise ApiError(401, "invalid_api_key", "Khoá đối tác không hợp lệ hoặc đã bị thu hồi")
    return Principal(
        org={},
        plan=plans.get("enterprise"),
        partner=partner,
    )


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
