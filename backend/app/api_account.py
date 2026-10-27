"""Tài khoản và quản trị tổ chức — chỉ cho giao diện (cookie phiên).

Khoá API cố tình không gọi được nhóm này: lộ khoá API không kéo theo việc kẻ
gian tự cấp thêm khoá, đổi webhook hay mời người vào tổ chức.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from . import accounts, mailer, plans, security, signing, trust, webhooks
from .auth import SESSION_COOKIE, Principal, client_ip, dashboard_user, org_admin, user_agent
from .config import ALLOW_SIGNUP, SESSION_TTL_DAYS
from .errors import ApiError
from .web import base_url, is_https

router = APIRouter(prefix="/api", tags=["Tài khoản & tổ chức"])


class RegisterRequest(BaseModel):
    org_name: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)


class LoginRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class ForgotRequest(BaseModel):
    email: str = Field(max_length=254)


class ResetRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(max_length=256)


class AcceptInvite(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    password: str = Field(max_length=256)


class OrgUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class MemberInvite(BaseModel):
    email: str = Field(max_length=254)
    name: str = Field(min_length=1, max_length=200)
    role: Literal["admin", "member"] = "member"


class MemberUpdate(BaseModel):
    role: Literal["admin", "member"]


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class WebhookCreate(BaseModel):
    url: str = Field(max_length=2000)
    events: list[str] = Field(default_factory=lambda: ["*"])
    description: str | None = Field(default=None, max_length=300)


class WebhookUpdate(BaseModel):
    url: str | None = Field(default=None, max_length=2000)
    events: list[str] | None = None
    description: str | None = Field(default=None, max_length=300)
    enabled: bool | None = None


# --------------------------------------------------------------------------
# Công khai
# --------------------------------------------------------------------------


@router.get("/config", summary="Cấu hình công khai cho giao diện")
async def public_config() -> dict:
    return {
        "profile": signing.default_profile().value,
        "timestamping": bool(trust.tsa_url()),
        "signup_enabled": ALLOW_SIGNUP,
        "email_enabled": mailer.enabled(),
        "webhook_events": list(webhooks.EVENT_TYPES),
    }


@router.get("/plans", summary="Các gói dịch vụ")
async def list_plans() -> list[dict]:
    return [plan.to_dict() for plan in plans.PLANS.values()]


# --------------------------------------------------------------------------
# Đăng ký / đăng nhập
# --------------------------------------------------------------------------


def _me(who: Principal | None = None, *, user: dict | None = None, org: dict | None = None, csrf: str) -> dict:
    return {
        "user": accounts.user_view(user or who.user),  # type: ignore[union-attr]
        "org": accounts.org_view(org or who.org),  # type: ignore[union-attr]
        "csrf_token": csrf,
        "email_enabled": mailer.enabled(),
    }


async def _start_session(request: Request, response: Response, user: dict) -> dict:
    token, csrf = await accounts.create_session(user["id"], client_ip(request), user_agent(request))
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL_DAYS * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=is_https(request),
        path="/",
    )
    org = await accounts.get_org(user["org_id"])
    return _me(user=user, org=org, csrf=csrf)


@router.post("/auth/register", status_code=201, summary="Đăng ký tổ chức mới (gói miễn phí)")
async def register(request: Request, response: Response, body: RegisterRequest) -> dict:
    if not ALLOW_SIGNUP:
        raise ApiError(403, "signup_disabled", "Máy chủ này không mở đăng ký tự do")
    security.enforce_rate(f"register:{client_ip(request)}", 10)
    user = await accounts.register(body.org_name, body.name, body.email, body.password)
    return await _start_session(request, response, user)


@router.post("/auth/login", summary="Đăng nhập")
async def login(request: Request, response: Response, body: LoginRequest) -> dict:
    security.enforce_rate(f"login-ip:{client_ip(request)}", 20)
    security.enforce_rate(f"login-email:{body.email.strip().lower()}", 10)
    user = await accounts.authenticate(body.email, body.password)
    if user is None:
        raise ApiError(401, "invalid_credentials", "Email hoặc mật khẩu không đúng")
    return await _start_session(request, response, user)


@router.post("/auth/logout", status_code=204, summary="Đăng xuất")
async def logout(who: Principal = Depends(dashboard_user)) -> Response:
    await accounts.delete_session(who.session_token or "")
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/auth/me", summary="Người dùng hiện tại, tổ chức và CSRF token")
async def me(who: Principal = Depends(dashboard_user)) -> dict:
    return _me(who, csrf=who.csrf_token or "")


@router.post("/auth/password", status_code=204, summary="Đổi mật khẩu (đăng xuất mọi phiên khác)")
async def change_password(body: PasswordChange, who: Principal = Depends(dashboard_user)) -> Response:
    await accounts.change_password(who.user, body.current_password, body.new_password, who.session_token)  # type: ignore[arg-type]
    return Response(status_code=204)


@router.post("/auth/forgot", status_code=202, summary="Gửi email đặt lại mật khẩu")
async def forgot(request: Request, body: ForgotRequest) -> dict:
    security.enforce_rate(f"forgot:{client_ip(request)}", 5)
    await accounts.request_password_reset(body.email, base_url(request))
    return {"ok": True}


@router.post("/auth/reset", status_code=204, summary="Đặt mật khẩu mới bằng liên kết trong email")
async def reset(request: Request, body: ResetRequest) -> Response:
    security.enforce_rate(f"reset:{client_ip(request)}", 10)
    await accounts.reset_password(body.token, body.password)
    return Response(status_code=204)


@router.get("/auth/invite/{token}", summary="Thông tin lời mời thành viên")
async def invite_info(request: Request, token: str) -> dict:
    security.enforce_rate(f"invite:{client_ip(request)}", 30)
    row = await accounts.peek_user_token(token, "invite")
    return {"email": row["email"], "name": row["name"], "org_name": row["org_name"]}


@router.post("/auth/accept-invite", summary="Nhận lời mời: đặt tên, mật khẩu và đăng nhập")
async def accept_invite(request: Request, response: Response, body: AcceptInvite) -> dict:
    security.enforce_rate(f"invite:{client_ip(request)}", 30)
    user = await accounts.accept_invite(body.token, body.name, body.password)
    return await _start_session(request, response, user)


# --------------------------------------------------------------------------
# Tổ chức, thành viên
# --------------------------------------------------------------------------


@router.patch("/org", summary="Đổi tên tổ chức")
async def update_org(body: OrgUpdate, who: Principal = Depends(org_admin)) -> dict:
    return accounts.org_view(await accounts.rename_org(who.org_id, body.name))


@router.get("/org/members", summary="Thành viên tổ chức")
async def members(who: Principal = Depends(dashboard_user)) -> list[dict]:
    return await accounts.list_members(who.org_id)


@router.post("/org/members", status_code=201, summary="Mời thành viên")
async def invite_member(request: Request, body: MemberInvite, who: Principal = Depends(org_admin)) -> dict:
    member, link = await accounts.invite_member(
        who.org, who.user, body.email, body.name, body.role, base_url(request)  # type: ignore[arg-type]
    )
    return {"member": member, "invite_url": link}


@router.patch("/org/members/{user_id}", summary="Đổi vai trò thành viên")
async def update_member(user_id: str, body: MemberUpdate, who: Principal = Depends(org_admin)) -> dict:
    return await accounts.update_member_role(who.org_id, user_id, body.role)


@router.delete("/org/members/{user_id}", status_code=204, summary="Xoá thành viên")
async def remove_member(user_id: str, who: Principal = Depends(org_admin)) -> Response:
    await accounts.remove_member(who.org_id, user_id)
    return Response(status_code=204)


# --------------------------------------------------------------------------
# Khoá API
# --------------------------------------------------------------------------


@router.get("/org/api-keys", summary="Khoá API của tổ chức")
async def api_keys(who: Principal = Depends(org_admin)) -> list[dict]:
    return await accounts.list_api_keys(who.org_id)


@router.post("/org/api-keys", status_code=201, summary="Tạo khoá API — bản rõ chỉ hiện một lần")
async def create_api_key(body: ApiKeyCreate, who: Principal = Depends(org_admin)) -> dict:
    key, secret = await accounts.create_api_key(who.org, body.name, who.user["id"])  # type: ignore[index]
    return {"key": key, "secret": secret}


@router.delete("/org/api-keys/{key_id}", status_code=204, summary="Thu hồi khoá API")
async def revoke_api_key(key_id: str, who: Principal = Depends(org_admin)) -> Response:
    await accounts.revoke_api_key(who.org_id, key_id)
    return Response(status_code=204)


# --------------------------------------------------------------------------
# Webhook
# --------------------------------------------------------------------------


@router.get("/org/webhooks", summary="Webhook của tổ chức")
async def list_webhooks(who: Principal = Depends(org_admin)) -> list[dict]:
    return await webhooks.list_endpoints(who.org_id)


@router.post("/org/webhooks", status_code=201, summary="Thêm webhook")
async def create_webhook(body: WebhookCreate, who: Principal = Depends(org_admin)) -> dict:
    return await webhooks.create_endpoint(who.org, body.url, body.events, body.description)


@router.get("/org/webhooks/{endpoint_id}", summary="Chi tiết webhook, kèm secret")
async def get_webhook(endpoint_id: str, who: Principal = Depends(org_admin)) -> dict:
    return await webhooks.get_endpoint(who.org_id, endpoint_id)


@router.patch("/org/webhooks/{endpoint_id}", summary="Sửa webhook")
async def update_webhook(endpoint_id: str, body: WebhookUpdate, who: Principal = Depends(org_admin)) -> dict:
    return await webhooks.update_endpoint(who.org_id, endpoint_id, body.model_dump(exclude_unset=True))


@router.delete("/org/webhooks/{endpoint_id}", status_code=204, summary="Xoá webhook")
async def delete_webhook(endpoint_id: str, who: Principal = Depends(org_admin)) -> Response:
    await webhooks.delete_endpoint(who.org_id, endpoint_id)
    return Response(status_code=204)


@router.post("/org/webhooks/{endpoint_id}/rotate-secret", summary="Đổi secret ký webhook")
async def rotate_webhook_secret(endpoint_id: str, who: Principal = Depends(org_admin)) -> dict:
    return await webhooks.rotate_secret(who.org_id, endpoint_id)


@router.post("/org/webhooks/{endpoint_id}/test", summary="Gửi sự kiện thử")
async def test_webhook(endpoint_id: str, who: Principal = Depends(org_admin)) -> dict:
    return await webhooks.send_test(who.org, endpoint_id)


@router.get("/org/webhooks/{endpoint_id}/deliveries", summary="50 lần gửi gần nhất")
async def webhook_deliveries(endpoint_id: str, who: Principal = Depends(org_admin)) -> list[dict]:
    return await webhooks.list_deliveries(who.org_id, endpoint_id)


@router.post("/org/webhooks/{endpoint_id}/deliveries/{delivery_id}/retry", summary="Gửi lại")
async def retry_webhook_delivery(
    endpoint_id: str, delivery_id: str, who: Principal = Depends(org_admin)
) -> dict:
    return await webhooks.retry_delivery(who.org_id, endpoint_id, delivery_id)
