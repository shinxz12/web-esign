"""Partner API theo SPEC §1-2:
- Quản trị các tenant thuộc quyền sở hữu của partner.
- Xác thực Bearer wsp_live_<...>.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field
from . import accounts, db, plans, secrets_crypto, security, webhooks
from .auth import Principal, partner_principal
from .errors import ApiError, not_found

router = APIRouter(prefix="/v1/partner", tags=["Partner API"])


def tenant_view(row: dict) -> dict:
    created = row["created_at"]
    created_str = created.isoformat() if isinstance(created, datetime) else str(created)
    settings = dict(row.get("settings") or {})
    if "embed_origins" not in settings:
        settings["embed_origins"] = list(row.get("embed_origins") or [])
    return {
        "id": row["id"],
        "name": row["name"],
        "external_id": row.get("external_id"),
        "plan": row["plan"],
        "settings": settings,
        "created_at": created_str,
    }
async def _check_idempotency(scope: str, key: str, fingerprint: bytes) -> tuple[int, dict] | None:
    if not 1 <= len(key) <= 200:
        raise ApiError(400, "invalid_idempotency_key", "Idempotency-Key dài 1–200 ký tự")
    inserted = await db.system_fetchone(
        "INSERT INTO idempotency_keys (org_id, key, fingerprint) VALUES (%s, %s, %s) "
        "ON CONFLICT DO NOTHING RETURNING key",
        (scope, key, fingerprint),
    )
    if inserted is not None:
        return None
    row = await db.system_fetchone(
        "SELECT fingerprint, response_status, response_body FROM idempotency_keys WHERE org_id = %s AND key = %s",
        (scope, key),
    )
    if row is None:
        return await _check_idempotency(scope, key, fingerprint)
    if bytes(row["fingerprint"]) != fingerprint:
        raise ApiError(422, "idempotency_mismatch", "Idempotency-Key đã dùng cho một request khác")
    if row["response_status"] is None:
        raise ApiError(409, "idempotency_in_progress", "Request với Idempotency-Key này đang được xử lý")
    return row["response_status"], row["response_body"]


async def _save_idempotency(scope: str, key: str, status: int, body: dict) -> None:
    await db.system_execute(
        "UPDATE idempotency_keys SET response_status = %s, response_body = %s "
        "WHERE org_id = %s AND key = %s",
        (status, Jsonb(body), scope, key),
    )


async def _clear_idempotency(scope: str, key: str) -> None:
    await db.system_execute(
        "DELETE FROM idempotency_keys WHERE org_id = %s AND key = %s",
        (scope, key),
    )


async def _require_partner_tenant(partner_id: str, tenant_id: str) -> dict:
    row = await db.system_fetchone(
        "SELECT * FROM organizations WHERE id = %s AND partner_id = %s",
        (tenant_id, partner_id),
    )
    if row is None:
        raise not_found("Không tìm thấy tổ chức")
    return row


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    external_id: str | None = Field(default=None, max_length=200)
    plan: str = Field(default="free")
    settings: dict[str, Any] = Field(default_factory=dict)


class TenantPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    plan: str | None = Field(default=None)
    settings: dict[str, Any] | None = None


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class WebhookCreate(BaseModel):
    url: str = Field(max_length=2000)
    events: list[str] = Field(default_factory=lambda: ["*"])
    description: str | None = Field(default=None, max_length=300)


@router.post("/tenants", summary="Tạo tenant hoặc trả về tenant đã có nếu trùng external_id")
async def create_tenant(request: Request, body: TenantCreate, who: Principal = Depends(partner_principal)):
    partner_id = who.partner["id"]  # type: ignore[index]

    if body.plan not in plans.PLANS:
        raise ApiError(400, "invalid_plan", f"Gói dịch vụ không hợp lệ: {body.plan}")

    external_id = body.external_id.strip() if body.external_id and body.external_id.strip() else None
    idem_key = request.headers.get("idempotency-key")
    idem_scope = f"partner:{partner_id}"
    if idem_key:
        fingerprint = hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True).encode()).digest()
        replay = await _check_idempotency(idem_scope, idem_key, fingerprint)
        if replay is not None:
            status_code, replay_body = replay
            return JSONResponse(replay_body, status_code=status_code, headers={"Idempotent-Replayed": "true"})

    try:
        org_id = security.new_id("org")
        settings = dict(body.settings)
        raw_origins = settings.get("embed_origins") or []
        embed_origins = sorted({accounts.normalize_embed_origin(o) for o in raw_origins})
        settings["embed_origins"] = embed_origins

        signing_key = secrets_crypto.new_signing_key()
        key_ciphertext, kek_id = secrets_crypto.encrypt_secret(signing_key)

        if external_id:
            row = await db.system_fetchone(
                "INSERT INTO organizations (id, name, plan, partner_id, external_id, settings, embed_origins, "
                "                           signing_key_ciphertext, signing_key_kek_id, signing_key_scheme) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'kek') "
                "ON CONFLICT (partner_id, external_id) WHERE external_id IS NOT NULL DO NOTHING RETURNING *",
                (
                    org_id,
                    body.name.strip(),
                    body.plan,
                    partner_id,
                    external_id,
                    Jsonb(settings),
                    embed_origins,
                    key_ciphertext,
                    kek_id,
                ),
            )
            if row is None:
                row = await db.system_fetchone(
                    "SELECT * FROM organizations WHERE partner_id = %s AND external_id = %s",
                    (partner_id, external_id),
                )
                view = tenant_view(row)
                if idem_key:
                    await _save_idempotency(idem_scope, idem_key, 200, view)
                return JSONResponse(view, status_code=200)
        else:
            row = await db.system_fetchone(
                "INSERT INTO organizations (id, name, plan, partner_id, external_id, settings, embed_origins, "
                "                           signing_key_ciphertext, signing_key_kek_id, signing_key_scheme) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'kek') RETURNING *",
                (
                    org_id,
                    body.name.strip(),
                    body.plan,
                    partner_id,
                    None,
                    Jsonb(settings),
                    embed_origins,
                    key_ciphertext,
                    kek_id,
                ),
            )
        view = tenant_view(row)
        if idem_key:
            await _save_idempotency(idem_scope, idem_key, 201, view)
        return JSONResponse(view, status_code=201)
    except BaseException:
        if idem_key:
            await _clear_idempotency(idem_scope, idem_key)
        raise


@router.get("/tenants", summary="Danh sách tenant của đối tác")
async def list_tenants(
    external_id: str | None = Query(None),
    cursor: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    who: Principal = Depends(partner_principal),
):
    partner_id = who.partner["id"]  # type: ignore[index]
    where = ["partner_id = %s"]
    params: list[Any] = [partner_id]

    if external_id:
        where.append("external_id = %s")
        params.append(external_id)

    if cursor:
        try:
            created_str, last_id = base64.urlsafe_b64decode(cursor.encode()).decode().split("|", 1)
            where.append("(created_at, id) < (%s, %s)")
            params.extend([datetime.fromisoformat(created_str), last_id])
        except Exception:
            raise ApiError(400, "invalid_cursor", "Cursor không hợp lệ")

    sql = (
        f"SELECT * FROM organizations WHERE {' AND '.join(where)} "
        f"ORDER BY created_at DESC, id DESC LIMIT %s"
    )
    params.append(limit + 1)
    rows = await db.system_fetchall(sql, params)

    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        raw = f"{last['created_at'].isoformat()}|{last['id']}"
        next_cursor = base64.urlsafe_b64encode(raw.encode()).decode()

    return {"items": [tenant_view(r) for r in page], "next_cursor": next_cursor}


@router.get("/tenants/{id}", summary="Thông tin chi tiết một tenant")
async def get_tenant(id: str, who: Principal = Depends(partner_principal)):
    row = await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]
    return tenant_view(row)


@router.patch("/tenants/{id}", summary="Cập nhật thông tin tenant")
async def patch_tenant(id: str, body: TenantPatch, who: Principal = Depends(partner_principal)):
    tenant = await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]

    changes: dict[str, Any] = {}
    if body.name is not None:
        changes["name"] = body.name.strip()
    if body.plan is not None:
        if body.plan not in plans.PLANS:
            raise ApiError(400, "invalid_plan", f"Gói dịch vụ không hợp lệ: {body.plan}")
        changes["plan"] = body.plan

    current_settings = dict(tenant.get("settings") or {})
    if body.settings is not None:
        merged = {**current_settings, **body.settings}
        if "embed_origins" in body.settings:
            raw_origins = body.settings["embed_origins"] or []
            origins = sorted({accounts.normalize_embed_origin(o) for o in raw_origins})
            changes["embed_origins"] = origins
            merged["embed_origins"] = origins
        changes["settings"] = Jsonb(merged)

    if not changes:
        return tenant_view(tenant)

    assignments = ", ".join(f"{col} = %s" for col in changes)
    row = await db.system_fetchone(
        f"UPDATE organizations SET {assignments} WHERE id = %s RETURNING *",
        (*changes.values(), id),
    )
    return tenant_view(row)


@router.post("/tenants/{id}/api-keys", status_code=201, summary="Tạo khoá API cho tenant")
async def create_tenant_api_key(
    request: Request, id: str, body: ApiKeyCreate, who: Principal = Depends(partner_principal)
):
    tenant = await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]
    plan = plans.get(tenant["plan"])

    idem_key = request.headers.get("idempotency-key")
    if idem_key:
        fingerprint = hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True).encode()).digest()
        replay = await _check_idempotency(id, idem_key, fingerprint)
        if replay is not None:
            status_code, replay_body = replay
            return JSONResponse(replay_body, status_code=status_code, headers={"Idempotent-Replayed": "true"})

    try:
        secret = accounts.API_KEY_PREFIX + security.random_token()
        prefix = secret[: len(accounts.API_KEY_PREFIX) + 6]
        key_id = security.new_id("key")

        cur_count = await db.system_fetchone(
            "SELECT count(*) AS n FROM api_keys WHERE org_id = %s AND revoked_at IS NULL", (id,)
        )
        if cur_count and cur_count["n"] >= plan.max_api_keys:
            raise ApiError(402, "quota_exceeded", f"Gói {plan.name} tối đa {plan.max_api_keys} khoá API")

        row = await db.system_fetchone(
            "INSERT INTO api_keys (id, org_id, name, prefix, key_hash) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING *",
            (key_id, id, body.name.strip(), prefix, security.token_hash(secret)),
        )
        result = {
            "key": {
                "id": row["id"],
                "name": row["name"],
                "prefix": row["prefix"],
                "created_at": row["created_at"].isoformat(),
            },
            "secret": secret,
        }
        if idem_key:
            await _save_idempotency(id, idem_key, 201, result)
        return result
    except BaseException:
        if idem_key:
            await _clear_idempotency(id, idem_key)
        raise


@router.delete("/tenants/{id}/api-keys/{key_id}", status_code=204, summary="Thu hồi khoá API của tenant")
async def revoke_tenant_api_key(id: str, key_id: str, who: Principal = Depends(partner_principal)):
    await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]
    count = await db.system_execute(
        "UPDATE api_keys SET revoked_at = now() WHERE id = %s AND org_id = %s AND revoked_at IS NULL",
        (key_id, id),
    )
    if not count:
        raise not_found("Không tìm thấy khoá API")
    return Response(status_code=204)


@router.post("/tenants/{id}/webhooks", status_code=201, summary="Tạo webhook endpoint cho tenant")
async def create_tenant_webhook(
    request: Request, id: str, body: WebhookCreate, who: Principal = Depends(partner_principal)
):
    tenant = await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]
    plan = plans.get(tenant["plan"])

    idem_key = request.headers.get("idempotency-key")
    if idem_key:
        fingerprint = hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True).encode()).digest()
        replay = await _check_idempotency(id, idem_key, fingerprint)
        if replay is not None:
            status_code, replay_body = replay
            return JSONResponse(replay_body, status_code=status_code, headers={"Idempotent-Replayed": "true"})

    try:
        url = webhooks.validate_url(body.url)
        events = webhooks._validate_events(body.events)

        cur_count = await db.system_fetchone(
            "SELECT count(*) AS n FROM webhook_endpoints WHERE org_id = %s", (id,)
        )
        if cur_count and cur_count["n"] >= plan.max_webhooks:
            raise ApiError(402, "quota_exceeded", f"Gói {plan.name} tối đa {plan.max_webhooks} webhook")

        raw_secret = secrets_crypto.new_webhook_secret()
        ciphertext, kek_id = secrets_crypto.encrypt_secret(raw_secret)
        wh_id = security.new_id("wh")

        row = await db.system_fetchone(
            "INSERT INTO webhook_endpoints (id, org_id, url, description, events, secret_scheme, secret_ciphertext, kek_id) "
            "VALUES (%s, %s, %s, %s, %s, 'kek', %s, %s) RETURNING *",
            (wh_id, id, url, body.description, events, ciphertext, kek_id),
        )
        result = {
            "endpoint": webhooks.endpoint_view(row),
            "secret": raw_secret,
        }
        if idem_key:
            await _save_idempotency(id, idem_key, 201, result)
        return result
    except BaseException:
        if idem_key:
            await _clear_idempotency(id, idem_key)
        raise


@router.get("/tenants/{id}/webhooks", summary="Danh sách webhook của tenant")
async def list_tenant_webhooks(id: str, who: Principal = Depends(partner_principal)):
    await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]
    rows = await db.system_fetchall(
        "SELECT * FROM webhook_endpoints WHERE org_id = %s ORDER BY created_at", (id,)
    )
    return [webhooks.endpoint_view(r) for r in rows]


@router.delete("/tenants/{id}/webhooks/{endpoint_id}", status_code=204, summary="Xoá webhook của tenant")
async def delete_tenant_webhook(id: str, endpoint_id: str, who: Principal = Depends(partner_principal)):
    await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]
    count = await db.system_execute(
        "DELETE FROM webhook_endpoints WHERE id = %s AND org_id = %s", (endpoint_id, id)
    )
    if not count:
        raise not_found("Không tìm thấy webhook")
    return Response(status_code=204)


@router.post("/tenants/{id}/webhooks/{endpoint_id}/rotate-secret", summary="Đổi secret ký webhook của tenant")
async def rotate_tenant_webhook_secret(id: str, endpoint_id: str, who: Principal = Depends(partner_principal)):
    await _require_partner_tenant(who.partner["id"], id)  # type: ignore[index]
    row = await db.system_fetchone(
        "SELECT * FROM webhook_endpoints WHERE id = %s AND org_id = %s", (endpoint_id, id)
    )
    if row is None:
        raise not_found("Không tìm thấy webhook")

    current_secret = webhooks._get_endpoint_secret(row)
    new_secret = secrets_crypto.new_webhook_secret()
    curr_kek_id = secrets_crypto.current_kek_id()
    ciphertext, _ = secrets_crypto.encrypt_secret(new_secret, curr_kek_id)
    prev_ciphertext, _ = secrets_crypto.encrypt_secret(current_secret, curr_kek_id)

    await db.system_execute(
        "UPDATE webhook_endpoints SET secret_version = secret_version + 1, "
        "prev_secret_ciphertext = %s, secret_ciphertext = %s, kek_id = %s, secret_scheme = 'kek' "
        "WHERE id = %s",
        (prev_ciphertext, ciphertext, curr_kek_id, endpoint_id),
    )
    return {"secret": new_secret}
