"""Tổ chức, người dùng, phiên đăng nhập, thành viên (memberships) và khoá API.

Mỗi người dùng (users) là một danh tính toàn hệ thống (email duy nhất).
Một người dùng có thể tham gia nhiều tổ chức qua bảng memberships (user_id, org_id, role).
Phiên đăng nhập (sessions) lưu tổ chức đang kích hoạt (active org).
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from . import config, db, mailer, plans, secrets_crypto, security
from .errors import ApiError, not_found

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$")
API_KEY_PREFIX = "wsk_live_"
INVITE_TTL = timedelta(days=7)
RESET_TTL = timedelta(hours=1)
ROLES = ("owner", "admin", "member")

logger = logging.getLogger("websigner.accounts")


def normalize_email(email: str) -> str:
    value = email.strip().lower()
    if not EMAIL_RE.match(value):
        raise ApiError(400, "invalid_email", "Email không hợp lệ")
    return value


def normalize_embed_origin(value: str) -> str:
    """``https://erp.doitac.vn[:port]`` — đúng một origin, không đường dẫn, không ký tự đại diện."""
    origin = value.strip().rstrip("/")
    parts = urlsplit(origin)
    allowed = ("https", "http") if config.WEBHOOK_ALLOW_PRIVATE else ("https",)
    if (
        parts.scheme not in allowed
        or not parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
        or "*" in origin
        or " " in origin
    ):
        raise ApiError(400, "invalid_origin", f"Origin không hợp lệ: {value!r} — dạng https://ten-mien.vn")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def user_view(row: dict) -> dict:
    created = row["created_at"]
    created_str = created.isoformat() if isinstance(created, datetime) else str(created)
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "pending": row.get("password_hash") is None,
        "created_at": created_str,
    }


def org_view(row: dict) -> dict:
    plan = plans.get(row["plan"])
    created = row["created_at"]
    created_str = created.isoformat() if isinstance(created, datetime) else str(created)
    embed_origins = list(row.get("embed_origins") or [])
    settings = dict(row.get("settings") or {})
    if "embed_origins" not in settings:
        settings["embed_origins"] = embed_origins
    return {
        "id": row["id"],
        "name": row["name"],
        "plan": plan.to_dict(),
        "embed_origins": embed_origins,
        "settings": settings,
        "created_at": created_str,
    }


# --------------------------------------------------------------------------
# Đăng ký, đăng nhập, phiên
# --------------------------------------------------------------------------


async def register(org_name: str, name: str, email: str, password: str) -> dict:
    email = normalize_email(email)
    security.check_password_strength(password)
    password_hash = await security.hash_password(password)
    org_id, user_id = security.new_id("org"), security.new_id("usr")

    signing_key = secrets_crypto.new_signing_key()
    key_ciphertext, kek_id = secrets_crypto.encrypt_secret(signing_key)

    try:
        async with db.system_transaction() as conn:
            existing_user = await conn.execute("SELECT 1 FROM users WHERE lower(email) = %s", (email,))
            if await existing_user.fetchone():
                raise ApiError(409, "email_taken", "Email này đã có tài khoản")

            await conn.execute(
                "INSERT INTO organizations (id, name, signing_key_ciphertext, signing_key_kek_id, signing_key_scheme) "
                "VALUES (%s, %s, %s, %s, 'kek')",
                (org_id, org_name.strip(), key_ciphertext, kek_id),
            )

            cur = await conn.execute(
                "INSERT INTO users (id, email, name, password_hash) "
                "VALUES (%s, %s, %s, %s) RETURNING *",
                (user_id, email, name.strip(), password_hash),
            )
            user_row = await cur.fetchone()

            await conn.execute(
                "INSERT INTO memberships (user_id, org_id, role) VALUES (%s, %s, 'owner')",
                (user_id, org_id),
            )
            return {**dict(user_row), "org_id": org_id, "role": "owner"}
    except UniqueViolation:
        raise ApiError(409, "email_taken", "Email này đã có tài khoản") from None

async def authenticate(email: str, password: str) -> dict | None:
    try:
        email = normalize_email(email)
    except ApiError:
        email = ""
    row = await db.system_fetchone("SELECT * FROM users WHERE lower(email) = %s", (email,))
    ok = await security.verify_password(password, row["password_hash"] if row else None)
    if not ok or not row:
        return None

    m = await db.system_fetchone(
        "SELECT org_id, role FROM memberships WHERE user_id = %s ORDER BY created_at LIMIT 1",
        (row["id"],),
    )
    if not m:
        raise ApiError(403, "no_organization", "Tài khoản không thuộc tổ chức nào")
    res = dict(row)
    res["org_id"] = m["org_id"]
    res["role"] = m["role"]
    return res


async def create_session(
    user_id: str, ip: str | None, user_agent: str | None, org_id: str | None = None
) -> tuple[str, str]:
    """-> (token cookie, csrf token)."""
    if not org_id:
        m = await db.system_fetchone(
            "SELECT org_id FROM memberships WHERE user_id = %s ORDER BY created_at LIMIT 1",
            (user_id,),
        )
        if not m:
            raise ApiError(403, "no_organization", "Tài khoản không thuộc tổ chức nào")
        org_id = m["org_id"]

    token = security.random_token()
    csrf = security.random_token(24)
    await db.system_execute(
        "INSERT INTO sessions (token_hash, user_id, org_id, csrf_token, expires_at, ip, user_agent) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (
            security.token_hash(token),
            user_id,
            org_id,
            csrf,
            _now() + timedelta(days=config.SESSION_TTL_DAYS),
            ip,
            (user_agent or "")[:300],
        ),
    )
    return token, csrf


async def session_context(token: str) -> dict | None:
    """Phiên còn hạn -> người dùng + tổ chức + csrf trong một truy vấn (system path)."""
    row = await db.system_fetchone(
        "SELECT s.csrf_token, s.expires_at, s.org_id, "
        "       u.id, u.email, u.name, u.password_hash, u.created_at, "
        "       m.role, "
        "       o.name AS org_name, o.plan AS org_plan, o.created_at AS org_created_at, "
        "       o.embed_origins AS org_embed_origins, o.settings AS org_settings, "
        "       o.signing_key_ciphertext AS org_signing_key_ciphertext, "
        "       o.signing_key_kek_id AS org_signing_key_kek_id, "
        "       o.signing_key_scheme AS org_signing_key_scheme "
        "FROM sessions s "
        "JOIN users u ON u.id = s.user_id "
        "JOIN memberships m ON m.user_id = s.user_id AND m.org_id = s.org_id "
        "JOIN organizations o ON o.id = s.org_id "
        "WHERE s.token_hash = %s AND s.expires_at > now()",
        (security.token_hash(token),),
    )
    if row is None:
        return None
    if row["expires_at"] - _now() < timedelta(days=config.SESSION_TTL_DAYS / 2):
        await db.system_execute(
            "UPDATE sessions SET expires_at = %s WHERE token_hash = %s",
            (_now() + timedelta(days=config.SESSION_TTL_DAYS), security.token_hash(token)),
        )
    return row


async def delete_session(token: str) -> None:
    await db.system_execute("DELETE FROM sessions WHERE token_hash = %s", (security.token_hash(token),))


async def change_password(user: dict, current: str, new: str, keep_session: str | None) -> None:
    if not await security.verify_password(current, user["password_hash"]):
        raise ApiError(400, "wrong_password", "Mật khẩu hiện tại không đúng")
    security.check_password_strength(new)
    password_hash = await security.hash_password(new)
    async with db.system_transaction() as conn:
        await conn.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, user["id"])
        )
        await conn.execute(
            "DELETE FROM sessions WHERE user_id = %s AND token_hash <> %s",
            (user["id"], security.token_hash(keep_session or "")),
        )


async def issue_user_token(conn: db.Conn, user_id: str, purpose: str, ttl: timedelta) -> str:
    token = security.random_token()
    await db.system_execute("DELETE FROM user_tokens WHERE user_id = %s AND purpose = %s", (user_id, purpose))
    await db.system_execute(
        "INSERT INTO user_tokens (token_hash, user_id, purpose, expires_at) VALUES (%s, %s, %s, %s)",
        (security.token_hash(token), user_id, purpose, _now() + ttl),
    )
    return token


async def peek_user_token(token: str, purpose: str) -> dict:
    row = await db.system_fetchone(
        "SELECT u.*, COALESCE(o.name, '') AS org_name FROM user_tokens t "
        "JOIN users u ON u.id = t.user_id "
        "LEFT JOIN memberships m ON m.user_id = u.id "
        "LEFT JOIN organizations o ON o.id = m.org_id "
        "WHERE t.token_hash = %s AND t.purpose = %s AND t.expires_at > now()",
        (security.token_hash(token), purpose),
    )
    if row is None:
        raise ApiError(400, "invalid_token", "Liên kết đã hết hạn hoặc đã được dùng")
    return row


async def _consume_user_token(conn: db.Conn, token: str, purpose: str) -> str:
    cur = await conn.execute(
        "DELETE FROM user_tokens WHERE token_hash = %s AND purpose = %s AND expires_at > now() "
        "RETURNING user_id",
        (security.token_hash(token), purpose),
    )
    row = await cur.fetchone()
    if row is None:
        raise ApiError(400, "invalid_token", "Liên kết đã hết hạn hoặc đã được dùng")
    return row["user_id"]


async def accept_invite(token: str, name: str, password: str) -> dict:
    security.check_password_strength(password)
    password_hash = await security.hash_password(password)
    async with db.system_transaction() as conn:
        user_id = await _consume_user_token(conn, token, "invite")
        cur = await conn.execute(
            "UPDATE users SET name = %s, password_hash = %s WHERE id = %s RETURNING *",
            (name.strip(), password_hash, user_id),
        )
        user = await cur.fetchone()
        m = await conn.execute(
            "SELECT org_id, role FROM memberships WHERE user_id = %s ORDER BY created_at LIMIT 1",
            (user_id,),
        )
        mrow = await m.fetchone()
        if not mrow:
            raise ApiError(403, "no_organization", "Tài khoản không thuộc tổ chức nào")
        res = dict(user)
        res["org_id"] = mrow["org_id"]
        res["role"] = mrow["role"]
        return res


async def request_password_reset(email: str, base_url: str) -> None:
    try:
        email = normalize_email(email)
    except ApiError:
        return
    row = await db.system_fetchone(
        "SELECT * FROM users WHERE lower(email) = %s AND password_hash IS NOT NULL", (email,)
    )
    if row is None or not mailer.enabled():
        return
    async with db.system_transaction() as conn:
        token = await issue_user_token(conn, row["id"], "reset", RESET_TTL)
        await mailer.enqueue(
            conn,
            row["email"],
            "Đặt lại mật khẩu Web Signer",
            f"Chào {row['name']},\n\nBạn (hoặc ai đó) vừa yêu cầu đặt lại mật khẩu cho tài khoản này.\n"
            f"Bấm vào liên kết sau để đặt mật khẩu mới (hết hạn sau 1 giờ):\n"
            f"{base_url}/#/reset?t={token}\n\nNếu không phải bạn yêu cầu, hãy bỏ qua email này.\n",
        )


async def reset_password(token: str, password: str) -> None:
    security.check_password_strength(password)
    password_hash = await security.hash_password(password)
    async with db.system_transaction() as conn:
        user_id = await _consume_user_token(conn, token, "reset")
        await conn.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, user_id)
        )
        await conn.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))


# --------------------------------------------------------------------------
# Tổ chức & thành viên
# --------------------------------------------------------------------------


async def get_org(org_id: str) -> dict:
    row = await db.fetchone("SELECT * FROM organizations WHERE id = %s", (org_id,), org_id=org_id)
    if row is None:
        raise not_found("Không tìm thấy tổ chức")
    return row


async def update_org(
    org_id: str,
    name: str | None,
    embed_origins: list[str] | None,
    settings: dict | None = None,
) -> dict:
    changes: dict[str, Any] = {}
    if name is not None:
        changes["name"] = name.strip()

    current = await get_org(org_id)
    current_settings = dict(current.get("settings") or {})

    if embed_origins is not None:
        if len(embed_origins) > 10:
            raise ApiError(400, "invalid_origin", "Tối đa 10 origin được nhúng")
        origins = sorted({normalize_embed_origin(o) for o in embed_origins})
        changes["embed_origins"] = origins
        current_settings["embed_origins"] = origins
        changes["settings"] = Jsonb(current_settings)

    if settings is not None:
        merged = {**current_settings, **settings}
        if "embed_origins" in settings and isinstance(settings["embed_origins"], list):
            origins = sorted({normalize_embed_origin(o) for o in settings["embed_origins"]})
            changes["embed_origins"] = origins
            merged["embed_origins"] = origins
        changes["settings"] = Jsonb(merged)

    if not changes:
        return current

    assignments = ", ".join(f"{column} = %s" for column in changes)
    row = await db.fetchone(
        f"UPDATE organizations SET {assignments} WHERE id = %s RETURNING *",
        (*changes.values(), org_id),
        org_id=org_id,
    )
    if row is None:
        raise not_found("Không tìm thấy tổ chức")
    return row


async def list_members(org_id: str) -> list[dict]:
    rows = await db.fetchall(
        "SELECT u.id, u.email, u.name, u.password_hash, m.role, m.created_at "
        "FROM memberships m JOIN users u ON u.id = m.user_id "
        "WHERE m.org_id = %s ORDER BY m.created_at",
        (org_id,),
    )
    return [user_view(r) for r in rows]


async def invite_member(
    org: dict, inviter: dict, email: str, name: str, role: str, base_url: str
) -> tuple[dict, str | None]:
    """-> (thành viên, liên kết nhận lời mời nếu chưa có tài khoản)."""
    if role not in ("admin", "member"):
        raise ApiError(400, "invalid_role", "Vai trò phải là admin hoặc member")
    email = normalize_email(email)
    plan = plans.get(org["plan"])

    async with db.transaction() as conn:
        if plan.max_members is not None:
            cur = await conn.execute(
                "SELECT count(*) AS n FROM memberships WHERE org_id = %s", (org["id"],)
            )
            if (await cur.fetchone())["n"] >= plan.max_members:
                raise ApiError(
                    402, "quota_exceeded", f"Gói {plan.name} tối đa {plan.max_members} thành viên"
                )

        user_row = await db.system_fetchone("SELECT * FROM users WHERE lower(email) = %s", (email,))
        if user_row:
            user_id = user_row["id"]
            cur = await conn.execute(
                "SELECT 1 FROM memberships WHERE user_id = %s AND org_id = %s", (user_id, org["id"])
            )
            if await cur.fetchone():
                raise ApiError(409, "already_member", "Người dùng này đã là thành viên của tổ chức")

            await conn.execute(
                "INSERT INTO memberships (user_id, org_id, role) VALUES (%s, %s, %s)",
                (user_id, org["id"], role),
            )
            member = {**dict(user_row), "role": role, "created_at": _now()}
            if user_row["password_hash"] is not None:
                # Đã có tài khoản: gửi email thông báo trực tiếp
                link = f"{base_url}/#/login"
                await mailer.enqueue(
                    conn,
                    email,
                    f"{inviter['name']} đã thêm bạn vào {org['name']} trên Web Signer",
                    f"Chào {user_row['name']},\n\n{inviter['name']} vừa thêm bạn vào tổ chức {org['name']}.\n"
                    f"Đăng nhập để xem: {link}\n",
                )
                return user_view(member), None
            else:
                # Chưa kích hoạt mật khẩu nhưng danh tính đã tồn tại: không cấp liên kết kích hoạt
                # cho admin tổ chức này để tránh chiếm đoạt tài khoản (Finding #3).
                await mailer.enqueue(
                    conn,
                    org["id"],
                    email,
                    f"{inviter['name']} mời bạn tham gia {org['name']} trên Web Signer",
                    f"Chào {user_row['name']},\n\n{inviter['name']} mời bạn tham gia tổ chức {org['name']}.\n"
                    f"Vui lòng kích hoạt tài khoản qua thư mời ban đầu đã gửi tới bạn.\n",
                )
                return user_view(member), None
        else:
            user_id = security.new_id("usr")
            new_user = await db.system_fetchone(
                "INSERT INTO users (id, email, name, password_hash) VALUES (%s, %s, %s, NULL) RETURNING *",
                (user_id, email, name.strip()),
            )
            await conn.execute(
                "INSERT INTO memberships (user_id, org_id, role) VALUES (%s, %s, %s)",
                (user_id, org["id"], role),
            )
            token = await issue_user_token(conn, user_id, "invite", INVITE_TTL)
            link = f"{base_url}/#/invite?t={token}"
            await mailer.enqueue(
                conn,
                email,
                f"{inviter['name']} mời bạn tham gia {org['name']} trên Web Signer",
                f"Chào {new_user['name']},\n\n{inviter['name']} mời bạn tham gia tổ chức "
                f"{org['name']}.\nĐặt mật khẩu để bắt đầu (liên kết hết hạn sau 7 ngày):\n"
                f"{link}\n",
            )
            member = {**dict(new_user), "role": role}
            return user_view(member), link


async def _member(org_id: str, user_id: str) -> dict:
    row = await db.fetchone(
        "SELECT u.id, u.email, u.name, u.password_hash, m.role, m.created_at "
        "FROM memberships m JOIN users u ON u.id = m.user_id "
        "WHERE m.user_id = %s AND m.org_id = %s",
        (user_id, org_id),
    )
    if row is None:
        raise not_found("Không tìm thấy thành viên")
    return row


async def update_member_role(org_id: str, user_id: str, role: str) -> dict:
    if role not in ("admin", "member"):
        raise ApiError(400, "invalid_role", "Vai trò phải là admin hoặc member")
    member = await _member(org_id, user_id)
    if member["role"] == "owner":
        raise ApiError(409, "owner_locked", "Không đổi được vai trò của chủ tổ chức")
    await db.execute(
        "UPDATE memberships SET role = %s WHERE user_id = %s AND org_id = %s",
        (role, user_id, org_id),
    )
    return await _member(org_id, user_id)


async def remove_member(org_id: str, user_id: str) -> None:
    member = await _member(org_id, user_id)
    if member["role"] == "owner":
        raise ApiError(409, "owner_locked", "Không xoá được chủ tổ chức")
    await db.execute("DELETE FROM memberships WHERE user_id = %s AND org_id = %s", (user_id, org_id))


async def list_user_orgs(user_id: str, active_org_id: str) -> list[dict]:
    """Danh sách mọi tổ chức của người dùng hiện tại."""
    rows = await db.system_fetchall(
        "SELECT o.id, o.name, o.plan, m.role, (o.id = %s) AS active, o.created_at "
        "FROM memberships m JOIN organizations o ON o.id = m.org_id "
        "WHERE m.user_id = %s ORDER BY m.created_at",
        (active_org_id, user_id),
    )
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "plan": r["plan"],
            "role": r["role"],
            "active": bool(r["active"]),
            "created_at": r["created_at"].isoformat() if isinstance(r["created_at"], datetime) else str(r["created_at"]),
        }
        for r in rows
    ]


async def switch_org(user_id: str, session_token: str, new_org_id: str) -> dict:
    """Chuyển tổ chức đang hoạt động của phiên đăng nhập."""
    m = await db.system_fetchone(
        "SELECT m.role, o.id, o.name, o.plan "
        "FROM memberships m JOIN organizations o ON o.id = m.org_id "
        "WHERE m.user_id = %s AND m.org_id = %s",
        (user_id, new_org_id),
    )
    if m is None:
        raise ApiError(403, "not_member", "Bạn không thuộc tổ chức này")

    await db.system_execute(
        "UPDATE sessions SET org_id = %s WHERE token_hash = %s",
        (new_org_id, security.token_hash(session_token)),
    )
    return {
        "id": m["id"],
        "name": m["name"],
        "plan": m["plan"],
        "role": m["role"],
    }


# --------------------------------------------------------------------------
# Khoá API
# --------------------------------------------------------------------------


def api_key_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "prefix": row["prefix"],
        "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"]),
        "last_used_at": row["last_used_at"].isoformat() if row.get("last_used_at") else None,
        "revoked_at": row["revoked_at"].isoformat() if row.get("revoked_at") else None,
    }


async def create_api_key(org: dict, name: str, user_id: str | None) -> tuple[dict, str]:
    """-> (khoá, bản rõ). Bản rõ chỉ trả về đúng một lần này."""
    plan = plans.get(org["plan"])
    secret = API_KEY_PREFIX + security.random_token()
    async with db.transaction() as conn:
        cur = await conn.execute(
            "SELECT count(*) AS n FROM api_keys WHERE org_id = %s AND revoked_at IS NULL",
            (org["id"],),
        )
        if (await cur.fetchone())["n"] >= plan.max_api_keys:
            raise ApiError(
                402, "quota_exceeded", f"Gói {plan.name} tối đa {plan.max_api_keys} khoá API"
            )
        cur = await conn.execute(
            "INSERT INTO api_keys (id, org_id, name, prefix, key_hash, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
            (
                security.new_id("key"),
                org["id"],
                name.strip(),
                secret[: len(API_KEY_PREFIX) + 6],
                security.token_hash(secret),
                user_id,
            ),
        )
        return api_key_view(await cur.fetchone()), secret


async def list_api_keys(org_id: str) -> list[dict]:
    rows = await db.fetchall(
        "SELECT * FROM api_keys WHERE org_id = %s ORDER BY created_at DESC", (org_id,)
    )
    return [api_key_view(r) for r in rows]


async def revoke_api_key(org_id: str, key_id: str) -> None:
    count = await db.execute(
        "UPDATE api_keys SET revoked_at = now() WHERE id = %s AND org_id = %s AND revoked_at IS NULL",
        (key_id, org_id),
    )
    if not count:
        raise not_found("Không tìm thấy khoá API")


async def api_key_context(secret: str) -> dict | None:
    if not secret.startswith(API_KEY_PREFIX):
        return None
    row = await db.system_fetchone(
        "SELECT k.id AS key_id, k.last_used_at, o.id AS org_id, o.name AS org_name, "
        "       o.plan AS org_plan, o.created_at AS org_created_at, "
        "       o.embed_origins AS org_embed_origins, o.settings AS org_settings, "
        "       o.signing_key_ciphertext AS org_signing_key_ciphertext, "
        "       o.signing_key_kek_id AS org_signing_key_kek_id, "
        "       o.signing_key_scheme AS org_signing_key_scheme "
        "FROM api_keys k JOIN organizations o ON o.id = k.org_id "
        "WHERE k.key_hash = %s AND k.revoked_at IS NULL",
        (security.token_hash(secret),),
    )
    if row is None:
        return None
    last = row["last_used_at"]
    if last is None or _now() - last > timedelta(minutes=1):
        await db.system_execute("UPDATE api_keys SET last_used_at = now() WHERE id = %s", (row["key_id"],))
    return row


def constant_time_equal(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode(), b.encode())
