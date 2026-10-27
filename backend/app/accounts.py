"""Tổ chức, người dùng, phiên đăng nhập, thành viên và khoá API.

Mỗi người dùng thuộc đúng một tổ chức; email là duy nhất toàn hệ thống.
Vai trò: ``owner`` (một người, không xoá được), ``admin`` (quản lý khoá API,
webhook, thành viên), ``member`` (chỉ làm việc với tài liệu).
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone

from psycopg.errors import UniqueViolation

from . import config, db, mailer, plans, security
from .errors import ApiError, not_found

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$")
API_KEY_PREFIX = "wsk_live_"
INVITE_TTL = timedelta(days=7)
RESET_TTL = timedelta(hours=1)
ROLES = ("owner", "admin", "member")


def normalize_email(email: str) -> str:
    value = email.strip().lower()
    if not EMAIL_RE.match(value):
        raise ApiError(400, "invalid_email", "Email không hợp lệ")
    return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def user_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "pending": row["password_hash"] is None,
        "created_at": row["created_at"].isoformat(),
    }


def org_view(row: dict) -> dict:
    plan = plans.get(row["plan"])
    return {
        "id": row["id"],
        "name": row["name"],
        "plan": plan.to_dict(),
        "embed_origins": list(row.get("embed_origins") or []),
        "created_at": row["created_at"].isoformat(),
    }


# --------------------------------------------------------------------------
# Đăng ký, đăng nhập, phiên
# --------------------------------------------------------------------------


async def register(org_name: str, name: str, email: str, password: str) -> dict:
    email = normalize_email(email)
    security.check_password_strength(password)
    password_hash = await security.hash_password(password)
    org_id, user_id = security.new_id("org"), security.new_id("usr")
    try:
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO organizations (id, name) VALUES (%s, %s)",
                (org_id, org_name.strip()),
            )
            cur = await conn.execute(
                "INSERT INTO users (id, org_id, email, name, role, password_hash) "
                "VALUES (%s, %s, %s, %s, 'owner', %s) RETURNING *",
                (user_id, org_id, email, name.strip(), password_hash),
            )
            return await cur.fetchone()
    except UniqueViolation:
        raise ApiError(409, "email_taken", "Email này đã có tài khoản") from None


async def authenticate(email: str, password: str) -> dict | None:
    try:
        email = normalize_email(email)
    except ApiError:
        email = ""
    row = await db.fetchone("SELECT * FROM users WHERE lower(email) = %s", (email,))
    # Luôn băm một lần dù không có người dùng: thời gian phản hồi không lộ email.
    ok = await security.verify_password(password, row["password_hash"] if row else None)
    return row if ok else None


async def create_session(user_id: str, ip: str | None, user_agent: str | None) -> tuple[str, str]:
    """-> (token cookie, csrf token)."""
    token = security.random_token()
    csrf = security.random_token(24)
    await db.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (
            security.token_hash(token),
            user_id,
            csrf,
            _now() + timedelta(days=config.SESSION_TTL_DAYS),
            ip,
            (user_agent or "")[:300],
        ),
    )
    return token, csrf


async def session_context(token: str) -> dict | None:
    """Phiên còn hạn -> người dùng + tổ chức + csrf trong một truy vấn."""
    row = await db.fetchone(
        "SELECT s.csrf_token, s.expires_at, u.*, "
        "       o.name AS org_name, o.plan AS org_plan, o.created_at AS org_created_at, "
        "       o.embed_origins AS org_embed_origins "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "JOIN organizations o ON o.id = u.org_id "
        "WHERE s.token_hash = %s AND s.expires_at > now()",
        (security.token_hash(token),),
    )
    if row is None:
        return None
    # Gia hạn trượt khi còn dưới nửa thời hạn — ghi tối đa vài lần mỗi tuần.
    if row["expires_at"] - _now() < timedelta(days=config.SESSION_TTL_DAYS / 2):
        await db.execute(
            "UPDATE sessions SET expires_at = %s WHERE token_hash = %s",
            (_now() + timedelta(days=config.SESSION_TTL_DAYS), security.token_hash(token)),
        )
    return row


async def delete_session(token: str) -> None:
    await db.execute("DELETE FROM sessions WHERE token_hash = %s", (security.token_hash(token),))


async def change_password(user: dict, current: str, new: str, keep_session: str | None) -> None:
    if not await security.verify_password(current, user["password_hash"]):
        raise ApiError(400, "wrong_password", "Mật khẩu hiện tại không đúng")
    security.check_password_strength(new)
    password_hash = await security.hash_password(new)
    async with db.transaction() as conn:
        await conn.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, user["id"])
        )
        # Đổi mật khẩu là đá mọi phiên khác ra.
        await conn.execute(
            "DELETE FROM sessions WHERE user_id = %s AND token_hash <> %s",
            (user["id"], security.token_hash(keep_session or "")),
        )


# --------------------------------------------------------------------------
# Token một lần: lời mời thành viên, đặt lại mật khẩu
# --------------------------------------------------------------------------


async def issue_user_token(conn: db.Conn, user_id: str, purpose: str, ttl: timedelta) -> str:
    token = security.random_token()
    await conn.execute("DELETE FROM user_tokens WHERE user_id = %s AND purpose = %s", (user_id, purpose))
    await conn.execute(
        "INSERT INTO user_tokens (token_hash, user_id, purpose, expires_at) VALUES (%s, %s, %s, %s)",
        (security.token_hash(token), user_id, purpose, _now() + ttl),
    )
    return token


async def peek_user_token(token: str, purpose: str) -> dict:
    row = await db.fetchone(
        "SELECT u.*, o.name AS org_name FROM user_tokens t "
        "JOIN users u ON u.id = t.user_id JOIN organizations o ON o.id = u.org_id "
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
    async with db.transaction() as conn:
        user_id = await _consume_user_token(conn, token, "invite")
        cur = await conn.execute(
            "UPDATE users SET name = %s, password_hash = %s WHERE id = %s RETURNING *",
            (name.strip(), password_hash, user_id),
        )
        return await cur.fetchone()


async def request_password_reset(email: str, base_url: str) -> None:
    """Không báo email có tồn tại hay không — luôn trả về như nhau."""
    try:
        email = normalize_email(email)
    except ApiError:
        return
    row = await db.fetchone(
        "SELECT * FROM users WHERE lower(email) = %s AND password_hash IS NOT NULL", (email,)
    )
    if row is None or not mailer.enabled():
        return
    async with db.transaction() as conn:
        token = await issue_user_token(conn, row["id"], "reset", RESET_TTL)
        await mailer.enqueue(
            conn,
            row["email"],
            "Đặt lại mật khẩu Web Signer",
            f"Chào {row['name']},\n\n"
            f"Mở liên kết sau để đặt mật khẩu mới (hết hạn sau 1 giờ):\n"
            f"{base_url}/#/reset?t={token}\n\n"
            "Nếu bạn không yêu cầu, hãy bỏ qua email này.",
        )


async def reset_password(token: str, password: str) -> None:
    security.check_password_strength(password)
    password_hash = await security.hash_password(password)
    async with db.transaction() as conn:
        user_id = await _consume_user_token(conn, token, "reset")
        await conn.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, user_id)
        )
        await conn.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))


# --------------------------------------------------------------------------
# Tổ chức và thành viên
# --------------------------------------------------------------------------


async def get_org(org_id: str) -> dict:
    row = await db.fetchone("SELECT * FROM organizations WHERE id = %s", (org_id,))
    if row is None:
        raise not_found("Không tìm thấy tổ chức")
    return row


def normalize_embed_origin(value: str) -> str:
    """``https://erp.doitac.vn[:port]`` — đúng một origin, không đường dẫn, không ký tự đại diện."""
    from urllib.parse import urlsplit

    from .config import WEBHOOK_ALLOW_PRIVATE

    origin = value.strip().rstrip("/")
    parts = urlsplit(origin)
    allowed = ("https", "http") if WEBHOOK_ALLOW_PRIVATE else ("https",)
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


async def update_org(org_id: str, name: str | None, embed_origins: list[str] | None) -> dict:
    changes: dict = {}
    if name is not None:
        changes["name"] = name.strip()
    if embed_origins is not None:
        if len(embed_origins) > 10:
            raise ApiError(400, "invalid_origin", "Tối đa 10 origin được nhúng")
        changes["embed_origins"] = sorted({normalize_embed_origin(o) for o in embed_origins})
    if not changes:
        return await get_org(org_id)
    assignments = ", ".join(f"{column} = %s" for column in changes)
    row = await db.fetchone(
        f"UPDATE organizations SET {assignments} WHERE id = %s RETURNING *", (*changes.values(), org_id)
    )
    if row is None:
        raise not_found("Không tìm thấy tổ chức")
    return row


async def list_members(org_id: str) -> list[dict]:
    rows = await db.fetchall(
        "SELECT * FROM users WHERE org_id = %s ORDER BY created_at", (org_id,)
    )
    return [user_view(r) for r in rows]


async def invite_member(
    org: dict, inviter: dict, email: str, name: str, role: str, base_url: str
) -> tuple[dict, str]:
    """-> (thành viên, liên kết nhận lời mời). Liên kết cũng được gửi email nếu có SMTP."""
    if role not in ("admin", "member"):
        raise ApiError(400, "invalid_role", "Vai trò phải là admin hoặc member")
    email = normalize_email(email)
    plan = plans.get(org["plan"])
    try:
        async with db.transaction() as conn:
            if plan.max_members is not None:
                cur = await conn.execute(
                    "SELECT count(*) AS n FROM users WHERE org_id = %s", (org["id"],)
                )
                if (await cur.fetchone())["n"] >= plan.max_members:
                    raise ApiError(
                        402, "quota_exceeded", f"Gói {plan.name} tối đa {plan.max_members} thành viên"
                    )
            cur = await conn.execute(
                "INSERT INTO users (id, org_id, email, name, role) VALUES (%s, %s, %s, %s, %s) "
                "RETURNING *",
                (security.new_id("usr"), org["id"], email, name.strip(), role),
            )
            user = await cur.fetchone()
            token = await issue_user_token(conn, user["id"], "invite", INVITE_TTL)
            link = f"{base_url}/#/invite?t={token}"
            await mailer.enqueue(
                conn,
                email,
                f"{inviter['name']} mời bạn tham gia {org['name']} trên Web Signer",
                f"Chào {user['name']},\n\n{inviter['name']} mời bạn tham gia tổ chức "
                f"{org['name']}.\nĐặt mật khẩu để bắt đầu (liên kết hết hạn sau 7 ngày):\n"
                f"{link}\n",
            )
    except UniqueViolation:
        raise ApiError(409, "email_taken", "Email này đã có tài khoản") from None
    return user_view(user), link


async def _member(org_id: str, user_id: str) -> dict:
    row = await db.fetchone(
        "SELECT * FROM users WHERE id = %s AND org_id = %s", (user_id, org_id)
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
    row = await db.fetchone(
        "UPDATE users SET role = %s WHERE id = %s RETURNING *", (role, user_id)
    )
    return user_view(row)


async def remove_member(org_id: str, user_id: str) -> None:
    member = await _member(org_id, user_id)
    if member["role"] == "owner":
        raise ApiError(409, "owner_locked", "Không xoá được chủ tổ chức")
    await db.execute("DELETE FROM users WHERE id = %s", (user_id,))


# --------------------------------------------------------------------------
# Khoá API
# --------------------------------------------------------------------------


def api_key_view(row: dict) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "prefix": row["prefix"],
        "created_at": row["created_at"].isoformat(),
        "last_used_at": row["last_used_at"].isoformat() if row["last_used_at"] else None,
        "revoked_at": row["revoked_at"].isoformat() if row["revoked_at"] else None,
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
    row = await db.fetchone(
        "SELECT k.id AS key_id, k.last_used_at, o.id AS org_id, o.name AS org_name, "
        "       o.plan AS org_plan, o.created_at AS org_created_at, "
        "       o.embed_origins AS org_embed_origins "
        "FROM api_keys k JOIN organizations o ON o.id = k.org_id "
        "WHERE k.key_hash = %s AND k.revoked_at IS NULL",
        (security.token_hash(secret),),
    )
    if row is None:
        return None
    last = row["last_used_at"]
    # Ghi "lần dùng cuối" tối đa mỗi phút một lần, không phải mỗi request.
    if last is None or _now() - last > timedelta(minutes=1):
        await db.execute("UPDATE api_keys SET last_used_at = now() WHERE id = %s", (row["key_id"],))
    return row


def constant_time_equal(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode(), b.encode())
