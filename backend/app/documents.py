"""Tài liệu, người nhận và luồng ký — phần nghiệp vụ trung tâm của nền tảng.

Vòng đời::

    draft ──send──▶ in_progress ──(mọi người nhận xong)──▶ completed
      │                 ├──(một người từ chối)──────────▶ declined
      └──void──▶ voided ◀┤
                        └──(quá hạn)────────────────────▶ expired

Người nhận có ``routing_order``: nhóm số nhỏ nhất còn người chưa xong là nhóm
đang tới lượt; cùng số thì ký song song. Mọi chuyển trạng thái ghi nhật ký
kiểm toán, xếp webhook và email **trong cùng một transaction**.

Danh tính người ký là chứng thư số: khai MST thì MST trên chứng thư phải khớp,
không khai thì so tên đã bỏ dấu.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, field_validator, model_validator

from . import audit, db, mailer, plans, security, signing, storage, trust, verify, webhooks
from .auth import Principal
from .errors import ApiError, bad_request, conflict, not_found

TERMINAL = frozenset({"completed", "declined", "voided", "expired"})
STATUS_LABELS = {
    "draft": "Nháp",
    "in_progress": "Đang ký",
    "completed": "Hoàn tất",
    "declined": "Bị từ chối",
    "voided": "Đã huỷ",
    "expired": "Hết hạn",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def normalize_name(value: str) -> str:
    """Bỏ dấu, gộp khoảng trắng, viết hoa — để so tên người ký nới tay hơn."""
    stripped = unicodedata.normalize("NFD", value.replace("đ", "d").replace("Đ", "D"))
    ascii_only = "".join(c for c in stripped if unicodedata.category(c) != "Mn")
    return " ".join(ascii_only.split()).upper()


def identity_matches(recipient: dict, cert_cn: str, cert_tax_code: str | None) -> bool:
    """Chứng thư này có đúng là người được mời không.

    MST là định danh pháp lý nên khi khai báo thì nó quyết định. Không khai MST
    thì so tên đã bỏ dấu.
    """
    if recipient["tax_code"]:
        return bool(cert_tax_code) and cert_tax_code.strip() == recipient["tax_code"]
    return normalize_name(cert_cn) == normalize_name(recipient["name"])


# --------------------------------------------------------------------------
# Đầu vào
# --------------------------------------------------------------------------


class FieldSpec(BaseModel):
    """Ô ký đặt sẵn. Toạ độ điểm PDF, gốc dưới-trái; ``page`` đếm từ 0."""

    page: int = Field(ge=0, le=9999)
    box: tuple[float, float, float, float]

    @model_validator(mode="after")
    def _sane(self) -> "FieldSpec":
        x1, y1, x2, y2 = self.box
        if min(self.box) < 0 or max(self.box) > 20000:
            raise ValueError("toạ độ ô ký nằm ngoài trang")
        if not (40 <= x2 - x1 <= 1200 and 20 <= y2 - y1 <= 800):
            raise ValueError("ô ký phải rộng 40–1200pt và cao 20–800pt, x2>x1, y2>y1")
        return self


class RecipientSpec(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str | None = Field(default=None, max_length=254)
    tax_code: str | None = Field(default=None, max_length=20, pattern=r"^[0-9A-Za-z-]*$")
    role: Literal["signer", "approver"] = "signer"
    order: int | None = Field(default=None, ge=1, le=100)
    field: FieldSpec | None = None

    @field_validator("email")
    @classmethod
    def _email(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        from .accounts import normalize_email

        try:
            return normalize_email(value)
        except ApiError as exc:
            raise ValueError(exc.message) from None

    @model_validator(mode="after")
    def _role_field(self) -> "RecipientSpec":
        if self.role == "approver" and self.field is not None:
            raise ValueError("người duyệt không có ô ký")
        self.name = self.name.strip()
        self.tax_code = (self.tax_code or "").strip() or None
        return self


def _check_metadata(value: dict[str, str]) -> dict[str, str]:
    if len(value) > 50:
        raise ValueError("metadata tối đa 50 khoá")
    for key, item in value.items():
        if not 1 <= len(key) <= 40 or len(item) > 500:
            raise ValueError("khoá metadata 1–40 ký tự, giá trị tối đa 500 ký tự")
    return value


class DocumentSpec(BaseModel):
    title: str | None = Field(default=None, max_length=300)
    message: str | None = Field(default=None, max_length=2000)
    external_ref: str | None = Field(default=None, max_length=200)
    metadata: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime | None = None
    expires_in_days: int | None = Field(default=None, ge=1, le=365)
    recipients: list[RecipientSpec] = Field(default_factory=list)
    send: bool = False

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, str]) -> dict[str, str]:
        return _check_metadata(value)

    def resolved_expiry(self) -> datetime | None:
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise bad_request("invalid_expiry", "expires_at phải kèm múi giờ")
            return self.expires_at
        if self.expires_in_days is not None:
            return _now() + timedelta(days=self.expires_in_days)
        return None


class DocumentPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    message: str | None = Field(default=None, max_length=2000)
    external_ref: str | None = Field(default=None, max_length=200)
    metadata: dict[str, str] | None = None
    expires_at: datetime | None = None

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return value if value is None else _check_metadata(value)


# --------------------------------------------------------------------------
# Hiển thị
# --------------------------------------------------------------------------


def recipient_view(row: dict, doc: dict, *, org_view: bool, base_url: str | None) -> dict:
    view: dict[str, Any] = {
        "id": row["id"],
        "role": row["role"],
        "order": row["routing_order"],
        "name": row["name"],
        "tax_code": row["tax_code"],
        "field": (
            {"page": row["field_page"], "box": list(row["field_box"])}
            if row["field_page"] is not None
            else None
        ),
        "status": row["status"],
        "viewed_at": _iso(row["viewed_at"]),
        "acted_at": _iso(row["acted_at"]),
        "decline_reason": row["decline_reason"],
        "signature": (
            {
                "signer": row["signed_by"],
                "tax_code": row["signer_tax_code"],
                "cert_serial": row["cert_serial"],
                "cert_issuer": row["cert_issuer"],
                "field_name": row["sig_field"],
                "page": row["sig_page"],
                "profile": row["sig_profile"],
                "revision": row["sig_revision"],
            }
            if row["status"] == "signed"
            else None
        ),
    }
    if org_view:
        view["email"] = row["email"]
        view["notified_at"] = _iso(row["notified_at"])
        if base_url and row["status"] == "pending" and doc["status"] not in TERMINAL:
            view["signing_url"] = signing_url(base_url, row)
    return view


def document_view(
    doc: dict, recipients: list[dict], *, org_view: bool = True, base_url: str | None = None
) -> dict:
    view: dict[str, Any] = {
        "id": doc["id"],
        "title": doc["title"],
        "filename": doc["filename"],
        "status": doc["status"],
        "revision": doc["revision"],
        "page_count": doc["page_count"],
        "message": doc["message"],
        "created_at": _iso(doc["created_at"]),
        "updated_at": _iso(doc["updated_at"]),
        "sent_at": _iso(doc["sent_at"]),
        "completed_at": _iso(doc["completed_at"]),
        "expires_at": _iso(doc["expires_at"]),
        "void_reason": doc["void_reason"],
        "recipients": [
            recipient_view(r, doc, org_view=org_view, base_url=base_url) for r in recipients
        ],
    }
    if org_view:
        view["external_ref"] = doc["external_ref"]
        view["metadata"] = doc["metadata"]
    else:
        view["organization"] = doc.get("org_name")
    return view


def signing_url(base_url: str, recipient: dict) -> str:
    return f"{base_url}/s/{security.recipient_token(recipient['id'], recipient['token_version'])}"


# --------------------------------------------------------------------------
# Truy vấn
# --------------------------------------------------------------------------

_DOC_SELECT = (
    "SELECT d.*, o.name AS org_name, u.email AS creator_email, u.name AS creator_name "
    "FROM documents d JOIN organizations o ON o.id = d.org_id "
    "LEFT JOIN users u ON u.id = d.created_by_user "
)


async def load(org_id: str, doc_id: str, *, conn: db.Conn | None = None) -> dict:
    """404 cả khi không tồn tại lẫn khi thuộc tổ chức khác — không lộ sự tồn tại."""
    if not storage.DOC_ID_RE.match(doc_id):
        raise not_found("Không tìm thấy tài liệu")
    row = await db.fetchone(
        _DOC_SELECT + "WHERE d.id = %s AND d.org_id = %s", (doc_id, org_id), conn=conn
    )
    if row is None:
        raise not_found("Không tìm thấy tài liệu")
    return row


async def _load_by_id(conn: db.Conn, doc_id: str) -> dict:
    row = await db.fetchone(_DOC_SELECT + "WHERE d.id = %s", (doc_id,), conn=conn)
    if row is None:
        raise not_found("Không tìm thấy tài liệu")
    return row


async def load_recipients(doc_id: str, *, conn: db.Conn | None = None) -> list[dict]:
    return await db.fetchall(
        "SELECT * FROM recipients WHERE document_id = %s ORDER BY position", (doc_id,), conn=conn
    )


async def get_view(principal: Principal, doc_id: str, base_url: str) -> dict:
    doc = await load(principal.org_id, doc_id)
    return document_view(doc, await load_recipients(doc_id), base_url=base_url)


def _encode_cursor(row: dict) -> str:
    raw = f"{row['created_at'].isoformat()}|{row['id']}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        created, doc_id = base64.urlsafe_b64decode(padded).decode().split("|", 1)
        return datetime.fromisoformat(created), doc_id
    except (ValueError, UnicodeDecodeError):
        raise bad_request("invalid_cursor", "cursor không hợp lệ") from None


async def list_documents(
    org_id: str,
    *,
    status: str | None,
    q: str | None,
    external_ref: str | None,
    limit: int,
    cursor: str | None,
) -> dict:
    where = ["d.org_id = %s"]
    params: list[Any] = [org_id]
    if status:
        if status not in STATUS_LABELS:
            raise bad_request("invalid_status", f"status phải là một trong {', '.join(STATUS_LABELS)}")
        where.append("d.status = %s")
        params.append(status)
    if external_ref:
        where.append("d.external_ref = %s")
        params.append(external_ref)
    if q:
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(d.title ILIKE %s OR d.filename ILIKE %s OR d.external_ref ILIKE %s)")
        params += [pattern, pattern, pattern]
    if cursor:
        created, last_id = _decode_cursor(cursor)
        where.append("(d.created_at, d.id) < (%s, %s)")
        params += [created, last_id]

    rows = await db.fetchall(
        "SELECT d.* FROM documents d WHERE " + " AND ".join(where)
        + " ORDER BY d.created_at DESC, d.id DESC LIMIT %s",
        (*params, limit + 1),
    )
    page, more = rows[:limit], len(rows) > limit
    by_doc: dict[str, list[dict]] = {row["id"]: [] for row in page}
    if page:
        for r in await db.fetchall(
            "SELECT * FROM recipients WHERE document_id = ANY(%s) ORDER BY position",
            (list(by_doc),),
        ):
            by_doc[r["document_id"]].append(r)
    return {
        "data": [document_view(row, by_doc[row["id"]]) for row in page],
        "next_cursor": _encode_cursor(page[-1]) if more else None,
    }


# --------------------------------------------------------------------------
# Tạo và sửa bản nháp
# --------------------------------------------------------------------------


def inspect_pdf_sync(data: bytes) -> int:
    from pyhanko.pdf_utils.reader import PdfFileReader

    if not data.startswith(b"%PDF-"):
        raise bad_request("invalid_pdf", "Tệp tải lên không phải PDF")
    try:
        hybrid = signing.has_hybrid_xrefs(data)
        reader = PdfFileReader(io.BytesIO(data), strict=not hybrid)
        if reader.encrypted:
            raise bad_request("encrypted_pdf", "PDF có mật khẩu, không ký được")
        return int(reader.root["/Pages"]["/Count"])
    except ApiError:
        raise
    except Exception as exc:
        raise bad_request("invalid_pdf", f"Không đọc được PDF: {exc}") from exc


def _check_recipients(specs: list[RecipientSpec], page_count: int, plan: plans.Plan) -> None:
    if len(specs) > plan.max_recipients:
        raise ApiError(
            402, "quota_exceeded", f"Gói {plan.name} tối đa {plan.max_recipients} người nhận mỗi tài liệu"
        )
    for spec in specs:
        if spec.field is not None and spec.field.page >= page_count:
            raise bad_request(
                "invalid_field", f"Ô ký của {spec.name} nằm ở trang {spec.field.page + 1}, tài liệu chỉ có {page_count} trang"
            )


async def _insert_recipients(conn: db.Conn, doc_id: str, specs: list[RecipientSpec]) -> None:
    for position, spec in enumerate(specs):
        recipient_id = security.new_id("rcp")
        await conn.execute(
            "INSERT INTO recipients (id, document_id, position, routing_order, role, name, email, "
            "tax_code, field_page, field_box, token_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                recipient_id,
                doc_id,
                position,
                spec.order if spec.order is not None else position + 1,
                spec.role,
                spec.name,
                spec.email,
                spec.tax_code,
                spec.field.page if spec.field else None,
                list(spec.field.box) if spec.field else None,
                security.token_hash(security.recipient_token(recipient_id, 1)),
            ),
        )


async def create(
    principal: Principal,
    filename: str,
    data: bytes,
    spec: DocumentSpec,
    *,
    base_url: str,
    ip: str | None,
    user_agent: str | None,
) -> dict:
    plan = principal.plan
    page_count = await asyncio.to_thread(inspect_pdf_sync, data)
    _check_recipients(spec.recipients, page_count, plan)
    expires_at = spec.resolved_expiry()

    doc_id = f"doc_{secrets.token_hex(8)}"
    filename = (filename or "tai-lieu.pdf").replace("/", "_").replace("\\", "_")[:200]
    title = (spec.title or filename.removesuffix(".pdf")).strip() or "Tài liệu"
    await asyncio.to_thread(storage.write_revision, doc_id, 0, data)
    try:
        async with db.transaction() as conn:
            await plans.consume_document(conn, principal.org_id, plan)
            await conn.execute(
                "INSERT INTO documents (id, org_id, title, filename, status, page_count, "
                "external_ref, metadata, message, created_by_user, created_by_key, expires_at) "
                "VALUES (%s, %s, %s, %s, 'draft', %s, %s, %s, %s, %s, %s, %s)",
                (
                    doc_id,
                    principal.org_id,
                    title,
                    filename,
                    page_count,
                    spec.external_ref,
                    Jsonb(spec.metadata),
                    spec.message,
                    principal.user["id"] if principal.user else None,
                    principal.api_key_id,
                    expires_at,
                ),
            )
            await conn.execute(
                "INSERT INTO revisions (document_id, revision, sha256, size) VALUES (%s, 0, %s, %s)",
                (doc_id, hashlib.sha256(data).digest(), len(data)),
            )
            await _insert_recipients(conn, doc_id, spec.recipients)
            await audit.append(
                conn,
                doc_id,
                "document.created",
                principal.actor,
                {"title": title, "filename": filename, "sha256": hashlib.sha256(data).hexdigest(),
                 "pages": page_count, "recipients": len(spec.recipients)},
                ip=ip,
                user_agent=user_agent,
            )
            if spec.send:
                await _send(conn, principal, doc_id, base_url=base_url, ip=ip, user_agent=user_agent)
            doc = await _load_by_id(conn, doc_id)
            recipients = await load_recipients(doc_id, conn=conn)
    except BaseException:
        await asyncio.to_thread(storage.delete_document, doc_id)
        raise
    webhooks.wake()
    return document_view(doc, recipients, base_url=base_url)


async def _locked_draft(conn: db.Conn, org_id: str, doc_id: str) -> dict:
    doc = await load(org_id, doc_id, conn=conn)
    await conn.execute("SELECT 1 FROM documents WHERE id = %s FOR UPDATE", (doc_id,))
    doc = await _load_by_id(conn, doc_id)
    if doc["status"] != "draft":
        raise conflict("not_draft", "Chỉ sửa được tài liệu ở trạng thái nháp")
    return doc


async def update_draft(
    principal: Principal, doc_id: str, patch: DocumentPatch, *, base_url: str
) -> dict:
    changes = patch.model_dump(exclude_unset=True)
    async with db.transaction() as conn:
        doc = await _locked_draft(conn, principal.org_id, doc_id)
        if changes:
            if "expires_at" in changes and changes["expires_at"] is not None:
                if changes["expires_at"].tzinfo is None:
                    raise bad_request("invalid_expiry", "expires_at phải kèm múi giờ")
            if "metadata" in changes:
                changes["metadata"] = Jsonb(changes["metadata"] or {})
            if "title" in changes and changes["title"] is None:
                changes.pop("title")
            assignments = ", ".join(f"{column} = %s" for column in changes)
            await conn.execute(
                f"UPDATE documents SET {assignments}, updated_at = now() WHERE id = %s",
                (*changes.values(), doc_id),
            )
            await audit.append(
                conn, doc_id, "document.updated", principal.actor, {"fields": sorted(changes)}
            )
        doc = await _load_by_id(conn, doc_id)
        recipients = await load_recipients(doc_id, conn=conn)
    return document_view(doc, recipients, base_url=base_url)


async def replace_recipients(
    principal: Principal, doc_id: str, specs: list[RecipientSpec], *, base_url: str
) -> dict:
    async with db.transaction() as conn:
        doc = await _locked_draft(conn, principal.org_id, doc_id)
        _check_recipients(specs, doc["page_count"], principal.plan)
        await conn.execute("DELETE FROM recipients WHERE document_id = %s", (doc_id,))
        await _insert_recipients(conn, doc_id, specs)
        await conn.execute("UPDATE documents SET updated_at = now() WHERE id = %s", (doc_id,))
        await audit.append(
            conn,
            doc_id,
            "document.recipients_set",
            principal.actor,
            {"recipients": [{"name": s.name, "role": s.role, "order": s.order, "tax_code": s.tax_code} for s in specs]},
        )
        doc = await _load_by_id(conn, doc_id)
        recipients = await load_recipients(doc_id, conn=conn)
    return document_view(doc, recipients, base_url=base_url)


# --------------------------------------------------------------------------
# Gửi, nhắc, huỷ, xoá
# --------------------------------------------------------------------------


def active_order(recipients: list[dict]) -> int | None:
    pending = [r["routing_order"] for r in recipients if r["status"] == "pending"]
    return min(pending) if pending else None


async def _event_payload(conn: db.Conn, doc_id: str, recipient_id: str | None = None) -> dict:
    doc = await _load_by_id(conn, doc_id)
    recipients = await load_recipients(doc_id, conn=conn)
    data: dict[str, Any] = {"document": document_view(doc, recipients)}
    if recipient_id is not None:
        data["recipient"] = next(
            recipient_view(r, doc, org_view=True, base_url=None)
            for r in recipients
            if r["id"] == recipient_id
        )
    return data


async def _notify_active(conn: db.Conn, doc_id: str, base_url: str) -> None:
    """Email mời cho nhóm đang tới lượt mà chưa được báo."""
    doc = await _load_by_id(conn, doc_id)
    recipients = await load_recipients(doc_id, conn=conn)
    order = active_order(recipients)
    for recipient in recipients:
        if (
            recipient["status"] != "pending"
            or recipient["routing_order"] != order
            or recipient["notified_at"] is not None
        ):
            continue
        verb = "ký" if recipient["role"] == "signer" else "duyệt"
        queued = await mailer.enqueue(
            conn,
            recipient["email"],
            f"{doc['org_name']} mời bạn {verb}: {doc['title']}",
            f"Chào {recipient['name']},\n\n{doc['org_name']} mời bạn {verb} tài liệu "
            f"«{doc['title']}».\n"
            + (f"\nLời nhắn: {doc['message']}\n" if doc["message"] else "")
            + f"\nMở tài liệu: {signing_url(base_url, recipient)}\n"
            + (
                f"\nHạn chót: {doc['expires_at'].astimezone(plans.VN_TZ):%d/%m/%Y %H:%M}\n"
                if doc["expires_at"]
                else ""
            )
            + ("\nKý số cần USB token và Web Signer Agent trên máy.\n" if recipient["role"] == "signer" else ""),
        )
        if queued:
            await conn.execute(
                "UPDATE recipients SET notified_at = now() WHERE id = %s", (recipient["id"],)
            )
            await audit.append(
                conn, doc_id, "recipient.notified", "system", {"recipient_id": recipient["id"], "channel": "email"}
            )


async def _send(
    conn: db.Conn,
    principal: Principal,
    doc_id: str,
    *,
    base_url: str,
    ip: str | None,
    user_agent: str | None,
) -> None:
    await conn.execute("SELECT 1 FROM documents WHERE id = %s FOR UPDATE", (doc_id,))
    doc = await _load_by_id(conn, doc_id)
    if doc["status"] != "draft":
        raise conflict("not_draft", "Tài liệu đã được gửi rồi")
    recipients = await load_recipients(doc_id, conn=conn)
    if not any(r["role"] == "signer" for r in recipients):
        raise bad_request("no_signers", "Cần ít nhất một người ký trước khi gửi")
    if doc["expires_at"] is not None and doc["expires_at"] <= _now():
        raise bad_request("invalid_expiry", "Hạn ký đã qua")
    await conn.execute(
        "UPDATE documents SET status = 'in_progress', sent_at = now(), updated_at = now() WHERE id = %s",
        (doc_id,),
    )
    await audit.append(conn, doc_id, "document.sent", principal.actor, ip=ip, user_agent=user_agent)
    await webhooks.enqueue(conn, doc["org_id"], "document.sent", await _event_payload(conn, doc_id))
    await _notify_active(conn, doc_id, base_url)


async def send(
    principal: Principal, doc_id: str, *, base_url: str, ip: str | None, user_agent: str | None
) -> dict:
    async with db.transaction() as conn:
        await load(principal.org_id, doc_id, conn=conn)
        await _send(conn, principal, doc_id, base_url=base_url, ip=ip, user_agent=user_agent)
        doc = await _load_by_id(conn, doc_id)
        recipients = await load_recipients(doc_id, conn=conn)
    webhooks.wake()
    return document_view(doc, recipients, base_url=base_url)


async def void(
    principal: Principal, doc_id: str, reason: str, *, ip: str | None, user_agent: str | None
) -> dict:
    async with db.transaction() as conn:
        await load(principal.org_id, doc_id, conn=conn)
        await conn.execute("SELECT 1 FROM documents WHERE id = %s FOR UPDATE", (doc_id,))
        doc = await _load_by_id(conn, doc_id)
        if doc["status"] not in ("draft", "in_progress"):
            raise conflict("not_voidable", f"Tài liệu đang ở trạng thái {STATUS_LABELS[doc['status']]}, không huỷ được")
        await conn.execute(
            "UPDATE documents SET status = 'voided', void_reason = %s, updated_at = now() WHERE id = %s",
            (reason, doc_id),
        )
        await audit.append(
            conn, doc_id, "document.voided", principal.actor, {"reason": reason}, ip=ip, user_agent=user_agent
        )
        await webhooks.enqueue(conn, doc["org_id"], "document.voided", await _event_payload(conn, doc_id))
        doc = await _load_by_id(conn, doc_id)
        recipients = await load_recipients(doc_id, conn=conn)
    webhooks.wake()
    return document_view(doc, recipients)


async def delete(principal: Principal, doc_id: str) -> None:
    async with db.transaction() as conn:
        await load(principal.org_id, doc_id, conn=conn)
        await conn.execute("SELECT 1 FROM documents WHERE id = %s FOR UPDATE", (doc_id,))
        doc = await _load_by_id(conn, doc_id)
        if doc["status"] == "in_progress":
            raise conflict("in_progress", "Tài liệu đang trong luồng ký — huỷ (void) trước khi xoá")
        await conn.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
    await asyncio.to_thread(storage.delete_document, doc_id)


async def _org_recipient(conn: db.Conn, principal: Principal, doc_id: str, recipient_id: str) -> tuple[dict, dict]:
    doc = await load(principal.org_id, doc_id, conn=conn)
    recipient = await db.fetchone(
        "SELECT * FROM recipients WHERE id = %s AND document_id = %s", (recipient_id, doc_id), conn=conn
    )
    if recipient is None:
        raise not_found("Không tìm thấy người nhận")
    return doc, recipient


async def remind(principal: Principal, doc_id: str, recipient_id: str, *, base_url: str) -> dict:
    if not mailer.enabled():
        raise conflict("email_disabled", "Máy chủ chưa cấu hình SMTP — hãy tự gửi signing_url cho người nhận")
    async with db.transaction() as conn:
        doc, recipient = await _org_recipient(conn, principal, doc_id, recipient_id)
        if doc["status"] != "in_progress" or recipient["status"] != "pending":
            raise conflict("not_pending", "Người nhận này không còn việc phải làm")
        if not recipient["email"]:
            raise bad_request("no_email", "Người nhận chưa có email")
        recipients = await load_recipients(doc_id, conn=conn)
        if recipient["routing_order"] != active_order(recipients):
            raise conflict("not_your_turn", "Chưa tới lượt người nhận này")
        await conn.execute("UPDATE recipients SET notified_at = NULL WHERE id = %s", (recipient_id,))
        await _notify_active(conn, doc_id, base_url)
    return {"ok": True}


async def rotate_link(principal: Principal, doc_id: str, recipient_id: str, *, base_url: str) -> dict:
    """Thu hồi liên kết cũ (lộ, gửi nhầm) và cấp liên kết mới."""
    async with db.transaction() as conn:
        doc, recipient = await _org_recipient(conn, principal, doc_id, recipient_id)
        if doc["status"] in TERMINAL or recipient["status"] != "pending":
            raise conflict("not_pending", "Người nhận này không còn việc phải làm")
        version = recipient["token_version"] + 1
        cur = await conn.execute(
            "UPDATE recipients SET token_version = %s, token_hash = %s WHERE id = %s RETURNING *",
            (version, security.token_hash(security.recipient_token(recipient_id, version)), recipient_id),
        )
        recipient = await cur.fetchone()
        await audit.append(conn, doc_id, "recipient.link_rotated", principal.actor, {"recipient_id": recipient_id})
    return recipient_view(recipient, doc, org_view=True, base_url=base_url)


# --------------------------------------------------------------------------
# Phía người nhận (liên kết /s/<token>)
# --------------------------------------------------------------------------


async def by_token(token: str) -> tuple[dict, dict, list[dict]]:
    if not 20 <= len(token) <= 100:
        raise not_found("Liên kết ký không hợp lệ")
    recipient = await db.fetchone(
        "SELECT * FROM recipients WHERE token_hash = %s", (security.token_hash(token),)
    )
    if recipient is None:
        raise not_found("Liên kết ký không hợp lệ hoặc đã bị thu hồi")
    async with db.connection() as conn:
        doc = await _load_by_id(conn, recipient["document_id"])
        recipients = await load_recipients(doc["id"], conn=conn)
    if doc["status"] == "draft":
        raise not_found("Tài liệu chưa được gửi")
    return doc, recipient, recipients


def turn(doc: dict, recipient: dict, recipients: list[dict]) -> dict:
    """Người nhận này làm gì được lúc này, và nếu không thì vì sao."""
    status = doc["status"]
    if status == "in_progress" and doc["expires_at"] is not None and doc["expires_at"] <= _now():
        status = "expired"
    waiting: list[str] = []
    if recipient["status"] != "pending":
        reason = "already_acted"
    elif status != "in_progress":
        reason = f"document_{status}"
    else:
        order = active_order(recipients)
        if recipient["routing_order"] == order:
            reason = None
        else:
            reason = "not_your_turn"
            waiting = [r["name"] for r in recipients if r["status"] == "pending" and r["routing_order"] == order]
    return {"can_act": reason is None, "reason": reason, "waiting_for": waiting}


def require_turn(doc: dict, recipient: dict, recipients: list[dict], role: str) -> None:
    state = turn(doc, recipient, recipients)
    if recipient["role"] != role:
        raise conflict("wrong_role", "Người duyệt không ký số" if role == "signer" else "Người ký không duyệt")
    if state["can_act"]:
        return
    messages = {
        "already_acted": "Bạn đã xử lý tài liệu này rồi",
        "not_your_turn": f"Chưa tới lượt bạn — đang chờ {', '.join(state['waiting_for'])}",
        "document_completed": "Tài liệu đã hoàn tất",
        "document_declined": "Tài liệu đã bị từ chối",
        "document_voided": "Tài liệu đã bị huỷ",
        "document_expired": "Tài liệu đã hết hạn ký",
    }
    raise conflict(state["reason"], messages.get(state["reason"], "Không thực hiện được"))


async def record_view(doc: dict, recipient: dict, *, ip: str | None, user_agent: str | None) -> None:
    """Lần mở đầu tiên mới ghi — mở lại để ký không làm nhiễu nhật ký."""
    if recipient["viewed_at"] is not None:
        return
    async with db.transaction() as conn:
        cur = await conn.execute(
            "UPDATE recipients SET viewed_at = now() WHERE id = %s AND viewed_at IS NULL RETURNING id",
            (recipient["id"],),
        )
        if await cur.fetchone() is None:
            return
        await audit.append(
            conn, doc["id"], "recipient.viewed", f"recipient:{recipient['id']}", ip=ip, user_agent=user_agent
        )
        await webhooks.enqueue(
            conn, doc["org_id"], "recipient.viewed", await _event_payload(conn, doc["id"], recipient["id"])
        )
    webhooks.wake()


async def _lock_for_action(conn: db.Conn, recipient_id: str, role: str) -> tuple[dict, dict, list[dict]]:
    cur = await conn.execute("SELECT document_id FROM recipients WHERE id = %s", (recipient_id,))
    row = await cur.fetchone()
    if row is None:
        raise not_found("Liên kết ký không hợp lệ")
    await conn.execute("SELECT 1 FROM documents WHERE id = %s FOR UPDATE", (row["document_id"],))
    doc = await _load_by_id(conn, row["document_id"])
    recipients = await load_recipients(doc["id"], conn=conn)
    recipient = next(r for r in recipients if r["id"] == recipient_id)
    require_turn(doc, recipient, recipients, role)
    return doc, recipient, recipients


async def _complete_if_done(conn: db.Conn, doc_id: str, base_url: str) -> None:
    recipients = await load_recipients(doc_id, conn=conn)
    if any(r["status"] == "pending" for r in recipients):
        await _notify_active(conn, doc_id, base_url)
        return
    await conn.execute(
        "UPDATE documents SET status = 'completed', completed_at = now(), updated_at = now() WHERE id = %s",
        (doc_id,),
    )
    await audit.append(conn, doc_id, "document.completed", "system")
    doc = await _load_by_id(conn, doc_id)
    await webhooks.enqueue(conn, doc["org_id"], "document.completed", await _event_payload(conn, doc_id))
    for recipient in recipients:
        await mailer.enqueue(
            conn,
            recipient["email"],
            f"Đã hoàn tất: {doc['title']}",
            f"Chào {recipient['name']},\n\nTài liệu «{doc['title']}» của {doc['org_name']} "
            f"đã được tất cả các bên xử lý xong.\nXem và tải bản đã ký: {signing_url(base_url, recipient)}\n",
        )
    await mailer.enqueue(
        conn,
        doc["creator_email"],
        f"Đã hoàn tất: {doc['title']}",
        f"Tài liệu «{doc['title']}» đã hoàn tất.\n{base_url}/#/documents/{doc_id}\n",
    )


async def approve(recipient: dict, *, base_url: str, ip: str | None, user_agent: str | None) -> None:
    async with db.transaction() as conn:
        doc, recipient, _ = await _lock_for_action(conn, recipient["id"], "approver")
        await conn.execute(
            "UPDATE recipients SET status = 'approved', acted_at = now() WHERE id = %s", (recipient["id"],)
        )
        await audit.append(
            conn, doc["id"], "recipient.approved", f"recipient:{recipient['id']}", ip=ip, user_agent=user_agent
        )
        await webhooks.enqueue(
            conn, doc["org_id"], "recipient.approved", await _event_payload(conn, doc["id"], recipient["id"])
        )
        await _complete_if_done(conn, doc["id"], base_url)
    webhooks.wake()


async def decline(recipient: dict, reason: str, *, ip: str | None, user_agent: str | None) -> None:
    async with db.transaction() as conn:
        doc, recipient, _ = await _lock_for_action(conn, recipient["id"], recipient["role"])
        await conn.execute(
            "UPDATE recipients SET status = 'declined', acted_at = now(), decline_reason = %s WHERE id = %s",
            (reason, recipient["id"]),
        )
        await conn.execute(
            "UPDATE documents SET status = 'declined', updated_at = now() WHERE id = %s", (doc["id"],)
        )
        actor = f"recipient:{recipient['id']}"
        await audit.append(conn, doc["id"], "recipient.declined", actor, {"reason": reason}, ip=ip, user_agent=user_agent)
        await audit.append(conn, doc["id"], "document.declined", "system")
        await webhooks.enqueue(
            conn, doc["org_id"], "recipient.declined", await _event_payload(conn, doc["id"], recipient["id"])
        )
        await webhooks.enqueue(conn, doc["org_id"], "document.declined", await _event_payload(conn, doc["id"]))
        await mailer.enqueue(
            conn,
            doc["creator_email"],
            f"Bị từ chối: {doc['title']}",
            f"{recipient['name']} đã từ chối tài liệu «{doc['title']}».\nLý do: {reason}\n",
        )
    webhooks.wake()


async def commit_signature(
    recipient_id: str,
    expected_revision: int,
    signed_pdf: bytes,
    details: dict[str, Any],
    *,
    base_url: str,
    ip: str | None,
    user_agent: str | None,
) -> None:
    """Ghi revision mới sau khi token đã ký. Revision cũ giữ nguyên để truy vết."""
    async with db.transaction() as conn:
        doc, recipient, _ = await _lock_for_action(conn, recipient_id, "signer")
        if doc["revision"] != expected_revision:
            raise conflict("concurrent_signature", "Tài liệu vừa được người khác ký, hãy ký lại")
        revision = expected_revision + 1
        await asyncio.to_thread(storage.write_revision, doc["id"], revision, signed_pdf)
        await conn.execute(
            "UPDATE documents SET revision = %s, updated_at = now() WHERE id = %s", (revision, doc["id"])
        )
        await conn.execute(
            "INSERT INTO revisions (document_id, revision, sha256, size) VALUES (%s, %s, %s, %s)",
            (doc["id"], revision, hashlib.sha256(signed_pdf).digest(), len(signed_pdf)),
        )
        await conn.execute(
            "UPDATE recipients SET status = 'signed', acted_at = now(), signed_by = %s, "
            "signer_tax_code = %s, cert_serial = %s, cert_issuer = %s, sig_field = %s, "
            "sig_page = %s, sig_profile = %s, sig_revision = %s WHERE id = %s",
            (
                details["signer"],
                details["tax_code"],
                details["cert_serial"],
                details["cert_issuer"],
                details["field_name"],
                details["page"],
                details["profile"],
                revision,
                recipient_id,
            ),
        )
        await plans.count_signature(conn, doc["org_id"])
        await audit.append(
            conn,
            doc["id"],
            "recipient.signed",
            f"recipient:{recipient_id}",
            {**details, "revision": revision, "sha256": hashlib.sha256(signed_pdf).hexdigest()},
            ip=ip,
            user_agent=user_agent,
        )
        await webhooks.enqueue(
            conn, doc["org_id"], "recipient.signed", await _event_payload(conn, doc["id"], recipient_id)
        )
        await _complete_if_done(conn, doc["id"], base_url)
    webhooks.wake()


# --------------------------------------------------------------------------
# Hết hạn — worker gọi định kỳ
# --------------------------------------------------------------------------


async def expire_due(limit: int = 50) -> int:
    expired = 0
    async with db.transaction() as conn:
        cur = await conn.execute(
            "SELECT id, org_id FROM documents WHERE status = 'in_progress' AND expires_at <= now() "
            "ORDER BY expires_at LIMIT %s FOR UPDATE SKIP LOCKED",
            (limit,),
        )
        for row in await cur.fetchall():
            await conn.execute(
                "UPDATE documents SET status = 'expired', updated_at = now() WHERE id = %s", (row["id"],)
            )
            await audit.append(conn, row["id"], "document.expired", "system")
            await webhooks.enqueue(conn, row["org_id"], "document.expired", await _event_payload(conn, row["id"]))
            expired += 1
    if expired:
        webhooks.wake()
    return expired


# --------------------------------------------------------------------------
# Tệp, xác thực, logo
# --------------------------------------------------------------------------


async def revision_file(doc: dict, revision: int | None) -> tuple[bytes, int]:
    """-> (nội dung PDF, revision). Mặc định bản mới nhất."""
    target = doc["revision"] if revision is None else revision
    if not 0 <= target <= doc["revision"]:
        raise not_found("Không có revision này")
    return await asyncio.to_thread(storage.read_revision, doc["id"], target), target


def _verify_sync(pdf: bytes) -> list[dict]:
    return [r.to_dict() for r in asyncio.run(verify.verify(pdf))]


async def verify_report(doc: dict) -> list[dict]:
    """Xác thực chữ ký của bản mới nhất. Cache theo revision + trust store + ngày
    (chứng thư hết hạn theo thời gian, nên kết quả không vĩnh viễn)."""
    cache_key = f"{trust.fingerprint()}:{_now().date().isoformat()}"
    row = await db.fetchone(
        "SELECT verify_report, verify_trust FROM revisions WHERE document_id = %s AND revision = %s",
        (doc["id"], doc["revision"]),
    )
    if row and row["verify_trust"] == cache_key and row["verify_report"] is not None:
        return row["verify_report"]
    pdf = await asyncio.to_thread(storage.read_revision, doc["id"], doc["revision"])
    reports = await asyncio.to_thread(_verify_sync, pdf)
    await db.execute(
        "UPDATE revisions SET verify_report = %s, verify_trust = %s WHERE document_id = %s AND revision = %s",
        (Jsonb(reports), cache_key, doc["id"], doc["revision"]),
    )
    return reports


async def audit_trail(principal: Principal, doc_id: str) -> dict:
    await load(principal.org_id, doc_id)
    return await audit.trail(doc_id)


async def save_logo(recipient_id: str, data: bytes, fmt: str) -> None:
    await db.execute(
        "INSERT INTO recipient_logos (recipient_id, data, format) VALUES (%s, %s, %s) "
        "ON CONFLICT (recipient_id) DO UPDATE SET data = EXCLUDED.data, format = EXCLUDED.format, "
        "updated_at = now()",
        (recipient_id, data, fmt),
    )


async def load_logo(recipient_id: str) -> tuple[bytes, str] | None:
    row = await db.fetchone(
        "SELECT data, format FROM recipient_logos WHERE recipient_id = %s", (recipient_id,)
    )
    return (bytes(row["data"]), row["format"]) if row else None


async def delete_logo(recipient_id: str) -> None:
    await db.execute("DELETE FROM recipient_logos WHERE recipient_id = %s", (recipient_id,))

