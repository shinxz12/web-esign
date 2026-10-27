"""Một lượt ký số của người nhận: pha 1 trên server, token ký qua agent, pha 2.

Tài liệu không rời server: agent chỉ nhận vài trăm byte signed attributes.

Hai người cùng nhóm ký song song không được ký đè lên nhau: mỗi tài liệu có
một khoá trong tiến trình giữ suốt prepare → token → finalize → ghi. Người
đến sau nhận 409 ngay thay vì treo chờ người trước nhập PIN. Khi ghi, revision
còn được so lại trong transaction (``commit_signature``) — lớp chặn thứ hai.
"""

from __future__ import annotations

import asyncio
import base64
import weakref

from pydantic import BaseModel, Field

from . import documents, signing, storage
from .errors import ApiError, bad_request, conflict
from .relay import AgentError, AgentSession


class SignRequest(BaseModel):
    # Bỏ trống khi trình duyệt đã kích hoạt cookie thiết bị: server tự tìm
    # agent của máy đó. Mã ghép cặp chỉ còn là đường dự phòng.
    agent_code: str | None = Field(default=None, min_length=4, max_length=16)
    cert_id: str = Field(min_length=1, max_length=200)
    # Bỏ qua khi người gửi đã đặt sẵn ô ký cho người nhận này.
    page: int | None = Field(default=None, ge=0)
    box: tuple[float, float, float, float] | None = None
    check_mark: bool = True
    color: str = Field(default=signing.DEFAULT_STAMP_COLOR, max_length=20)
    show_border: bool = False
    use_logo: bool = True


_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()


def _lock(doc_id: str) -> asyncio.Lock:
    lock = _locks.get(doc_id)
    if lock is None:
        lock = asyncio.Lock()
        _locks[doc_id] = lock
    return lock


def _placement(doc: dict, recipient: dict, request: SignRequest) -> tuple[int, tuple[float, float, float, float]]:
    """Ô ký người gửi đặt sẵn thắng mọi thứ trình duyệt gửi lên."""
    if recipient["field_page"] is not None:
        return recipient["field_page"], tuple(recipient["field_box"])  # type: ignore[return-value]
    if request.page is None or request.box is None:
        raise bad_request("missing_placement", "Chưa chọn vị trí ô ký")
    if request.page >= doc["page_count"]:
        raise bad_request("invalid_field", "Trang đặt ô ký không tồn tại")
    documents.FieldSpec(page=request.page, box=request.box)  # cùng luật kích thước
    return request.page, request.box


async def sign(
    token: str,
    request: SignRequest,
    session: AgentSession,
    *,
    base_url: str,
    ip: str | None,
    user_agent: str | None,
) -> None:
    doc, recipient, recipients = await documents.by_token(token)
    documents.require_turn(doc, recipient, recipients, "signer")

    cert_entry = session.certificates.get(request.cert_id)
    if cert_entry is None:
        raise conflict("unknown_certificate", "Chưa nạp danh sách chứng thư của agent, hãy kết nối lại")
    cert_der = base64.b64decode(cert_entry["cert_b64"])
    chain_der = [base64.b64decode(c) for c in cert_entry.get("chain_b64", [])]
    cert = signing.load_cert_chain(cert_der, chain_der)[0]
    cert_cn = signing.subject_cn(cert)
    cert_mst = signing.subject_tax_code(cert)

    # Đúng lượt chưa đủ: chứng thư phải đúng người được mời.
    if not documents.identity_matches(recipient, cert_cn, cert_mst):
        expected = f"MST {recipient['tax_code']}" if recipient["tax_code"] else recipient["name"]
        raise ApiError(
            403,
            "wrong_signer",
            f"Chứng thư của «{cert_cn}» không khớp người được mời ký ({expected})",
        )

    page, box = _placement(doc, recipient, request)
    lock = _lock(doc["id"])
    if lock.locked():
        raise conflict("signing_in_progress", "Một người khác đang ký tài liệu này, thử lại sau ít phút")

    async with lock:
        # Đọc lại sau khi giữ khoá: có thể ai đó vừa ký xong.
        doc, recipient, recipients = await documents.by_token(token)
        documents.require_turn(doc, recipient, recipients, "signer")
        revision = doc["revision"]
        pdf = await asyncio.to_thread(storage.read_revision, doc["id"], revision)

        logo = await documents.load_logo(recipient["id"]) if request.use_logo else None
        profile = signing.default_profile()
        appearance = signing.SignatureAppearance(
            page=page,
            box=box,
            check_mark=request.check_mark,
            logo=logo[0] if logo else None,
            color=request.color,
            show_border=request.show_border,
        )
        field_name = await asyncio.to_thread(signing.free_field_name, pdf)

        # Pha 1 — tài liệu ở lại server.
        try:
            prepared = await signing.prepare(pdf, cert_der, chain_der, appearance, field_name, profile)
        except signing.SigningError as exc:
            raise bad_request("prepare_failed", f"Không chuẩn bị được chữ ký: {exc}") from exc

        # Chỉ signed attributes đi ra ngoài.
        try:
            result = await session.call(
                "sign",
                {
                    "cert_id": request.cert_id,
                    "algo": prepared.algo.value,
                    "algo_params": prepared.algo_params,
                    "document_name": doc["title"],
                    "document_digest": prepared.document_digest.hex(),
                    "tbs_digest": prepared.tbs_digest.hex(),
                    "tbs_b64": base64.b64encode(prepared.signed_attrs_der).decode(),
                },
            )
        except AgentError as exc:
            await signing.close_signing_context(prepared._signing_context)
            raise ApiError(502, "agent_error", str(exc)) from exc

        # Pha 2 — nhúng CMS, dấu thời gian và DSS vào chỗ đã chừa.
        try:
            signed_pdf = await signing.finalize(
                prepared, cert_der, chain_der, base64.b64decode(result["signature_b64"])
            )
        except signing.SigningError as exc:
            raise bad_request("finalize_failed", f"Không hoàn tất được chữ ký: {exc}") from exc

        issuer = cert.issuer.native
        await documents.commit_signature(
            recipient["id"],
            revision,
            signed_pdf,
            {
                "signer": cert_cn,
                "tax_code": cert_mst,
                "cert_serial": format(cert.serial_number, "x"),
                "cert_issuer": str(issuer.get("common_name") or cert.issuer.human_friendly),
                "field_name": field_name,
                "page": page,
                "profile": profile.value,
            },
            base_url=base_url,
            ip=ip,
            user_agent=user_agent,
        )
