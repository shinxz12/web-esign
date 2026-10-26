"""Lưu trữ tài liệu và luồng ký. Mỗi lần ký tạo một revision mới.

Mô hình phân quyền không có bảng người dùng: danh tính người ký **chính là
chứng thư số** của họ. Chủ tài liệu giữ `owner_token` (cookie), mỗi người ký
nhận một `invite_token` riêng. Server chỉ chấp nhận chữ ký khi đúng lượt và
đúng người — đối chiếu MST, không đối chiếu tên hiển thị.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import secrets
import shutil
import unicodedata
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA_DIR = pathlib.Path(
    os.environ.get("WEBSIGNER_DATA", REPO_ROOT / "data")
).resolve()
DOCUMENTS_DIR = DATA_DIR / "documents"
CERTS_DIR = DATA_DIR / "certs"  # khoá/chứng thư test + CRL phục vụ qua HTTP
LOGOS_DIR = DATA_DIR / "logos"  # logo/con dấu của người ký, khoá theo token


class DocumentNotFound(KeyError):
    pass


class WorkflowError(RuntimeError):
    """Vi phạm luồng ký: sai lượt, sai người, tài liệu đã xong."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_name(value: str) -> str:
    """Bỏ dấu, gộp khoảng trắng, viết hoa — để so tên người ký nới tay hơn."""
    stripped = unicodedata.normalize("NFD", value)
    ascii_only = "".join(c for c in stripped if unicodedata.category(c) != "Mn")
    return " ".join(ascii_only.split()).upper()


@dataclass
class SignerSlot:
    """Một lượt ký trong luồng."""

    order: int
    name: str
    tax_code: str | None
    invite_token: str
    signed_at: str | None = None
    signed_by: str | None = None  # CN thật trên chứng thư đã ký

    @property
    def done(self) -> bool:
        return self.signed_at is not None

    def accepts(self, cert_cn: str, cert_tax_code: str | None) -> bool:
        """Chứng thư này có đúng là người được mời ký lượt này không.

        MST là định danh pháp lý nên khi khai báo thì nó quyết định. Không khai
        MST thì so tên đã bỏ dấu.
        """
        if self.tax_code:
            return bool(cert_tax_code) and cert_tax_code == self.tax_code
        return normalize_name(cert_cn) == normalize_name(self.name)


@dataclass
class SignatureRecord:
    field_name: str
    signer: str
    tax_code: str | None
    signed_at: str
    page: int
    # meta.json cũ còn reason/location; _known() loại chúng khi nạp.
    # meta.json ghi trước khi có TSA/LTV không có trường này — chúng đúng là B-B
    profile: str = "B-B"


@dataclass
class DocumentMeta:
    id: str
    name: str
    created_at: str
    # Tài liệu tạo trước khi có phân quyền không có chủ: chuỗi rỗng không bao
    # giờ khớp owner_token thật, nên chúng vô hình với mọi người thay vì làm
    # hỏng cả danh sách.
    owner_token: str = ""
    revision: int = 0
    signers: list[SignerSlot] = field(default_factory=list)
    signatures: list[SignatureRecord] = field(default_factory=list)

    # ---- trạng thái luồng ------------------------------------------------

    @property
    def ordered_workflow(self) -> bool:
        return bool(self.signers)

    @property
    def next_slot(self) -> SignerSlot | None:
        """Lượt ký kế tiếp, hoặc None khi không có luồng / đã xong."""
        return next((s for s in self.signers if not s.done), None)

    @property
    def status(self) -> str:
        if not self.signers:
            return "tu_do" if not self.signatures else "da_ky"
        if self.next_slot is None:
            return "hoan_tat"
        return "cho_ky" if any(s.done for s in self.signers) else "chua_bat_dau"

    def slot_for_invite(self, invite_token: str) -> SignerSlot:
        for slot in self.signers:
            if secrets.compare_digest(slot.invite_token, invite_token):
                return slot
        raise WorkflowError("Liên kết ký không hợp lệ")

    def to_dict(self, *, redact_invites: bool = True) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status
        data.pop("owner_token")
        if redact_invites:
            for slot in data["signers"]:
                slot.pop("invite_token")
        return data


# --------------------------------------------------------------------------
# Đọc/ghi
# --------------------------------------------------------------------------


def init() -> None:
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    LOGOS_DIR.mkdir(parents=True, exist_ok=True)


def _logo_path(key: str) -> pathlib.Path:
    """Tên tệp lấy từ băm của token, không lộ token ra hệ thống tệp."""
    return LOGOS_DIR / f"{hashlib.sha256(key.encode()).hexdigest()[:32]}.img"


def save_logo(key: str, data: bytes) -> None:
    LOGOS_DIR.mkdir(parents=True, exist_ok=True)
    _logo_path(key).write_bytes(data)


def load_logo(key: str) -> bytes | None:
    path = _logo_path(key)
    return path.read_bytes() if path.is_file() else None


def delete_logo(key: str) -> None:
    _logo_path(key).unlink(missing_ok=True)


def _doc_dir(doc_id: str) -> pathlib.Path:
    if not doc_id.isalnum():
        raise DocumentNotFound(doc_id)
    path = DOCUMENTS_DIR / doc_id
    if not path.is_dir():
        raise DocumentNotFound(doc_id)
    return path


def _write_meta(path: pathlib.Path, meta: DocumentMeta) -> None:
    tmp = path / "meta.json.tmp"
    tmp.write_text(
        json.dumps(asdict(meta), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    tmp.replace(path / "meta.json")


def _known(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    """Lọc bỏ khoá lạ — meta.json cũ còn trường đã bỏ (reason, location)."""
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in names}


def load_meta(doc_id: str) -> DocumentMeta:
    raw = json.loads((_doc_dir(doc_id) / "meta.json").read_text(encoding="utf-8"))
    signers = [SignerSlot(**_known(SignerSlot, s)) for s in raw.pop("signers", [])]
    signatures = [
        SignatureRecord(**_known(SignatureRecord, s))
        for s in raw.pop("signatures", [])
    ]
    return DocumentMeta(
        **_known(DocumentMeta, raw), signers=signers, signatures=signatures
    )


def save_meta(meta: DocumentMeta) -> None:
    _write_meta(_doc_dir(meta.id), meta)


def create(name: str, pdf_bytes: bytes, owner_token: str) -> DocumentMeta:
    doc_id = secrets.token_hex(8)
    path = DOCUMENTS_DIR / doc_id
    path.mkdir(parents=True)
    (path / "rev0.pdf").write_bytes(pdf_bytes)
    meta = DocumentMeta(
        id=doc_id, name=name, created_at=_now(), owner_token=owner_token
    )
    _write_meta(path, meta)
    return meta


def current_pdf(doc_id: str) -> bytes:
    meta = load_meta(doc_id)
    return (_doc_dir(doc_id) / f"rev{meta.revision}.pdf").read_bytes()


def commit_signature(
    doc_id: str,
    pdf_bytes: bytes,
    record: SignatureRecord,
    slot: SignerSlot | None,
) -> DocumentMeta:
    """Ghi revision mới. Revision cũ giữ nguyên để truy vết."""
    path = _doc_dir(doc_id)
    meta = load_meta(doc_id)
    meta.revision += 1
    (path / f"rev{meta.revision}.pdf").write_bytes(pdf_bytes)
    meta.signatures.append(record)
    if slot is not None:
        target = next(s for s in meta.signers if s.order == slot.order)
        target.signed_at = record.signed_at
        target.signed_by = record.signer
    _write_meta(path, meta)
    return meta


def set_signers(doc_id: str, people: list[dict[str, Any]]) -> DocumentMeta:
    """Khai báo luồng ký theo thứ tự. Chỉ được khai khi chưa ai ký."""
    meta = load_meta(doc_id)
    if meta.signatures:
        raise WorkflowError("Tài liệu đã có chữ ký, không đổi được luồng ký")
    meta.signers = [
        SignerSlot(
            order=index,
            name=person["name"].strip(),
            tax_code=(person.get("tax_code") or "").strip() or None,
            invite_token=secrets.token_urlsafe(16),
        )
        for index, person in enumerate(people)
    ]
    save_meta(meta)
    return meta


def list_documents(owner_token: str) -> list[DocumentMeta]:
    if not DOCUMENTS_DIR.is_dir():
        return []
    metas = []
    for path in DOCUMENTS_DIR.iterdir():
        if not (path / "meta.json").is_file():
            continue
        meta = load_meta(path.name)
        if secrets.compare_digest(meta.owner_token, owner_token):
            metas.append(meta)
    return sorted(metas, key=lambda m: m.created_at, reverse=True)


def find_by_invite(invite_token: str) -> tuple[DocumentMeta, SignerSlot]:
    """Tra tài liệu theo liên kết mời ký.

    Quét toàn bộ thư mục — chấp nhận được ở quy mô này; khi lên cơ sở dữ liệu
    thì thay bằng chỉ mục trên `invite_token`.
    """
    if not DOCUMENTS_DIR.is_dir():
        raise WorkflowError("Liên kết ký không hợp lệ")
    for path in DOCUMENTS_DIR.iterdir():
        if not (path / "meta.json").is_file():
            continue
        meta = load_meta(path.name)
        for slot in meta.signers:
            if secrets.compare_digest(slot.invite_token, invite_token):
                return meta, slot
    raise WorkflowError("Liên kết ký không hợp lệ")


def delete(doc_id: str) -> None:
    shutil.rmtree(_doc_dir(doc_id))
