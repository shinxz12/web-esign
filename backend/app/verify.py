"""Xác thực chữ ký trong PDF — tương đương panel 'Signature Panel' của Adobe.

Khi tệp có DSS (PAdES B-LT), việc kiểm tra thu hồi dùng **đúng dữ liệu nhúng
trong tệp**, không gọi mạng. Đó chính là ý nghĩa của LTV: mười năm sau, không
còn CA nào online, tệp vẫn tự chứng minh được.
"""

from __future__ import annotations

import io
import pathlib
from dataclasses import dataclass, field
from typing import Any

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import (
    DocumentSecurityStore,
    async_validate_pdf_signature,
    async_validate_pdf_timestamp,
)
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext

from .signing import has_hybrid_xrefs, subject_cn, subject_tax_code
from .trust import validation_context_kwargs


@dataclass
class SignatureReport:
    field_name: str
    signer: str
    tax_code: str | None
    issuer: str
    signed_at: str | None
    reason: str | None
    location: str | None
    intact: bool  # nội dung được ký không bị sửa
    trusted: bool  # chuỗi chứng thư về tới trust anchor
    covers_whole_document: bool
    timestamped: bool  # có dấu thời gian của TSA
    timestamp_at: str | None
    timestamp_trusted: bool
    ltv: bool  # kiểm tra thu hồi được hoàn toàn bằng dữ liệu trong tệp
    profile: str  # mức PAdES quan sát được
    summary: str
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # thông tin, không phải lỗi

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _offline_context(reader: PdfFileReader, trust_dir: pathlib.Path | None) -> tuple[
    ValidationContext, bool
]:
    """Ngữ cảnh xác thực chỉ dùng dữ liệu có sẵn trong tệp.

    -> (context, có_revinfo_nhúng)
    """
    kwargs = validation_context_kwargs(
        allow_fetching=False, revocation_mode="soft-fail", trust_dir=trust_dir
    )
    try:
        dss = DocumentSecurityStore.read_dss(reader)
    except Exception:
        dss = None

    if dss is not None and (dss.crls or dss.ocsps):
        kwargs["revocation_mode"] = "hard-fail"
        return dss.as_validation_context(kwargs), True

    return ValidationContext(**kwargs), False


def _observed_profile(timestamped: bool, ltv: bool, archival: bool) -> str:
    if ltv and timestamped:
        return "PAdES B-LTA" if archival else "PAdES B-LT"
    if timestamped:
        return "PAdES B-T"
    return "PAdES B-B"


def _split_signatures(reader: PdfFileReader):
    """Tách chữ ký người dùng khỏi dấu thời gian tài liệu (B-LTA).

    ``/DocTimeStamp`` cũng nằm trong ``embedded_signatures`` nhưng không phải
    chữ ký của ai cả; đưa nó vào trình xác thực chữ ký sẽ nổ.
    """
    signatures, timestamps = [], []
    for embedded in reader.embedded_signatures:
        if embedded.sig_object.get("/Type") == "/DocTimeStamp":
            timestamps.append(embedded)
        else:
            signatures.append(embedded)
    return signatures, timestamps


def _describe_later_changes(status) -> tuple[bool, str | None]:
    """Phân tích thay đổi sau chữ ký này. -> (lành tính, mô tả)."""
    if status.coverage == SignatureCoverageLevel.ENTIRE_FILE:
        return True, None
    if status.coverage != SignatureCoverageLevel.ENTIRE_REVISION:
        return False, f"Chữ ký chỉ phủ một phần tệp ({status.coverage.name})"

    diff = status.diff_result
    if diff is None or not status.docmdp_ok:
        return False, "Có thay đổi sau khi ký mà không kiểm chứng được"

    # Thứ tự enum: NONE(0) < LTA_UPDATES(1) < FORM_FILLING(2) < ANNOTATIONS(3).
    # Ngưỡng lành tính là FORM_FILLING, không phải LTA_UPDATES.
    if diff.modification_level <= ModificationLevel.FORM_FILLING:
        changed = sorted(diff.changed_form_fields)
        if changed:
            return True, f"Sau đó có thêm chữ ký: {', '.join(changed)}"
        return True, "Sau đó có bổ sung dữ liệu lưu trữ dài hạn (DSS/dấu thời gian)"
    return False, f"Tài liệu bị sửa sau khi ký ({diff.modification_level.name})"


def _summarize(intact: bool, trusted: bool, benign: bool) -> str:
    if not intact:
        return "Tài liệu đã bị sửa sau khi ký — chữ ký KHÔNG hợp lệ"
    if not benign:
        return "Chữ ký KHÔNG còn hợp lệ: nội dung đã thay đổi sau khi ký"
    if not trusted:
        return "Chữ ký toàn vẹn nhưng chứng thư chưa được tin cậy"
    return "Chữ ký hợp lệ"


async def verify(
    pdf_bytes: bytes, trust_dir: pathlib.Path | None = None
) -> list[SignatureReport]:
    # Tệp hybrid cũng bị chặn ở chế độ strict khi xác thực, không chỉ khi ký.
    reader = PdfFileReader(
        io.BytesIO(pdf_bytes), strict=not has_hybrid_xrefs(pdf_bytes)
    )
    context, has_embedded_revinfo = _offline_context(reader, trust_dir)
    signatures, doc_timestamps = _split_signatures(reader)

    archival = False
    for embedded in doc_timestamps:
        ts_status = await async_validate_pdf_timestamp(embedded, context)
        archival = archival or bool(ts_status.valid and ts_status.intact)

    reports: list[SignatureReport] = []
    for embedded in signatures:
        status = await async_validate_pdf_signature(
            embedded, signer_validation_context=context
        )
        cert = status.signing_cert
        trusted = status.trust_problem_indic is None and status.valid
        benign, note = _describe_later_changes(status)

        ts = status.timestamp_validity
        timestamped = ts is not None
        timestamp_trusted = bool(ts and ts.valid and ts.trust_problem_indic is None)
        ltv = has_embedded_revinfo and trusted

        problems: list[str] = []
        notes: list[str] = []
        if status.trust_problem_indic is not None:
            problems.append(f"Chuỗi tin cậy: {status.trust_problem_indic.name}")
        if not status.intact:
            problems.append("Dữ liệu được ký đã bị thay đổi")
        if timestamped and not timestamp_trusted:
            problems.append("Dấu thời gian chưa kiểm chứng được tới trust anchor")
        if note:
            (notes if benign else problems).append(note)

        signed_dt = embedded.self_reported_timestamp or status.signer_reported_dt
        reports.append(
            SignatureReport(
                field_name=embedded.field_name,
                signer=subject_cn(cert),
                tax_code=subject_tax_code(cert),
                issuer=str(
                    cert.issuer.native.get("common_name") or cert.issuer.human_friendly
                ),
                signed_at=signed_dt.isoformat() if signed_dt else None,
                reason=embedded.sig_object.get("/Reason"),
                location=embedded.sig_object.get("/Location"),
                intact=bool(status.intact),
                trusted=bool(trusted),
                covers_whole_document=benign,
                timestamped=timestamped,
                timestamp_at=ts.timestamp.isoformat() if timestamped else None,
                timestamp_trusted=timestamp_trusted,
                ltv=ltv,
                profile=_observed_profile(timestamped, ltv, archival),
                summary=_summarize(bool(status.intact), bool(trusted), benign),
                problems=problems,
                notes=notes,
            )
        )
    return reports
