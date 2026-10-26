"""Lõi ký PDF hai pha (hash-then-sign).

Pha 1 — prepare: chèn trường chữ ký + hình hiển thị, chừa chỗ trống cho CMS,
băm ByteRange, dựng signed attributes. Tài liệu KHÔNG rời server.
Pha 2 — finalize: nhận chữ ký thô (256 byte với RSA-2048) từ agent, dựng CMS
và nhét vào đúng chỗ trống đã chừa.

Giữa hai pha, thứ duy nhất đi ra ngoài là `signed_attrs` (vài trăm byte).
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import pathlib
from dataclasses import dataclass, field
from enum import Enum
from typing import IO, Any, Sequence

from asn1crypto import cms as asn1_cms
from asn1crypto import x509 as asn1_x509
from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.pdf_utils.layout import (
    AxisAlignment,
    InnerScaling,
    Margins,
    SimpleBoxLayoutRule,
)
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.sign import fields
from pyhanko.sign.general import SigningError as PyHankoSigningError
from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner
from pyhanko.sign.signers.pdf_cms import ExternalSigner
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator.registry import SimpleCertificateStore

from . import trust
from .store import DATA_DIR

logger = logging.getLogger("websigner.signing")

MD_ALGORITHM = "sha256"

# Bật RSA-PSS thay PKCS#1 v1.5 cho khoá RSA. Token đời cũ thường không hỗ trợ.
PREFER_PSS = os.environ.get("WEBSIGNER_PREFER_PSS", "").lower() in ("1", "true", "yes")


class SigAlgo(str, Enum):
    """Phải khớp từng ký tự với ``SigAlgo`` trong ``agent/keysource.py``.

    Hai bên là hai tiến trình tách rời nên giá trị chuỗi chính là giao kèo.
    """

    RSA_PKCS1_SHA256 = "rsa_pkcs1v15_sha256"
    RSA_PSS_SHA256 = "rsa_pss_sha256"
    ECDSA_SHA256 = "ecdsa_sha256"


class SignatureProfile(str, Enum):
    """Mức hồ sơ PAdES theo ETSI EN 319 142."""

    B_B = "B-B"  # chữ ký cơ bản
    B_T = "B-T"  # + dấu thời gian của TSA
    B_LT = "B-LT"  # + CRL/OCSP nhúng trong DSS (đạt LTV)
    B_LTA = "B-LTA"  # + dấu thời gian tài liệu, gia hạn được về sau


def _bytes_reserved(profile: SignatureProfile) -> int:
    """Chỗ trống cho CMS.

    RSA-2048 + chuỗi 2 chứng thư ~ 3.5 KB. Dấu thời gian thêm ~4 KB, CRL nhúng
    trong unsigned attrs thêm vài KB nữa, nên hồ sơ cao cần nhiều chỗ hơn.
    """
    return 16384 if profile is SignatureProfile.B_B else 65536


def default_profile() -> SignatureProfile:
    """Hồ sơ mặc định: cao nhất mà cấu hình hiện tại đáp ứng được."""
    configured = os.environ.get("WEBSIGNER_PROFILE")
    if configured:
        return SignatureProfile(configured.upper())
    return SignatureProfile.B_LT if trust.tsa_url() else SignatureProfile.B_B


_FONT_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "C:/Windows/Fonts/arial.ttf",
)

# Nằm trong WEBSIGNER_DATA, không phải thư mục mã nguồn: trong container thư
# mục mã nguồn chỉ đọc, còn /data mới là volume ghi được.
FONT_CACHE_DIR = DATA_DIR / ".fontcache"


class SigningError(RuntimeError):
    """Lỗi nghiệp vụ khi ký — trả về client dưới dạng 4xx."""


def find_font() -> str | None:
    """Font có glyph tiếng Việt cho hình chữ ký. None -> dùng font chuẩn PDF."""
    override = os.environ.get("WEBSIGNER_FONT")
    candidates = (override, *_FONT_CANDIDATES) if override else _FONT_CANDIDATES
    for path in candidates:
        if path and pathlib.Path(path).is_file():
            return normalize_upem(path)
    return None


def normalize_upem(font_path: str) -> str:
    """Trả về font có ``unitsPerEm == 1000``, scale lại nếu cần.

    pyHanko ghi mảng ``/W`` của CIDFont bằng đơn vị gốc của font thay vì
    1/1000 em như PDF quy định. Với font 2048 upem (Arial Unicode MS,
    DejaVu Sans, Times New Roman...) mọi glyph rộng gấp đôi nên chữ trong
    hình chữ ký bị giãn và tràn khỏi khung. Scale font về 1000 upem làm hai
    đơn vị trùng nhau, nên ``/W`` thành đúng.

    Bản đã scale được cache theo (đường dẫn, kích thước, mtime).
    """
    from fontTools.ttLib import TTFont
    from fontTools.ttLib.scaleUpem import scale_upem

    source = pathlib.Path(font_path)
    stat = source.stat()
    cache_key = hashlib.sha1(
        f"{source.resolve()}:{stat.st_size}:{stat.st_mtime_ns}".encode()
    ).hexdigest()[:16]
    cached = FONT_CACHE_DIR / f"{source.stem}-{cache_key}-upem1000.ttf"
    if cached.is_file():
        return str(cached)

    font = TTFont(str(source))
    if font["head"].unitsPerEm == 1000:
        return str(source)

    scale_upem(font, 1000)

    # Bytecode hinting được viết cho unitsPerEm cũ. Giữ lại thì ở cỡ chữ nhỏ
    # nó bóp méo theo lưới sai và nuốt mất các nét nhỏ — dấu chấm trên chữ
    # "i" và nửa trên của dấu ":" biến mất. Bỏ hinting, dùng outline thô.
    for table in ("fpgm", "prep", "cvt ", "gasp"):
        if table in font:
            del font[table]
    if "glyf" in font:
        glyf = font["glyf"]
        for name in glyf.keys():
            glyph = glyf[name]
            # Xoá hẳn thuộc tính thì fontTools không biên dịch lại được;
            # phải giữ nguyên và gán bytecode rỗng.
            if hasattr(glyph, "program"):
                glyph.program.fromBytecode(b"")
    FONT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = cached.with_suffix(".tmp")
    font.save(str(tmp))
    tmp.replace(cached)  # đổi tên nguyên tử: tránh đọc file đang ghi dở
    return str(cached)


@dataclass(frozen=True)
class SignatureAppearance:
    """Vị trí và nội dung hiển thị của chữ ký trên trang."""

    page: int  # 0-based
    box: tuple[float, float, float, float]  # (x1, y1, x2, y2), gốc dưới-trái
    reason: str | None = None
    location: str | None = None
    logo: bytes | None = None  # PNG/JPEG vẽ bên trái hình chữ ký
    color: str = "xanh-duong"
    show_border: bool = False


@dataclass
class PreparedSignature:
    """Kết quả pha 1 — đủ để nối lại pha 2 sau khi agent trả chữ ký.

    Giữ luôn ``PdfTBSDocument`` và luồng ghi của pyHanko thay vì chuỗi byte:
    chúng mang theo chỉ dẫn hậu ký (DSS, dấu thời gian tài liệu) cần cho
    B-LT/B-LTA. Hệ quả: hai pha phải nằm trong cùng một tiến trình, đúng như
    cách ``api_sign`` điều phối.
    """

    field_name: str
    algo: SigAlgo
    profile: SignatureProfile
    signed_attrs_der: bytes
    document_digest: bytes
    algo_params: dict[str, Any] = field(default_factory=dict)

    _prepared_digest: Any = field(repr=False, default=None)
    _tbs_document: Any = field(repr=False, default=None)
    _output: IO | None = field(repr=False, default=None)
    _timestamper: HTTPTimeStamper | None = field(repr=False, default=None)
    _signing_context: Any = field(repr=False, default=None)

    @property
    def tbs_digest(self) -> bytes:
        """32 byte mà USB token thực sự phải ký (SHA-256 của signed attrs)."""
        return hashlib.sha256(self.signed_attrs_der).digest()


def load_cert_chain(
    cert_der: bytes, chain_der: Sequence[bytes]
) -> tuple[asn1_x509.Certificate, SimpleCertificateStore]:
    signing_cert = asn1_x509.Certificate.load(cert_der)
    registry = SimpleCertificateStore()
    registry.register_multiple(asn1_x509.Certificate.load(c) for c in chain_der)
    return signing_cert, registry


def subject_cn(cert: asn1_x509.Certificate) -> str:
    native = cert.subject.native
    return str(native.get("common_name") or cert.subject.human_friendly)


def subject_tax_code(cert: asn1_x509.Certificate) -> str | None:
    """MST thường nằm ở OU dạng ``MST:0101234567`` trong chứng thư VN."""
    value = cert.subject.native.get("organizational_unit_name")
    values = value if isinstance(value, list) else [value]
    for item in values:
        if isinstance(item, str) and item.upper().startswith("MST:"):
            return item.split(":", 1)[1].strip()
    return None


# Bảng màu quen thuộc trên chữ ký số VN. Mặc định xanh dương đậm.
STAMP_COLORS: dict[str, tuple[float, float, float]] = {
    "xanh-duong": (0.08, 0.22, 0.48),
    "xanh-la": (0.11, 0.48, 0.24),
    "do": (0.63, 0.11, 0.11),
    "den": (0.0, 0.0, 0.0),
}
DEFAULT_STAMP_COLOR = "xanh-duong"


def _logo_content(logo_png: bytes):
    """Logo/con dấu vẽ bên trái hình chữ ký."""
    from PIL import Image
    from pyhanko.pdf_utils.images import PdfImage

    image = Image.open(io.BytesIO(logo_png))
    image.load()
    return PdfImage(image)


def _stamp_style(
    lines: Sequence[str], appearance: "SignatureAppearance"
) -> TextStampStyle:
    """Bố cục theo thông lệ chữ ký số VN: logo bên trái, chữ bên phải."""
    font_path = find_font()
    font_size = 7
    color = STAMP_COLORS.get(appearance.color, STAMP_COLORS[DEFAULT_STAMP_COLOR])
    if font_path:
        box_style = TextBoxStyle(
            font=GlyphAccumulatorFactory(font_path, font_size=font_size),
            font_size=font_size,
            text_color=color,
        )
    else:  # font chuẩn PDF, không có dấu tiếng Việt
        box_style = TextBoxStyle(font_size=font_size, text_color=color)

    height = abs(appearance.box[3] - appearance.box[1])
    logo = _logo_content(appearance.logo) if appearance.logo else None
    # Chừa bên trái đúng một ô vuông bằng chiều cao khung để đặt logo.
    text_left = int(height) + 4 if logo else 6

    return TextStampStyle(
        stamp_text="\n".join(lines),
        text_box_style=box_style,
        border_width=1 if appearance.show_border else 0,
        border_color=color,
        background=logo,
        background_opacity=1.0,
        background_layout=SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MIN,
            y_align=AxisAlignment.ALIGN_MID,
            margins=Margins(left=2, right=0, top=2, bottom=2),
            inner_content_scaling=InnerScaling.SHRINK_TO_FIT,
        ),
        inner_content_layout=SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MIN,
            y_align=AxisAlignment.ALIGN_MID,
            margins=Margins(left=text_left, right=3, top=2, bottom=2),
            inner_content_scaling=InnerScaling.SHRINK_TO_FIT,
        ),
        # %z cho ra +0700, đúng kiểu Adobe hiển thị trên chữ ký VN
        timestamp_format="%d/%m/%Y %H:%M:%S %z",
    )


def _appearance_lines(
    cert: asn1_x509.Certificate, appearance: SignatureAppearance
) -> tuple[list[str], dict[str, str]]:
    """Nhãn song ngữ giống chữ ký của các CA công cộng VN."""
    params: dict[str, str] = {"cn": subject_cn(cert)}
    lines = ["Digitally signed by/Ký bởi: %(cn)s"]

    mst = subject_tax_code(cert)
    if mst:
        params["mst"] = mst
        lines.append("Tax code/MST: %(mst)s")

    lines.append("Signing date/Ngày ký: %(ts)s")

    if appearance.reason:
        params["reason"] = appearance.reason
        lines.append("Reason/Lý do: %(reason)s")
    if appearance.location:
        params["location"] = appearance.location
        lines.append("Location/Nơi ký: %(location)s")

    return lines, params


def signature_algorithm(cert: asn1_x509.Certificate) -> SigAlgo:
    """Thuật toán ký suy ra từ khoá công khai trong chứng thư."""
    algorithm = cert.public_key.algorithm
    if algorithm == "ec":
        return SigAlgo.ECDSA_SHA256
    if algorithm == "rsa":
        return SigAlgo.RSA_PSS_SHA256 if PREFER_PSS else SigAlgo.RSA_PKCS1_SHA256
    raise SigningError(f"Chưa hỗ trợ khoá loại {algorithm!r}")


def _check_signature_value(
    cert: asn1_x509.Certificate, algo: SigAlgo, value: bytes
) -> None:
    if algo is SigAlgo.ECDSA_SHA256:
        # DER SEQUENCE{r,s}: độ dài thay đổi, chỉ kiểm tra khung ngoài
        if not value.startswith(b"\x30") or not 8 <= len(value) <= 144:
            raise SigningError("Chữ ký ECDSA không phải DER SEQUENCE hợp lệ")
        return
    expected = cert.public_key.byte_size
    if len(value) != expected:
        raise SigningError(
            f"Chữ ký dài {len(value)} byte, chứng thư yêu cầu {expected} byte"
        )


def _external_signer(
    signing_cert: asn1_x509.Certificate,
    registry: SimpleCertificateStore,
    algo: SigAlgo,
    signature_value: bytes,
) -> ExternalSigner:
    return ExternalSigner(
        signing_cert=signing_cert,
        cert_registry=registry,
        signature_value=signature_value,
        prefer_pss=algo is SigAlgo.RSA_PSS_SHA256,
    )


def _algo_params(signer: ExternalSigner, algo: SigAlgo) -> dict[str, Any]:
    """Tham số thuật toán mà agent phải dùng y hệt.

    Với RSA-PSS, pyHanko khai salt dài tối đa (``k - hLen - 2``, tức 222 byte
    với khoá 2048) chứ không phải 32. Agent đoán sai salt thì chữ ký không
    verify được, dù token đã ký bằng đúng khoá.
    """
    if algo is not SigAlgo.RSA_PSS_SHA256:
        return {}
    mechanism = signer.get_signature_mechanism_for_digest(MD_ALGORITHM)
    return {"salt_length": int(mechanism["parameters"]["salt_length"].native)}


def _timestamper(profile: SignatureProfile) -> HTTPTimeStamper | None:
    if profile is SignatureProfile.B_B:
        return None
    url = trust.tsa_url()
    if not url:
        raise SigningError(
            f"Hồ sơ {profile.value} cần đóng dấu thời gian, "
            "nhưng chưa đặt WEBSIGNER_TSA_URL"
        )
    return HTTPTimeStamper(url, timeout=15)


def has_hybrid_xrefs(pdf_bytes: bytes) -> bool:
    """Tệp có dùng hybrid cross-reference không.

    Đây là cơ chế tương thích ngược của PDF 1.5: một bảng xref cổ điển cộng
    thêm ``/XRefStm`` trỏ tới xref stream chứa phần còn lại. Word, Excel và
    nhiều máy in PDF đời cũ vẫn sinh ra kiểu này.
    """
    return PdfFileReader(io.BytesIO(pdf_bytes), strict=True).xrefs.hybrid_xrefs_present


def incremental_writer(pdf_bytes: bytes) -> IncrementalPdfFileWriter:
    """Writer để ký thêm một revision.

    pyHanko ở chế độ strict từ chối ký tệp hybrid vì hai bảng tham chiếu có
    thể mâu thuẫn nhau. Nới strict cho **đúng những tệp đó**, không nới cho
    mọi tệp — nếu không sẽ mất luôn các kiểm tra cấu trúc khác.
    """
    hybrid = has_hybrid_xrefs(pdf_bytes)
    if hybrid:
        logger.warning("Tệp dùng hybrid cross-reference; nới strict để ký được")
    return IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=not hybrid)


async def prepare(
    pdf_bytes: bytes,
    cert_der: bytes,
    chain_der: Sequence[bytes],
    appearance: SignatureAppearance,
    field_name: str,
    profile: SignatureProfile = SignatureProfile.B_B,
) -> PreparedSignature:
    """Pha 1: chèn placeholder, băm ByteRange, dựng signed attributes.

    Với hồ sơ B-LT/B-LTA, pha này còn thu thập CRL/OCSP của chuỗi chứng thư để
    nhúng vào DSS ở pha 2 — nên chứng thư bị thu hồi sẽ bị chặn ngay tại đây,
    trước khi token được yêu cầu ký.
    """
    signing_cert, registry = load_cert_chain(cert_der, chain_der)
    algo = signature_algorithm(signing_cert)

    # signature_value giả chỉ để pyHanko ước lượng kích thước khi dựng CMS;
    # giá trị thật được gắn ở pha 2.
    external_signer = _external_signer(
        signing_cert, registry, algo, bytes(signing_cert.public_key.byte_size)
    )

    timestamper = _timestamper(profile)
    embed_revinfo = profile in (SignatureProfile.B_LT, SignatureProfile.B_LTA)
    # Giữ lại để đóng ở pha 2: context này sở hữu một phiên aiohttp dùng tải
    # CRL/OCSP; không đóng là rò kết nối mỗi lần ký.
    signing_context = (
        trust.validation_context(allow_fetching=True, revocation_mode="hard-fail")
        if embed_revinfo
        else None
    )

    lines, text_params = _appearance_lines(signing_cert, appearance)
    pdf_signer = PdfSigner(
        PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm=MD_ALGORITHM,
            subfilter=fields.SigSeedSubFilter.PADES,
            reason=appearance.reason or None,
            location=appearance.location or None,
            validation_context=signing_context,
            embed_validation_info=embed_revinfo,
            use_pades_lta=profile is SignatureProfile.B_LTA,
        ),
        signer=external_signer,
        timestamper=timestamper,
        new_field_spec=fields.SigFieldSpec(
            sig_field_name=field_name,
            on_page=appearance.page,
            box=appearance.box,
        ),
        stamp_style=_stamp_style(lines, appearance),
    )

    writer = incremental_writer(pdf_bytes)
    try:
        prepared_digest, tbs_document, output = (
            await pdf_signer.async_digest_doc_for_signing(
                writer,
                bytes_reserved=_bytes_reserved(profile),
                appearance_text_params=text_params,
                output=io.BytesIO(),
            )
        )
    except PyHankoSigningError as exc:
        # Thu hồi chứng thư, thiếu CRL, TSA chết... đều rơi vào đây.
        await close_signing_context(signing_context)
        raise SigningError(str(exc)) from exc

    signed_attrs = await external_signer.signed_attrs(
        prepared_digest.document_digest,
        MD_ALGORITHM,
        use_pades=True,
        timestamper=timestamper,
    )

    return PreparedSignature(
        field_name=field_name,
        algo=algo,
        profile=profile,
        signed_attrs_der=signed_attrs.dump(),
        document_digest=prepared_digest.document_digest,
        algo_params=_algo_params(external_signer, algo),
        _prepared_digest=prepared_digest,
        _tbs_document=tbs_document,
        _output=output,
        _timestamper=timestamper,
        _signing_context=signing_context,
    )


async def close_signing_context(context) -> None:
    """Đóng phiên HTTP mà ValidationContext mở để tải CRL/OCSP."""
    if context is not None:
        await context.aclose()


async def finalize(
    prepared: PreparedSignature,
    cert_der: bytes,
    chain_der: Sequence[bytes],
    signature_value: bytes,
) -> bytes:
    """Pha 2: dựng CMS từ chữ ký thô của token và nhúng vào chỗ đã chừa.

    Dấu thời gian chữ ký (B-T) và DSS chứa CRL/OCSP (B-LT) được thêm ở đây —
    token không phải ký thêm lần nào.
    """
    signing_cert, registry = load_cert_chain(cert_der, chain_der)
    _check_signature_value(signing_cert, prepared.algo, signature_value)

    external_signer = _external_signer(
        signing_cert, registry, prepared.algo, signature_value
    )
    try:
        signature_cms = await external_signer.async_sign_prescribed_attributes(
            MD_ALGORITHM,
            signed_attrs=asn1_cms.CMSAttributes.load(prepared.signed_attrs_der),
            timestamper=prepared._timestamper,
        )

        tbs_document = prepared._tbs_document
        await PdfTBSDocument.async_finish_signing(
            prepared._output,
            prepared_digest=prepared._prepared_digest,
            signature_cms=signature_cms,
            post_sign_instr=tbs_document.post_sign_instructions,
            validation_context=tbs_document.validation_context,
        )
    except PyHankoSigningError as exc:
        raise SigningError(str(exc)) from exc
    finally:
        await close_signing_context(prepared._signing_context)

    prepared._output.seek(0)
    return prepared._output.read()
