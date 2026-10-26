"""Trust anchor và ngữ cảnh kiểm tra thu hồi, dùng chung cho ký và xác thực."""

from __future__ import annotations

import logging
import os
import pathlib

from asn1crypto import pem
from asn1crypto import x509 as asn1_x509
from pyhanko_certvalidator import ValidationContext

from .store import DATA_DIR

logger = logging.getLogger("websigner.trust")

# Chỉ thư mục này mới là trust anchor. KHÔNG trỏ vào nơi chứa chứng thư người
# ký: một leaf nằm trong trust store sẽ tự làm anchor cho chính nó, chuỗi dài
# 1, và mọi kiểm tra thu hồi bị bỏ qua — chữ ký thu hồi vẫn báo hợp lệ.
TRUST_DIR = pathlib.Path(
    os.environ.get("WEBSIGNER_TRUST_DIR", DATA_DIR / "trust")
).resolve()


def _is_ca(cert: asn1_x509.Certificate) -> bool:
    return bool(cert.basic_constraints_value and cert.basic_constraints_value["ca"])


def load_trust_roots(
    trust_dir: pathlib.Path | None = None,
) -> list[asn1_x509.Certificate]:
    """Mọi chứng thư CA trong thư mục trust là một trust anchor.

    Chứng thư không phải CA bị bỏ qua kèm cảnh báo — đó gần như luôn là lỗi
    cấu hình chứ không phải ý đồ.

    Production thay bằng danh sách root của các CA công cộng được NEAC cấp phép.
    """
    directory = trust_dir or TRUST_DIR
    roots: list[asn1_x509.Certificate] = []
    if not directory.is_dir():
        logger.warning("Không có thư mục trust %s — mọi chữ ký sẽ không tin cậy", directory)
        return roots

    for path in sorted(directory.glob("*.crt")):
        data = path.read_bytes()
        if data.lstrip().startswith(b"-----BEGIN"):
            candidates = [
                asn1_x509.Certificate.load(der)
                for _, _, der in pem.unarmor(data, multiple=True)
            ]
        else:
            candidates = [asn1_x509.Certificate.load(data)]
        for cert in candidates:
            if _is_ca(cert):
                roots.append(cert)
            else:
                logger.warning("Bỏ qua %s: không phải chứng thư CA", path.name)
    return roots


def validation_context(
    *,
    allow_fetching: bool,
    revocation_mode: str,
    trust_dir: pathlib.Path | None = None,
) -> ValidationContext:
    """
    :param allow_fetching:
        cho phép tải CRL/OCSP qua mạng. Bật khi thu thập dữ liệu nhúng vào DSS
        lúc ký; tắt khi xác thực lại để kết quả chỉ dựa trên dữ liệu trong tệp.
    :param revocation_mode:
        ``hard-fail`` khi ký LTV (thiếu bằng chứng thu hồi là từ chối ký),
        ``soft-fail`` khi xác thực tệp cũ.
    """
    return ValidationContext(
        trust_roots=load_trust_roots(trust_dir),
        allow_fetching=allow_fetching,
        revocation_mode=revocation_mode,
        weak_hash_algos=set(),
    )


def tsa_url() -> str | None:
    """URL của TSA. Chưa đặt nghĩa là không đóng dấu thời gian."""
    return os.environ.get("WEBSIGNER_TSA_URL") or None
