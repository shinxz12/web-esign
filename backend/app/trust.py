"""Trust anchor và ngữ cảnh kiểm tra thu hồi, dùng chung cho ký và xác thực."""

from __future__ import annotations

import logging
import os
import pathlib
import shutil
from dataclasses import dataclass

from asn1crypto import pem
from asn1crypto import x509 as asn1_x509
from pyhanko_certvalidator import ValidationContext

from .store import DATA_DIR, REPO_ROOT

logger = logging.getLogger("websigner.trust")

# Chỉ thư mục này mới là trust anchor. KHÔNG trỏ vào nơi chứa chứng thư người
# ký: một leaf nằm trong trust store sẽ tự làm anchor cho chính nó, chuỗi dài
# 1, và mọi kiểm tra thu hồi bị bỏ qua — chữ ký thu hồi vẫn báo hợp lệ.
TRUST_DIR = pathlib.Path(
    os.environ.get("WEBSIGNER_TRUST_DIR", DATA_DIR / "trust")
).resolve()


# Chứng thư CA mặc định đóng kèm ảnh triển khai. Lần chạy đầu, nếu thư mục
# trust còn rỗng thì chép vào — sau đó người vận hành toàn quyền thêm/bớt.
TRUST_SEED_DIR = pathlib.Path(
    os.environ.get("WEBSIGNER_TRUST_SEED", REPO_ROOT / "trust")
)

CERT_SUFFIXES = (".crt", ".cer", ".pem", ".der")


@dataclass(frozen=True)
class TrustMaterial:
    """Trust anchor và các CA trung gian giúp dựng chuỗi."""

    roots: list[asn1_x509.Certificate]
    intermediates: list[asn1_x509.Certificate]


def _is_ca(cert: asn1_x509.Certificate) -> bool:
    return bool(cert.basic_constraints_value and cert.basic_constraints_value["ca"])


def _is_self_signed(cert: asn1_x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def _read_certs(path: pathlib.Path) -> list[asn1_x509.Certificate]:
    """Đọc tệp PEM (một hoặc nhiều) hoặc DER. Đuôi tệp không quyết định gì."""
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        return [
            asn1_x509.Certificate.load(der)
            for _, _, der in pem.unarmor(data, multiple=True)
        ]
    return [asn1_x509.Certificate.load(data)]


def seed_trust_store(trust_dir: pathlib.Path | None = None) -> int:
    """Chép chứng thư CA mặc định vào thư mục trust nếu nó còn rỗng."""
    target = trust_dir or TRUST_DIR
    if not TRUST_SEED_DIR.is_dir():
        return 0
    target.mkdir(parents=True, exist_ok=True)
    if any(p.suffix.lower() in CERT_SUFFIXES for p in target.iterdir()):
        return 0
    copied = 0
    for path in sorted(TRUST_SEED_DIR.iterdir()):
        if path.suffix.lower() in CERT_SUFFIXES:
            shutil.copyfile(path, target / path.name)
            copied += 1
    if copied:
        logger.info("Nạp %d chứng thư CA mặc định vào %s", copied, target)
    return copied


def load_trust_material(trust_dir: pathlib.Path | None = None) -> TrustMaterial:
    """Phân loại chứng thư trong thư mục trust.

    CA tự ký -> trust anchor. CA do CA khác cấp -> trung gian, chỉ dùng để nối
    chuỗi chứ không tự làm gốc tin cậy. Chứng thư không phải CA bị bỏ qua kèm
    cảnh báo: để một leaf lọt vào đây là nó tự làm anchor cho chính mình,
    chuỗi dài 1, không ai kiểm tra thu hồi.
    """
    directory = trust_dir or TRUST_DIR
    roots: list[asn1_x509.Certificate] = []
    intermediates: list[asn1_x509.Certificate] = []
    if not directory.is_dir():
        logger.warning(
            "Không có thư mục trust %s — mọi chữ ký sẽ không tin cậy", directory
        )
        return TrustMaterial(roots, intermediates)

    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in CERT_SUFFIXES:
            continue
        try:
            certs = _read_certs(path)
        except Exception as exc:
            logger.warning("Không đọc được %s: %s", path.name, exc)
            continue
        for cert in certs:
            if not _is_ca(cert):
                logger.warning("Bỏ qua %s: không phải chứng thư CA", path.name)
            elif _is_self_signed(cert):
                roots.append(cert)
            else:
                intermediates.append(cert)
    return TrustMaterial(roots, intermediates)


def load_trust_roots(
    trust_dir: pathlib.Path | None = None,
) -> list[asn1_x509.Certificate]:
    return load_trust_material(trust_dir).roots


def validation_context_kwargs(
    *,
    allow_fetching: bool,
    revocation_mode: str,
    trust_dir: pathlib.Path | None = None,
) -> dict:
    material = load_trust_material(trust_dir)
    return {
        "trust_roots": material.roots,
        "other_certs": material.intermediates,
        "allow_fetching": allow_fetching,
        "revocation_mode": revocation_mode,
        "weak_hash_algos": set(),
    }


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
        **validation_context_kwargs(
            allow_fetching=allow_fetching,
            revocation_mode=revocation_mode,
            trust_dir=trust_dir,
        )
    )


def tsa_url() -> str | None:
    """URL của TSA. Chưa đặt nghĩa là không đóng dấu thời gian."""
    return os.environ.get("WEBSIGNER_TSA_URL") or None
