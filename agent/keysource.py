"""Giao diện chung cho mọi nguồn khoá của agent.

Mỗi nguồn khoá chỉ phải làm hai việc: liệt kê chứng thư, và ký một khối byte
bằng thuật toán server chỉ định. Không nguồn nào biết PDF là gì.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from cryptography.x509 import Certificate, load_der_x509_certificate


class SigAlgo(str, Enum):
    """Thuật toán ký. Server chọn dựa trên khoá công khai trong chứng thư."""

    RSA_PKCS1_SHA256 = "rsa_pkcs1v15_sha256"
    RSA_PSS_SHA256 = "rsa_pss_sha256"
    ECDSA_SHA256 = "ecdsa_sha256"

    @property
    def is_rsa(self) -> bool:
        return self in (SigAlgo.RSA_PKCS1_SHA256, SigAlgo.RSA_PSS_SHA256)


class KeySourceError(RuntimeError):
    """Lỗi khi mở nguồn khoá hoặc khi ký."""


def rfc4514_cn(dn: str) -> str:
    for part in dn.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:]
    return dn


def cert_id_for(der: bytes) -> str:
    """Định danh ổn định của chứng thư, dùng chung giữa browser và agent."""
    return hashlib.sha1(der).hexdigest()[:16]


def pss_salt_length(params: dict[str, Any] | None) -> int:
    """Độ dài salt cho RSA-PSS, do server quyết định.

    pyHanko khai salt dài tối đa (``k - hLen - 2``) chứ không phải 32 byte.
    Đoán sai là chữ ký không verify được dù khoá đúng — nên thiếu tham số thì
    từ chối ký, không mặc định.
    """
    value = (params or {}).get("salt_length")
    if value is None:
        raise KeySourceError("Server không gửi salt_length cho RSA-PSS")
    return int(value)


def ecdsa_raw_to_der(raw: bytes) -> bytes:
    """Chuyển chữ ký ECDSA dạng r||s (PKCS#11, CNG) sang DER cho CMS.

    PKCS#11 ``CKM_ECDSA*`` và ``NCryptSignHash`` trả về hai số nguyên r, s
    nối nhau với độ dài cố định. CMS lại yêu cầu ``SEQUENCE { r, s }`` dạng
    DER, nên phải chuyển.
    """
    if len(raw) % 2:
        raise KeySourceError(f"Chữ ký ECDSA dài lẻ ({len(raw)} byte)")
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")

    def encode_int(value: int) -> bytes:
        body = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
        return b"\x02" + bytes([len(body)]) + body

    payload = encode_int(r) + encode_int(s)
    if len(payload) > 127:
        length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
        return b"\x30" + bytes([0x80 | len(length)]) + length + payload
    return b"\x30" + bytes([len(payload)]) + payload


@dataclass(frozen=True)
class CertEntry:
    """Một chứng thư có khoá riêng dùng được trên nguồn khoá này."""

    cert_id: str
    cert_der: bytes
    chain_der: list[bytes]

    @classmethod
    def build(cls, cert_der: bytes, chain_der: list[bytes]) -> "CertEntry":
        chain = [cert_der] + [c for c in chain_der if c != cert_der]
        return cls(cert_id_for(cert_der), cert_der, chain)

    @property
    def cert(self) -> Certificate:
        return load_der_x509_certificate(self.cert_der)

    def describe(self) -> dict:
        cert = self.cert
        return {
            "id": self.cert_id,
            "subject": rfc4514_cn(cert.subject.rfc4514_string()),
            "subject_full": cert.subject.rfc4514_string(),
            "issuer": rfc4514_cn(cert.issuer.rfc4514_string()),
            "serial": format(cert.serial_number, "x"),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "cert_b64": base64.b64encode(self.cert_der).decode(),
            "chain_b64": [base64.b64encode(c).decode() for c in self.chain_der],
        }


@runtime_checkable
class KeySource(Protocol):
    label: str

    def certificates(self) -> list[CertEntry]:
        """Mọi chứng thư có khoá riêng tương ứng trên thiết bị."""

    def sign(
        self, cert_id: str, data: bytes, algo: SigAlgo, params: dict[str, Any]
    ) -> bytes:
        """Ký ``data`` (chưa băm) bằng ``algo``.

        ``params`` là tham số do server chỉ định; agent phải dùng y hệt, không
        được tự chọn. Hiện chỉ RSA-PSS cần: khoá ``salt_length``.

        Với ECDSA phải trả chữ ký DER, dùng :func:`ecdsa_raw_to_der` nếu thiết
        bị trả về r||s.
        """
