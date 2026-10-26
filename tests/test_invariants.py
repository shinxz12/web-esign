"""Bất biến dễ hỏng âm thầm mà không làm chữ ký báo lỗi ngay.

Ba nhóm ở đây đều từng là nguồn lỗi thật trong dự án này.
"""

from __future__ import annotations

import pathlib
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "agent"))

from app import store, trust  # noqa: E402
from keysource import KeySourceError, ecdsa_raw_to_der, pss_salt_length  # noqa: E402


# --------------------------------------------------------------------------
# ECDSA: token trả r‖s, CMS cần DER
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "r, s",
    [
        (1, 1),
        (0xFF, 0xFF),  # bit cao bật -> DER phải chèn byte 0x00
        (0x7F, 0x80),
        (2**255 - 1, 2**255 - 1),
        (2**256 - 1, 2**256 - 1),  # tối đa P-256, cả hai cần đệm
        (0x00112233, 0x44556677),  # số nhỏ, không được cắt mất byte 0 đầu
    ],
)
def test_ecdsa_der_khop_voi_chuan(r: int, s: int) -> None:
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert ecdsa_raw_to_der(raw) == encode_dss_signature(r, s)
    assert decode_dss_signature(ecdsa_raw_to_der(raw)) == (r, s)


def test_ecdsa_do_dai_le_bi_tu_choi() -> None:
    with pytest.raises(KeySourceError):
        ecdsa_raw_to_der(b"\x01" * 65)


def test_ecdsa_p521_dung_dang_dai_hon_127_byte() -> None:
    r = s = 2**521 - 1
    raw = r.to_bytes(66, "big") + s.to_bytes(66, "big")
    der = ecdsa_raw_to_der(raw)
    assert der == encode_dss_signature(r, s)
    assert der[1] == 0x81  # dạng độ dài dài, 1 byte


# --------------------------------------------------------------------------
# RSA-PSS: salt do server quyết định, agent không được đoán
# --------------------------------------------------------------------------


def test_thieu_salt_thi_tu_choi_ky() -> None:
    with pytest.raises(KeySourceError):
        pss_salt_length({})


def test_salt_lay_dung_gia_tri_server_gui() -> None:
    assert pss_salt_length({"salt_length": 222}) == 222


# --------------------------------------------------------------------------
# Luồng ký: ai được ký, lượt nào
# --------------------------------------------------------------------------


def slot(order: int, name: str, tax_code: str | None = None) -> store.SignerSlot:
    return store.SignerSlot(
        order=order, name=name, tax_code=tax_code, invite_token=f"tok{order}"
    )


def test_mst_quyet_dinh_khi_duoc_khai_bao() -> None:
    s = slot(0, "Nguyễn Văn A", "0101234567")
    assert s.accepts("CONG TY KHAC HOAN TOAN", "0101234567")
    assert not s.accepts("NGUYEN VAN A", "0107654321")
    assert not s.accepts("NGUYEN VAN A", None)


def test_khong_co_mst_thi_so_ten_bo_dau() -> None:
    s = slot(0, "Nguyễn Văn A")
    assert s.accepts("NGUYEN VAN A", None)
    assert s.accepts("nguyen  van   a", None)
    assert not s.accepts("NGUYEN VAN B", None)


def doc(*slots: store.SignerSlot) -> store.DocumentMeta:
    return store.DocumentMeta(
        id="a" * 16, name="x.pdf", created_at="2026-01-01T00:00:00+00:00",
        owner_token="owner", signers=list(slots),
    )


def test_trang_thai_chay_theo_dung_thu_tu() -> None:
    a, b = slot(0, "A", "1"), slot(1, "B", "2")
    d = doc(a, b)
    assert d.status == "chua_bat_dau"
    assert d.next_slot is a

    a.signed_at = "2026-01-01T00:00:00+00:00"
    assert d.status == "cho_ky"
    assert d.next_slot is b

    b.signed_at = "2026-01-01T00:01:00+00:00"
    assert d.status == "hoan_tat"
    assert d.next_slot is None


def test_khong_khai_luong_thi_ky_tu_do() -> None:
    assert doc().status == "tu_do"


def test_lien_ket_sai_bi_tu_choi() -> None:
    d = doc(slot(0, "A", "1"))
    assert d.slot_for_invite("tok0").order == 0
    with pytest.raises(store.WorkflowError):
        d.slot_for_invite("tok-khong-ton-tai")


def test_to_dict_khong_lo_bi_mat() -> None:
    d = doc(slot(0, "A", "1"))
    public = d.to_dict()
    assert "owner_token" not in public
    assert "invite_token" not in public["signers"][0]
    assert "invite_token" in d.to_dict(redact_invites=False)["signers"][0]


# --------------------------------------------------------------------------
# Trust store: leaf lọt vào là mọi kiểm tra thu hồi bị vô hiệu
# --------------------------------------------------------------------------


def test_chi_nhan_chung_thu_ca_lam_trust_anchor(tmp_path: pathlib.Path) -> None:
    certs = ROOT / "data" / "certs"
    if not (certs / "ca.crt").is_file():
        pytest.skip("chưa chạy scripts/make_test_certs.sh")

    (tmp_path / "ca.crt").write_bytes((certs / "ca.crt").read_bytes())
    (tmp_path / "leaf.crt").write_bytes((certs / "signer-a.crt").read_bytes())

    material = trust.load_trust_material(tmp_path)
    assert [c.subject.native["common_name"] for c in material.roots] == [
        "DEMO-CA Root (TEST ONLY)"
    ]
    assert material.intermediates == []  # leaf không được lọt vào đâu cả


def test_ca_trung_gian_khong_tu_lam_trust_anchor() -> None:
    """CA do CA khác cấp chỉ để nối chuỗi, không phải gốc tin cậy."""
    seed = ROOT / "trust"
    if not seed.is_dir():
        pytest.skip("không có thư mục trust/ mặc định")

    material = trust.load_trust_material(seed)
    roots = {c.subject.native["common_name"] for c in material.roots}
    assert roots == {"MIC National Root CA", "Vietnam National Root CA"}
    assert all(c.subject != c.issuer for c in material.intermediates)
    assert {c.subject.native["common_name"] for c in material.intermediates} == {
        "Viettel-CA",
        "Viettel-CA RS",
    }


def test_doc_duoc_ca_pem_lan_der(tmp_path: pathlib.Path) -> None:
    """Thư mục trust thật trộn cả hai định dạng và đuôi .cer lẫn .crt."""
    seed = ROOT / "trust"
    if not seed.is_dir():
        pytest.skip("không có thư mục trust/ mặc định")
    material = trust.load_trust_material(seed)
    assert len(material.roots) + len(material.intermediates) == 5


def test_nap_mac_dinh_chi_khi_thu_muc_con_rong(tmp_path: pathlib.Path) -> None:
    if not (ROOT / "trust").is_dir():
        pytest.skip("không có thư mục trust/ mặc định")

    target = tmp_path / "trust"
    assert trust.seed_trust_store(target) == 5
    assert trust.seed_trust_store(target) == 0  # không ghi đè lần hai

    # người vận hành xoá bớt rồi khởi động lại: không bị nạp lại
    for path in list(target.iterdir())[:3]:
        path.unlink()
    assert trust.seed_trust_store(target) == 0
    assert len(list(target.iterdir())) == 2
