"""Bất biến dễ hỏng âm thầm mà không làm chữ ký hay API báo lỗi ngay.

Chạy không cần server hay cơ sở dữ liệu.
"""

from __future__ import annotations

import asyncio
import pathlib
import shutil
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "agent"))

from app import audit, config, documents, plans, security, signing, trust, webhooks  # noqa: E402
from app.errors import ApiError  # noqa: E402
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


def recipient(order: int, name: str, tax_code: str | None = None) -> dict:
    return {"id": f"rcp_{name}", "routing_order": order, "name": name, "tax_code": tax_code,
            "status": "pending", "role": "signer"}


def in_progress(expires_at: datetime | None = None) -> dict:
    return {"status": "in_progress", "expires_at": expires_at}


def test_mst_quyet_dinh_khi_duoc_khai_bao() -> None:
    r = recipient(1, "Nguyễn Văn A", "0101234567")
    assert documents.identity_matches(r, "CONG TY KHAC HOAN TOAN", "0101234567")
    assert not documents.identity_matches(r, "NGUYEN VAN A", "0107654321")
    assert not documents.identity_matches(r, "NGUYEN VAN A", None)


def test_khong_co_mst_thi_so_ten_bo_dau_ca_chu_d() -> None:
    # "Đ" không tách thành D + dấu khi chuẩn hoá NFD: phải xử lý riêng.
    r = recipient(1, "Đặng Văn Đức")
    assert documents.identity_matches(r, "DANG VAN DUC", None)
    assert documents.identity_matches(r, "dang  van   duc", None)
    assert not documents.identity_matches(r, "DANG VAN DUNG", None)


def test_cung_so_thu_tu_thi_ky_song_song_nhom_sau_doi_nhom_truoc() -> None:
    a, b, c = recipient(1, "A"), recipient(2, "B"), recipient(2, "C")
    everyone, doc = [a, b, c], in_progress()
    assert documents.turn(doc, a, everyone)["can_act"]
    assert documents.turn(doc, b, everyone) == {"can_act": False, "reason": "not_your_turn", "waiting_for": ["A"]}

    a["status"] = "approved"
    assert documents.turn(doc, b, everyone)["can_act"] and documents.turn(doc, c, everyone)["can_act"]

    c["status"] = "signed"
    assert documents.turn(doc, c, everyone)["reason"] == "already_acted"
    assert documents.turn(doc, b, everyone)["can_act"]
    assert documents.active_order(everyone) == 2


def test_qua_han_la_chan_ngay_ca_khi_worker_chua_quet() -> None:
    a = recipient(1, "A")
    expired = in_progress(datetime.now(timezone.utc) - timedelta(seconds=1))
    assert documents.turn(expired, a, [a])["reason"] == "document_expired"


def test_nguoi_duyet_khong_co_o_ky() -> None:
    with pytest.raises(ValueError):
        documents.RecipientSpec(name="Kế toán", role="approver", field={"page": 0, "box": [0, 0, 165, 90]})


# --------------------------------------------------------------------------
# Nhật ký kiểm toán: sửa, xoá, chèn đều làm đứt chuỗi
# --------------------------------------------------------------------------


def _chain(*payloads: str) -> list[dict]:
    rows, prev = [], None
    for seq, canonical in enumerate(payloads, start=1):
        digest = audit.chain_hash(prev, canonical)
        rows.append({"seq": seq, "canonical": canonical, "prev_hash": prev, "hash": digest})
        prev = digest
    return rows


def test_chuoi_bam_phat_hien_sua_xoa() -> None:
    rows = _chain('{"type":"created"}', '{"type":"signed","by":"A"}', '{"type":"completed"}')
    assert audit.verify_chain(rows) == (True, None)

    edited = [dict(r) for r in rows]
    edited[1]["canonical"] = '{"type":"signed","by":"KE GIAN"}'
    assert audit.verify_chain(edited) == (False, 2)

    # Sửa cả băm của dòng đó vẫn lộ ở dòng kế tiếp.
    edited[1]["hash"] = audit.chain_hash(edited[1]["prev_hash"], edited[1]["canonical"])
    assert audit.verify_chain(edited) == (False, 3)

    assert audit.verify_chain([rows[0], rows[2]]) == (False, 3)  # xoá dòng giữa


# --------------------------------------------------------------------------
# Webhook không được thành cửa SSRF vào mạng nội bộ
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/ws",  # không phải https
        "https://127.0.0.1/h",
        "https://10.0.0.5/h",
        "https://169.254.169.254/latest/meta-data",  # metadata đám mây
        "https://[::1]/h",
        "https://[::ffff:127.0.0.1]/h",  # IPv4 đội lốt IPv6
        "https://localhost/h",
        "https://user:pw@hooks.example.com/h",
    ],
)
def test_url_webhook_noi_bo_bi_tu_choi(url: str, monkeypatch) -> None:
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", False)
    with pytest.raises(ApiError):
        webhooks.validate_url(url)


def test_ten_mien_cong_cong_tro_ve_ip_noi_bo_bi_chan_luc_ket_noi(monkeypatch) -> None:
    """DNS rebinding: URL hợp lệ lúc đăng ký, lúc gửi lại trỏ vào mạng nội bộ."""
    from aiohttp.resolver import ThreadedResolver

    async def rebinding(self, host, port=0, family=0):
        return [{"hostname": host, "host": "10.1.2.3", "port": port, "family": 2, "proto": 0, "flags": 0}]

    monkeypatch.setattr(ThreadedResolver, "resolve", rebinding)
    assert webhooks.validate_url("https://hooks.example.com/ws") == "https://hooks.example.com/ws"

    async def resolve():
        return await webhooks.PublicOnlyResolver().resolve("hooks.example.com", 443)

    with pytest.raises(OSError):
        asyncio.run(resolve())


# --------------------------------------------------------------------------
# Mật khẩu, giới hạn tần suất, hạn mức
# --------------------------------------------------------------------------


def test_mat_khau_sai_mot_ky_tu_cung_bi_tu_choi() -> None:
    encoded = security.hash_password_sync("mat-khau-dai-123")
    assert security.verify_password_sync("mat-khau-dai-123", encoded)
    assert not security.verify_password_sync("mat-khau-dai-124", encoded)
    assert not security.verify_password_sync("mat-khau-dai-123", None)
    assert encoded != security.hash_password_sync("mat-khau-dai-123"), "phải có salt riêng"


def test_gioi_han_tan_suat_cho_phep_dot_bien_roi_chan() -> None:
    limiter = security.RateLimiter()
    results = [limiter.hit("k", per_minute=60, burst=3) for _ in range(4)]
    assert results[:3] == [None, None, None]
    assert results[3] is not None and 0 < results[3] <= 1.0


def test_thang_tinh_han_muc_theo_gio_viet_nam() -> None:
    # 17:30 UTC ngày 31/10 đã là 00:30 ngày 1/11 ở Việt Nam.
    assert plans.current_period(datetime(2026, 10, 31, 17, 30, tzinfo=timezone.utc)) == "2026-11"
    assert plans.current_period(datetime(2026, 10, 31, 16, 59, tzinfo=timezone.utc)) == "2026-10"


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


def test_them_ca_vao_trust_store_co_hieu_luc_khong_can_khoi_dong_lai(tmp_path: pathlib.Path) -> None:
    """Chứng thư CA được cache theo dấu vân tay thư mục — thêm tệp phải đọc lại."""
    seed = ROOT / "trust"
    if not seed.is_dir():
        pytest.skip("không có thư mục trust/ mặc định")
    shutil.copyfile(seed / "mic-national-root-ca.cer", tmp_path / "mic.cer")
    assert len(trust.load_trust_material(tmp_path).roots) == 1
    before = trust.fingerprint(tmp_path)

    shutil.copyfile(seed / "vietnam-national-root-ca-2014-2039.cer", tmp_path / "vn.cer")
    assert trust.fingerprint(tmp_path) != before
    assert len(trust.load_trust_material(tmp_path).roots) == 2



# --------------------------------------------------------------------------
# Hình chữ ký: tên tổ chức dài phải xuống dòng, không tràn khỏi ô ký
# --------------------------------------------------------------------------

LONG_CN = "CONG TY CO PHAN PHAT TRIEN HA TANG KY THUAT VMCTECH"


def _appearance_text(width: float, height: float, cn: str, monkeypatch) -> list[str]:
    monkeypatch.setattr(signing, "subject_cn", lambda cert: cn)
    monkeypatch.setattr(signing, "subject_tax_code", lambda cert: "0101234567")
    appearance = signing.SignatureAppearance(page=0, box=(0, 0, width, height))
    lines, params = signing._appearance_lines(None, appearance)
    assert params == {}  # mọi giá trị đã nội suy sẵn, trừ %(ts)s của pyHanko
    return lines


@pytest.mark.parametrize(
    "width, height", [(140, 76), (165, 90), (190, 104), (220, 120)]
)
def test_ten_dai_xuong_dong_vua_be_rong_o_ky(width, height, monkeypatch) -> None:
    lines = _appearance_text(width, height, LONG_CN, monkeypatch)
    avail = width - 6 - 3  # lề trái/phải của phần chữ khi không có logo

    for line in lines:
        estimated = len(line) * signing.STAMP_FONT_SIZE * 0.52
        assert estimated <= avail + 0.5, line

    words = " ".join(lines).split()
    assert all(word in words for word in LONG_CN.split())  # không mất chữ nào


def test_o_ky_hep_van_giu_du_ba_muc(monkeypatch) -> None:
    """Ô nhỏ nhất vẫn phải có người ký, MST và ngày ký."""
    text = " ".join(_appearance_text(140, 76, LONG_CN, monkeypatch))
    assert "Ký bởi:" in text
    assert "MST: 0101234567" in text
    assert "Ngày ký:" in text and "%(ts)s" in text


def test_hinh_chu_ky_khong_con_ly_do_va_noi_ky(monkeypatch) -> None:
    text = " ".join(_appearance_text(165, 90, "NGUYEN VAN A", monkeypatch)).lower()
    assert "lý do" not in text and "nơi ký" not in text