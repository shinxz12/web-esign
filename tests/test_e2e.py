"""Test end-to-end: chạy thật backend, TSA, agent và USB token ảo.

Chậm (vài chục giây) nhưng không mock gì. Chạy riêng:

    .venv/bin/python -m pytest tests/test_e2e.py -v

Bỏ qua nhóm này khi chỉ muốn test nhanh:

    .venv/bin/python -m pytest tests -q -m "not e2e"
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from harness import (  # noqa: E402
    BOX_LEFT,
    BOX_RIGHT,
    Lab,
    cert_for,
    first_cert,
    make_softhsm_token,
    sign,
    softhsm_module,
    upload,
)

pytestmark = pytest.mark.e2e

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


# --------------------------------------------------------------------------
# Môi trường dùng chung cho cả phiên
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    lab = Lab(tmp_path_factory.mktemp("websigner-e2e"))
    lab.setup()
    lab.agent_with_pfx("111111", "signer-a.pfx")
    lab.agent_with_pfx("222222", "signer-b.pfx")
    lab.agent_with_pfx("999999", "signer-revoked.pfx")
    try:
        yield lab
    finally:
        lab.teardown()


@pytest.fixture(scope="session")
def pdf(lab) -> bytes:
    return lab.sample.read_bytes()


@pytest.fixture()
def owner(lab):
    return lab.main.client()


# --------------------------------------------------------------------------
# Ký cơ bản
# --------------------------------------------------------------------------


def test_ky_tu_do_dat_pades_b_lt(owner, lab, pdf):
    doc_id = upload(owner, pdf)

    status, body = sign(owner, f"/api/documents/{doc_id}", "111111", reason="Phê duyệt")
    assert status == 200, body
    assert body["signatures"][0]["profile"] == "B-LT"

    status, reports = owner.get(f"/api/documents/{doc_id}/verify")
    assert status == 200
    [report] = reports
    assert report["signer"] == "NGUYEN VAN A"
    assert report["tax_code"] == "0101234567"
    assert report["intact"] and report["trusted"]
    assert report["timestamped"] and report["timestamp_trusted"]
    assert report["ltv"], "CRL phải được nhúng vào DSS"
    assert report["profile"] == "PAdES B-LT"
    assert report["problems"] == []


def test_chung_thu_thu_hoi_bi_tu_choi_truoc_khi_hoi_token(owner, lab, pdf):
    doc_id = upload(owner, pdf)
    status, body = sign(owner, f"/api/documents/{doc_id}", "999999")

    assert status == 400, body
    assert "could not be validated" in body["detail"] or "thu hồi" in body["detail"]

    # tài liệu không được đụng tới
    _, meta = owner.get(f"/api/documents/{doc_id}")
    assert meta["revision"] == 0 and meta["signatures"] == []


def test_nhieu_nguoi_ky_khong_lam_hong_chu_ky_truoc(owner, lab, pdf):
    doc_id = upload(owner, pdf)
    assert sign(owner, f"/api/documents/{doc_id}", "111111", BOX_LEFT)[0] == 200
    assert sign(owner, f"/api/documents/{doc_id}", "222222", BOX_RIGHT)[0] == 200

    _, reports = owner.get(f"/api/documents/{doc_id}/verify")
    assert [r["signer"] for r in reports] == ["NGUYEN VAN A", "TRAN THI BICH"]
    for report in reports:
        assert report["intact"] and report["trusted"] and report["ltv"]
        assert report["summary"] == "Chữ ký hợp lệ"
        assert report["problems"] == []
    assert "Sig2" in reports[0]["notes"][0]


def test_ky_duoc_pdf_hybrid_cross_reference(owner, lab, pdf):
    """Word/Excel sinh ra tệp hybrid; pyHanko ở chế độ strict từ chối ký."""
    from harness import make_hybrid_pdf

    hybrid = make_hybrid_pdf(pdf)
    assert hybrid != pdf

    doc_id = upload(owner, hybrid)
    status, body = sign(owner, f"/api/documents/{doc_id}", "111111")
    assert status == 200, body

    status, reports = owner.get(f"/api/documents/{doc_id}/verify")
    assert status == 200, reports
    assert reports[0]["intact"] and reports[0]["trusted"]


def test_sua_mot_byte_lam_moi_chu_ky_vo_hieu(owner, lab, pdf):
    import asyncio

    from app.verify import verify

    doc_id = upload(owner, pdf)
    assert sign(owner, f"/api/documents/{doc_id}", "111111", BOX_LEFT)[0] == 200
    assert sign(owner, f"/api/documents/{doc_id}", "222222", BOX_RIGHT)[0] == 200
    signed = owner.download(f"/api/documents/{doc_id}/download")

    async def report(data: bytes):
        return await verify(data, trust_dir=lab.trust)

    before = asyncio.run(report(signed))
    assert all(r.intact for r in before)

    # lật 1 bit trong nội dung trang, nằm trong ByteRange của cả hai chữ ký
    tampered = bytearray(signed)
    tampered[20000] ^= 0x01
    after = asyncio.run(report(bytes(tampered)))
    assert [r.intact for r in after] == [False, False]
    assert all("KHÔNG hợp lệ" in r.summary for r in after)


# --------------------------------------------------------------------------
# Luồng ký có thứ tự và phân quyền
# --------------------------------------------------------------------------


@pytest.fixture()
def workflow(owner, lab, pdf):
    doc_id = upload(owner, pdf)
    status, doc = owner.put(
        f"/api/documents/{doc_id}/signers",
        [
            {"name": "Nguyễn Văn A", "tax_code": "0101234567"},
            {"name": "Trần Thị Bích", "tax_code": "0107654321"},
        ],
    )
    assert status == 200, doc
    assert doc["status"] == "chua_bat_dau"
    invites = [f"/api/sign/{s['invite_token']}" for s in doc["signers"]]
    return doc_id, invites


def test_khach_la_khong_thay_tai_lieu_cua_nguoi_khac(lab, workflow):
    doc_id, _ = workflow
    stranger = lab.main.client()
    assert stranger.get(f"/api/documents/{doc_id}")[0] == 404
    assert stranger.get(f"/api/documents/{doc_id}/file")[0] == 404
    assert stranger.request("DELETE", f"/api/documents/{doc_id}")[0] == 404


def test_khong_the_ky_vuot_luot(lab, workflow):
    _, invites = workflow
    status, body = sign(lab.main.client(), invites[1], "222222", BOX_RIGHT)
    assert status == 409
    assert "Chưa tới lượt" in body["detail"]


def test_chung_thu_sai_nguoi_bi_tu_choi(lab, workflow):
    _, invites = workflow
    # đúng lượt 1, nhưng cầm token của người thứ hai
    status, body = sign(lab.main.client(), invites[0], "222222", BOX_LEFT)
    assert status == 403
    assert "0101234567" in body["detail"]


def test_luong_ky_chay_het_dung_thu_tu(lab, owner, workflow):
    doc_id, invites = workflow
    signer_a, signer_b = lab.main.client(), lab.main.client()

    status, body = sign(signer_a, invites[0], "111111", BOX_LEFT)
    assert status == 200, body
    assert body["status"] == "cho_ky"

    status, body = sign(signer_a, invites[0], "111111", BOX_LEFT)
    assert status == 409 and "đã ký" in body["detail"]

    status, body = sign(signer_b, invites[1], "222222", BOX_RIGHT)
    assert status == 200, body
    assert body["status"] == "hoan_tat"
    assert [s["signed_by"] for s in body["signers"]] == [
        "NGUYEN VAN A",
        "TRAN THI BICH",
    ]

    status, body = sign(owner, f"/api/documents/{doc_id}", "111111")
    assert status == 409 and "luồng ký" in body["detail"]

    _, reports = owner.get(f"/api/documents/{doc_id}/verify")
    assert len(reports) == 2
    assert all(r["intact"] and r["trusted"] and r["ltv"] for r in reports)


def test_lien_ket_moi_khong_lo_bi_mat(lab, workflow):
    _, invites = workflow
    status, info = lab.main.client().get(invites[0])
    assert status == 200
    assert info["my_turn"] is True
    assert "owner_token" not in info["document"]
    assert "invite_token" not in info["document"]["signers"][0]


# --------------------------------------------------------------------------
# Thuật toán và hồ sơ khác
# --------------------------------------------------------------------------


@pytest.mark.skipif(softhsm_module() is None, reason="chưa cài softhsm2")
def test_ecdsa_qua_token_pkcs11(lab, owner, pdf):
    env = make_softhsm_token(lab, "signer-ec.pfx", "E2E-EC")
    lab.start_agent(
        "444444",
        "--pkcs11",
        softhsm_module(),
        "--token-label",
        "E2E-EC",
        "--pin",
        "123456",
        env=env,
    )

    doc_id = upload(owner, pdf)
    status, body = sign(owner, f"/api/documents/{doc_id}", "444444")
    assert status == 200, body

    _, reports = owner.get(f"/api/documents/{doc_id}/verify")
    assert reports[0]["signer"] == "LE MINH CUONG"
    assert reports[0]["intact"] and reports[0]["trusted"] and reports[0]["ltv"]


@pytest.mark.skipif(softhsm_module() is None, reason="chưa cài softhsm2")
def test_nhieu_token_cung_luc_ky_dung_token(lab, owner, pdf):
    """Người ký giữ token của nhiều công ty, cắm cùng lúc.

    Agent phải liệt kê chứng thư của mọi token và ký bằng đúng token giữ
    chứng thư được chọn — không phải token đầu tiên dò thấy.
    """
    env = make_softhsm_token(lab, "signer-a.pfx", "E2E-CTY-A")
    make_softhsm_token(lab, "signer-b.pfx", "E2E-CTY-B")
    # Không truyền --token-label: agent phải tự quét mọi token đang cắm.
    lab.start_agent(
        "555555", "--pkcs11", softhsm_module(), "--pin", "123456", env=env
    )

    _, listed = owner.get("/api/agents/555555/certificates")
    subjects = {c["subject"] for c in listed["certificates"]}
    assert {"NGUYEN VAN A", "TRAN THI BICH"} <= subjects, subjects

    # Ký bằng chứng thư của công ty thứ hai, nằm trên token thứ hai.
    doc_id = upload(owner, pdf)
    status, body = owner.post(
        f"/api/documents/{doc_id}/sign",
        body={
            "agent_code": "555555",
            "cert_id": cert_for(owner, "555555", "TRAN THI BICH"),
            "page": 1,
            "box": BOX_RIGHT,
            "reason": "Ký bằng token công ty B",
        },
    )
    assert status == 200, body

    _, reports = owner.get(f"/api/documents/{doc_id}/verify")
    assert reports[0]["signer"] == "TRAN THI BICH"
    assert reports[0]["tax_code"] == "0107654321"
    assert reports[0]["intact"] and reports[0]["trusted"]


def test_rsa_pss_dung_salt_cua_server(lab, pdf):
    backend = lab.start_backend("backend-pss", WEBSIGNER_PREFER_PSS="1")
    lab.agent_with_pfx("777777", "signer-a.pfx", backend=backend)
    client = backend.client()

    doc_id = upload(client, pdf)
    status, body = sign(client, f"/api/documents/{doc_id}", "777777")
    assert status == 200, body

    _, reports = client.get(f"/api/documents/{doc_id}/verify")
    assert reports[0]["intact"] and reports[0]["trusted"]

    signed = client.download(f"/api/documents/{doc_id}/download")
    assert _signature_mechanism(signed) == "rsassa_pss"


def test_b_lta_co_dau_thoi_gian_tai_lieu(lab, pdf):
    backend = lab.start_backend("backend-lta", WEBSIGNER_PROFILE="B-LTA")
    lab.agent_with_pfx("888888", "signer-a.pfx", backend=backend)
    client = backend.client()

    doc_id = upload(client, pdf)
    assert sign(client, f"/api/documents/{doc_id}", "888888")[0] == 200

    _, reports = client.get(f"/api/documents/{doc_id}/verify")
    assert reports[0]["profile"] == "PAdES B-LTA"

    signed = client.download(f"/api/documents/{doc_id}/download")
    assert _has_document_timestamp(signed)


def test_khong_co_tsa_thi_chi_ky_duoc_b_b(lab, pdf):
    backend = lab.start_backend("backend-no-tsa", WEBSIGNER_TSA_URL="")
    lab.agent_with_pfx("666666", "signer-a.pfx", backend=backend)
    client = backend.client()

    _, session = client.get("/api/session")
    assert session == {"profile": "B-B", "timestamping": False}

    doc_id = upload(client, pdf)
    assert sign(client, f"/api/documents/{doc_id}", "666666")[0] == 200
    _, reports = client.get(f"/api/documents/{doc_id}/verify")
    assert reports[0]["profile"] == "PAdES B-B"
    assert reports[0]["timestamped"] is False
    assert reports[0]["intact"] and reports[0]["trusted"]


# --------------------------------------------------------------------------
# Soi vào bên trong tệp PDF
# --------------------------------------------------------------------------


def _reader(signed: bytes):
    import io

    from pyhanko.pdf_utils.reader import PdfFileReader

    return PdfFileReader(io.BytesIO(signed))


def _signature_mechanism(signed: bytes) -> str:
    signer_info = _reader(signed).embedded_signatures[0].signer_info
    return signer_info["signature_algorithm"]["algorithm"].native


def _has_document_timestamp(signed: bytes) -> bool:
    return any(
        embedded.sig_object.get("/Type") == "/DocTimeStamp"
        for embedded in _reader(signed).embedded_signatures
    )
