"""Test end-to-end: chạy thật PostgreSQL, backend, TSA, agent và USB token ảo.

Chậm (vài chục giây) nhưng không mock gì. Chạy riêng:

    .venv/bin/python -m pytest tests/test_e2e.py -v

Bỏ qua nhóm này khi chỉ muốn test nhanh:

    .venv/bin/python -m pytest tests -q -m "not e2e"
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from harness import (  # noqa: E402
    BOX_LEFT,
    BOX_RIGHT,
    PASSWORD,
    PYTHON,
    SIGNER_A,
    SIGNER_B,
    Client,
    Lab,
    api_client,
    cert_for,
    create_document,
    first_cert,
    free_port,
    invite_path,
    make_softhsm_token,
    postgres_available,
    register,
    sign,
    softhsm_module,
    verify_webhook_signature,
    wait_until,
)

pytestmark = pytest.mark.e2e

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


# --------------------------------------------------------------------------
# Môi trường dùng chung cho cả phiên
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    if not postgres_available():
        pytest.skip("cần PostgreSQL (đặt WEBSIGNER_TEST_ADMIN_DSN)")
    lab = Lab(tmp_path_factory.mktemp("websigner-e2e"))
    lab.setup()
    try:
        lab.agent_with_pfx("111111", "signer-a.pfx")
        lab.agent_with_pfx("222222", "signer-b.pfx")
        lab.agent_with_pfx("999999", "signer-revoked.pfx")
        yield lab
    finally:
        lab.teardown()


@pytest.fixture(scope="session")
def pdf(lab) -> bytes:
    return lab.sample.read_bytes()


@pytest.fixture(scope="session")
def owner(lab) -> Client:
    """Chủ một tổ chức đã đăng nhập giao diện (cookie + CSRF)."""
    return register(lab.main, lab=lab)


@pytest.fixture(scope="session")
def api(owner) -> Client:
    """Hệ thống tích hợp của tổ chức đó, gọi bằng khoá API."""
    return api_client(owner)


@pytest.fixture()
def browser(lab) -> Client:
    """Trình duyệt mới tinh của một người nhận."""
    return lab.main.client()


def _doc(api: Client, doc: dict) -> dict:
    status, body = api.get(f"/v1/documents/{doc['id']}")
    assert status == 200, body
    return body


# --------------------------------------------------------------------------
# Ký cơ bản
# --------------------------------------------------------------------------


def test_ky_dat_pades_b_lt(api, browser, pdf):
    doc = create_document(api, pdf, [SIGNER_A])
    assert doc["status"] == "in_progress"

    status, body = sign(browser, invite_path(doc, 0), "111111")
    assert status == 200, body
    assert body["document"]["status"] == "completed"
    assert body["recipient"]["signature"]["profile"] == "B-LT"

    status, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert status == 200
    [report] = reports
    assert report["signer"] == "NGUYEN VAN A"
    assert report["tax_code"] == "0101234567"
    assert report["intact"] and report["trusted"]
    assert report["timestamped"] and report["timestamp_trusted"]
    assert report["ltv"], "CRL phải được nhúng vào DSS"
    assert report["profile"] == "PAdES B-LT"
    assert report["problems"] == []


def test_chung_thu_thu_hoi_bi_tu_choi_truoc_khi_hoi_token(api, browser, pdf):
    doc = create_document(api, pdf, [{"name": "Phạm Thu Hà", "tax_code": "0100000000"}])
    status, body = sign(browser, invite_path(doc, 0), "999999")

    assert status == 400, body
    assert body["code"] == "prepare_failed"
    assert "could not be validated" in body["detail"] or "thu hồi" in body["detail"]

    # tài liệu không được đụng tới
    meta = _doc(api, doc)
    assert meta["revision"] == 0 and meta["recipients"][0]["status"] == "pending"


def test_nhieu_nguoi_ky_khong_lam_hong_chu_ky_truoc(api, lab, pdf):
    doc = create_document(api, pdf, [SIGNER_A, SIGNER_B])
    assert sign(lab.main.client(), invite_path(doc, 0), "111111", BOX_LEFT)[0] == 200
    assert sign(lab.main.client(), invite_path(doc, 1), "222222", BOX_RIGHT)[0] == 200

    _, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert [r["signer"] for r in reports] == ["NGUYEN VAN A", "TRAN THI BICH"]
    for report in reports:
        assert report["intact"] and report["trusted"] and report["ltv"]
        assert report["summary"] == "Chữ ký hợp lệ"
        assert report["problems"] == []
    assert "Sig2" in reports[0]["notes"][0]


def test_ky_tiep_len_pdf_da_ky_san_o_phan_mem_khac(api, lab, pdf):
    """File khách mang tới đã có chữ ký (ô "Sig1") từ Adobe/phần mềm của CA.

    Người ngoài tổ chức ký tiếp qua liên kết, không tài khoản: chữ ký cũ phải
    còn nguyên và ô ký mới không được trùng tên ô đã có.
    """
    first = create_document(api, pdf, [SIGNER_A])
    assert sign(lab.main.client(), invite_path(first, 0), "111111", BOX_LEFT)[0] == 200
    presigned = api.download(f"/v1/documents/{first['id']}/file")

    doc = create_document(api, presigned, [SIGNER_B])
    status, body = sign(lab.main.client(), invite_path(doc, 0), "222222", BOX_RIGHT)
    assert status == 200, body
    assert body["recipient"]["signature"]["field_name"] != "Sig1"

    _, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert [r["signer"] for r in reports] == ["NGUYEN VAN A", "TRAN THI BICH"]
    assert all(r["intact"] and r["trusted"] for r in reports)


def test_ky_duoc_pdf_hybrid_cross_reference(api, browser, pdf):
    """Word/Excel sinh ra tệp hybrid; pyHanko ở chế độ strict từ chối ký."""
    from harness import make_hybrid_pdf

    hybrid = make_hybrid_pdf(pdf)
    assert hybrid != pdf

    doc = create_document(api, hybrid, [SIGNER_A])
    status, body = sign(browser, invite_path(doc, 0), "111111")
    assert status == 200, body

    status, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert status == 200, reports
    assert reports[0]["intact"] and reports[0]["trusted"]


def test_sua_mot_byte_lam_moi_chu_ky_vo_hieu(api, lab, pdf):
    import asyncio

    from app.verify import verify

    doc = create_document(api, pdf, [SIGNER_A, SIGNER_B])
    assert sign(lab.main.client(), invite_path(doc, 0), "111111", BOX_LEFT)[0] == 200
    assert sign(lab.main.client(), invite_path(doc, 1), "222222", BOX_RIGHT)[0] == 200
    signed = api.download(f"/v1/documents/{doc['id']}/file?download=true")

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
# Luồng ký có thứ tự và phân quyền người nhận
# --------------------------------------------------------------------------


@pytest.fixture()
def workflow(api, pdf):
    doc = create_document(api, pdf, [SIGNER_A, SIGNER_B])
    return doc["id"], [invite_path(doc, 0), invite_path(doc, 1)]


def test_to_chuc_khac_khong_thay_tai_lieu(lab, workflow):
    doc_id, _ = workflow
    stranger = register(lab.main, lab=lab)
    stranger_api = api_client(stranger)
    for client in (stranger, stranger_api):
        assert client.get(f"/v1/documents/{doc_id}")[0] == 404
        assert client.get(f"/v1/documents/{doc_id}/file")[0] == 404
        assert client.get(f"/v1/documents/{doc_id}/audit")[0] == 404
        assert client.delete(f"/v1/documents/{doc_id}")[0] == 404
        _, listing = client.get("/v1/documents")
        assert doc_id not in [d["id"] for d in listing["data"]]


def test_khong_the_ky_vuot_luot(lab, workflow):
    _, invites = workflow
    status, body = sign(lab.main.client(), invites[1], "222222", BOX_RIGHT)
    assert status == 409
    assert body["code"] == "not_your_turn"
    assert "Chưa tới lượt" in body["detail"]


def test_chung_thu_sai_nguoi_bi_tu_choi(lab, workflow):
    _, invites = workflow
    # đúng lượt 1, nhưng cầm token của người thứ hai
    status, body = sign(lab.main.client(), invites[0], "222222", BOX_LEFT)
    assert status == 403
    assert body["code"] == "wrong_signer"
    assert "0101234567" in body["detail"]


def test_luong_ky_chay_het_dung_thu_tu(lab, api, workflow):
    doc_id, invites = workflow
    signer_a, signer_b = lab.main.client(), lab.main.client()

    status, body = sign(signer_a, invites[0], "111111", BOX_LEFT)
    assert status == 200, body
    assert body["document"]["status"] == "in_progress"
    assert body["turn"]["reason"] == "already_acted"

    status, body = sign(signer_a, invites[0], "111111", BOX_LEFT)
    assert status == 409 and body["code"] == "already_acted"

    status, body = sign(signer_b, invites[1], "222222", BOX_RIGHT)
    assert status == 200, body
    assert body["document"]["status"] == "completed"

    _, doc = api.get(f"/v1/documents/{doc_id}")
    assert [r["signature"]["signer"] for r in doc["recipients"]] == ["NGUYEN VAN A", "TRAN THI BICH"]
    assert all("signing_url" not in r for r in doc["recipients"]), "xong rồi thì không còn liên kết ký"

    _, reports = api.get(f"/v1/documents/{doc_id}/verify")
    assert len(reports) == 2
    assert all(r["intact"] and r["trusted"] and r["ltv"] for r in reports)


def test_lien_ket_moi_khong_lo_bi_mat(lab, api, pdf):
    doc = create_document(
        api, pdf, [{**SIGNER_A, "email": "a@e2e.vn"}], external_ref="HD-001", metadata={"crm_id": "42"}
    )
    status, info = lab.main.client().get(invite_path(doc, 0))
    assert status == 200
    assert info["turn"]["can_act"] is True
    assert "metadata" not in info["document"] and "external_ref" not in info["document"]
    for recipient in [info["recipient"], *info["document"]["recipients"]]:
        assert "email" not in recipient and "signing_url" not in recipient


def test_ky_song_song_sau_nguoi_duyet(lab, api, pdf):
    """Người duyệt ở lượt 1; hai người ký cùng lượt 2, ai ký trước cũng được."""
    doc = create_document(
        api,
        pdf,
        [
            {"name": "Kế toán trưởng", "role": "approver", "order": 1},
            {**SIGNER_A, "order": 2},
            {**SIGNER_B, "order": 2},
        ],
    )
    approver, path_a, path_b = (invite_path(doc, i) for i in range(3))

    status, body = sign(lab.main.client(), path_a, "111111", BOX_LEFT)
    assert status == 409 and body["code"] == "not_your_turn"
    assert "Kế toán trưởng" in body["detail"]

    status, body = lab.main.client().post(f"{approver}/approve")
    assert status == 200, body
    assert body["recipient"]["status"] == "approved"

    # B ký trước A dù khai sau: cùng lượt là song song.
    assert sign(lab.main.client(), path_b, "222222", BOX_RIGHT)[0] == 200
    status, body = sign(lab.main.client(), path_a, "111111", BOX_LEFT)
    assert status == 200, body
    assert body["document"]["status"] == "completed"

    _, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert [r["signer"] for r in reports] == ["TRAN THI BICH", "NGUYEN VAN A"]
    assert all(r["intact"] and r["trusted"] for r in reports)


def test_tu_choi_dung_ca_tai_lieu(lab, api, pdf):
    doc = create_document(api, pdf, [SIGNER_A, {**SIGNER_B, "order": 1}])
    path_a, path_b = invite_path(doc, 0), invite_path(doc, 1)

    status, body = lab.main.client().post(f"{path_a}/decline", {"reason": "Sai điều khoản thanh toán"})
    assert status == 200, body
    assert body["document"]["status"] == "declined"

    status, info = lab.main.client().get(path_b)
    assert info["turn"]["reason"] == "document_declined"
    status, body = sign(lab.main.client(), path_b, "222222", BOX_RIGHT)
    assert status == 409 and body["code"] == "document_declined"

    meta = _doc(api, doc)
    assert meta["recipients"][0]["decline_reason"] == "Sai điều khoản thanh toán"


def test_o_ky_dat_san_thang_vi_tri_trinh_duyet_gui(lab, api, pdf):
    """Hệ thống tích hợp đặt ô ký; trình duyệt không dời được nó đi chỗ khác."""
    field = {"page": 0, "box": [300, 100, 465, 190]}
    doc = create_document(api, pdf, [{**SIGNER_A, "field": field}])

    status, body = sign(lab.main.client(), invite_path(doc, 0), "111111", BOX_LEFT, page=1)
    assert status == 200, body
    assert body["recipient"]["signature"]["page"] == 0

    signed = api.download(f"/v1/documents/{doc['id']}/file")
    rect = [float(v) for v in _reader(signed).embedded_signatures[0].sig_field["/Rect"]]
    assert rect == pytest.approx(field["box"])


def test_ho_so_dat_san_khong_hop_le_bi_chan_khi_tao(api, pdf):
    status, body = api.post(
        "/v1/documents",
        upload=pdf,
        form={"data": json.dumps({"recipients": [{**SIGNER_A, "field": {"page": 5, "box": [0, 0, 165, 90]}}]})},
    )
    assert status == 400 and body["code"] == "invalid_field"

    status, body = api.post("/v1/documents", upload=b"day khong phai pdf", form={"data": "{}"})
    assert status == 400 and body["code"] == "invalid_pdf"


# --------------------------------------------------------------------------
# Nền tảng: khoá API, phiên, hạn mức, webhook, email, nhật ký
# --------------------------------------------------------------------------


def test_khoa_api_va_phien_dang_nhap(lab, owner):
    anonymous = lab.main.client()
    status, body = anonymous.get("/v1/documents")
    assert status == 401 and body["code"] == "unauthenticated"

    bogus = Client(lab.main.url, api_key="wsk_live_" + "x" * 43)
    assert bogus.get("/v1/documents")[1]["code"] == "invalid_api_key"

    key_api = api_client(owner)
    assert key_api.get("/v1/documents")[0] == 200
    # Khoá API không tự cấp thêm khoá, không đụng được webhook/thành viên.
    status, body = key_api.post("/api/org/api-keys", {"name": "leo thang"})
    assert status == 403 and body["code"] == "session_required"

    # Cookie mà thiếu CSRF token thì không thay đổi được gì.
    csrf, owner.csrf = owner.csrf, None
    try:
        status, body = owner.post("/api/org/api-keys", {"name": "csrf"})
        assert status == 403 and body["code"] == "csrf_failed"
    finally:
        owner.csrf = csrf

    _, keys = owner.get("/api/org/api-keys")
    newest = keys[0]
    assert owner.delete(f"/api/org/api-keys/{newest['id']}")[0] == 204
    assert key_api.get("/v1/documents")[1]["code"] == "invalid_api_key"


def test_idempotency_key_khong_tao_trung(api, pdf):
    headers = {"Idempotency-Key": f"order-{uuid.uuid4()}"}
    first = create_document(api, pdf, [SIGNER_A], headers=headers, external_ref="DH-1")
    second = create_document(api, pdf, [SIGNER_A], headers=headers, external_ref="DH-1")
    assert second["id"] == first["id"]
    assert api.last_headers.get("Idempotent-Replayed") == "true"

    status, body = api.post(
        "/v1/documents",
        upload=pdf,
        form={"data": json.dumps({"recipients": [SIGNER_B]})},
        headers=headers,
    )
    assert status == 422 and body["code"] == "idempotency_mismatch"


def test_vuot_han_muc_goi_mien_phi(lab, pdf):
    free = register(lab.main, plan=None)
    free_api = api_client(free)
    _, usage = free_api.get("/v1/usage")
    assert usage["plan"]["code"] == "free"
    limit = usage["plan"]["documents_per_month"]
    lab.sql(
        "INSERT INTO usage_counters (org_id, period, documents) VALUES (%s, %s, %s)",
        (free.me["org"]["id"], usage["period"], limit - 1),
    )

    create_document(free_api, pdf, [SIGNER_A], send=False)  # chiếc cuối cùng còn trong hạn mức
    status, body = free_api.post("/v1/documents", upload=pdf, form={"data": "{}"})
    assert status == 402 and body["code"] == "quota_exceeded"
    assert free_api.get("/v1/usage")[1]["documents"] == limit


def test_webhook_co_chu_ky_va_gui_lai_duoc(lab, pdf):
    org = register(lab.main, lab=lab)
    org_api = api_client(org)
    status, endpoint = org.post("/api/org/webhooks", {"url": lab.hooks.url, "events": ["*"]})
    assert status == 201, endpoint
    secret = endpoint["secret"]

    doc = create_document(org_api, pdf, [SIGNER_A])
    assert sign(lab.main.client(), invite_path(doc, 0), "111111")[0] == 200

    wait_until(
        lambda: "document.completed" in [e["type"] for e in lab.hooks.events(doc["id"])],
        "webhook document.completed",
    )
    types = [e["type"] for e in lab.hooks.events(doc["id"])]
    assert types == ["document.sent", "recipient.signed", "document.completed"]
    completed = lab.hooks.events(doc["id"])[-1]
    assert completed["data"]["document"]["status"] == "completed"
    assert "signing_url" not in json.dumps(completed), "webhook không mang liên kết ký"

    with lab.hooks.lock:
        requests = list(lab.hooks.requests)
    assert requests and all(verify_webhook_signature(secret, r["headers"], r["body"]) for r in requests)
    assert not verify_webhook_signature("whsec_sai", requests[0]["headers"], requests[0]["body"])

    # Người nhận trả 500: lần gửi giữ trạng thái chờ, bấm gửi lại thì tới.
    lab.hooks.fail_next.append(500)
    status, delivery = org.post(f"/api/org/webhooks/{endpoint['id']}/test")
    assert status == 200, delivery

    def delivery_state():
        _, items = org.get(f"/api/org/webhooks/{endpoint['id']}/deliveries")
        return next(d for d in items if d["id"] == delivery["id"])

    wait_until(lambda: delivery_state()["attempts"] == 1, "lần gửi thử đầu tiên")
    assert delivery_state()["status"] == "pending" and delivery_state()["last_status_code"] == 500
    org.post(f"/api/org/webhooks/{endpoint['id']}/deliveries/{delivery['id']}/retry")
    wait_until(lambda: delivery_state()["status"] == "succeeded", "gửi lại webhook")


def test_email_moi_dung_luot_va_bao_hoan_tat(lab, api, pdf):
    email_a, email_b = f"a-{uuid.uuid4().hex[:8]}@e2e.vn", f"b-{uuid.uuid4().hex[:8]}@e2e.vn"
    doc = create_document(api, pdf, [{**SIGNER_A, "email": email_a}, {**SIGNER_B, "email": email_b}])

    wait_until(lambda: lab.smtp.to(email_a), "email mời người ký thứ nhất")
    [invite_a] = lab.smtp.to(email_a)
    assert doc["recipients"][0]["signing_url"] in invite_a["body"]
    assert lab.smtp.to(email_b) == [], "người thứ hai chưa tới lượt thì chưa được mời"

    assert sign(lab.main.client(), invite_path(doc, 0), "111111", BOX_LEFT)[0] == 200
    wait_until(lambda: lab.smtp.to(email_b), "email mời người ký thứ hai")
    assert doc["recipients"][1]["signing_url"] in lab.smtp.to(email_b)[0]["body"]

    assert sign(lab.main.client(), invite_path(doc, 1), "222222", BOX_RIGHT)[0] == 200
    wait_until(lambda: len(lab.smtp.to(email_a)) == 2 and len(lab.smtp.to(email_b)) == 2, "email hoàn tất")
    assert lab.smtp.to(email_a)[-1]["subject"].startswith("Đã hoàn tất")


def test_nhat_ky_kiem_toan_phat_hien_bi_sua(lab, api, pdf):
    import hashlib

    doc = create_document(api, pdf, [SIGNER_A])
    lab.main.client().get(invite_path(doc, 0))
    assert sign(lab.main.client(), invite_path(doc, 0), "111111")[0] == 200
    api.download(f"/v1/documents/{doc['id']}/file?download=true")

    _, trail = api.get(f"/v1/documents/{doc['id']}/audit")
    assert trail["chain_valid"] is True
    types = [e["type"] for e in trail["events"]]
    assert types == [
        "document.created",
        "document.sent",
        "recipient.viewed",
        "recipient.signed",
        "document.completed",
        "document.downloaded",
    ]
    signed_event = trail["events"][3]
    signed = api.download(f"/v1/documents/{doc['id']}/file")
    assert signed_event["data"]["sha256"] == hashlib.sha256(signed).hexdigest()
    assert signed_event["data"]["signer"] == "NGUYEN VAN A"
    assert trail["head"] == trail["events"][-1]["hash"]

    # Kẻ có quyền ghi DB sửa tên người ký trong nhật ký: chuỗi băm đứt ngay đó.
    lab.sql(
        "UPDATE events SET canonical = replace(canonical, 'NGUYEN VAN A', 'KE GIAN') "
        "WHERE document_id = %s AND type = 'recipient.signed'",
        (doc["id"],),
    )
    _, trail = api.get(f"/v1/documents/{doc['id']}/audit")
    assert trail["chain_valid"] is False
    assert trail["broken_at"] == signed_event["seq"]


def test_huy_va_xoa_tai_lieu(lab, api, pdf):
    doc = create_document(api, pdf, [SIGNER_A])
    path = invite_path(doc, 0)

    status, body = api.delete(f"/v1/documents/{doc['id']}")
    assert status == 409 and body["code"] == "in_progress"

    status, body = api.post(f"/v1/documents/{doc['id']}/void", {"reason": "Khách huỷ đơn"})
    assert status == 200 and body["status"] == "voided"
    assert lab.main.client().get(path)[1]["turn"]["reason"] == "document_voided"
    status, body = sign(lab.main.client(), path, "111111")
    assert status == 409 and body["code"] == "document_voided"

    assert api.delete(f"/v1/documents/{doc['id']}")[0] == 204
    assert api.get(f"/v1/documents/{doc['id']}")[0] == 404
    assert lab.main.client().get(path)[0] == 404


def test_het_han_thi_khong_ky_duoc_nua(lab, api, pdf):
    doc = create_document(api, pdf, [SIGNER_A], expires_in_days=7)
    lab.sql(
        "UPDATE documents SET expires_at = now() - interval '1 minute' WHERE id = %s", (doc["id"],)
    )
    # Chưa cần worker quét: tới hạn là chặn ký ngay.
    status, body = sign(lab.main.client(), invite_path(doc, 0), "111111")
    assert status == 409 and body["code"] == "document_expired"
    wait_until(lambda: _doc(api, doc)["status"] == "expired", "worker đánh dấu hết hạn", timeout=15)


def test_cap_lai_lien_ket_ky(lab, api, pdf):
    doc = create_document(api, pdf, [SIGNER_A])
    old = invite_path(doc, 0)
    status, recipient = api.post(f"/v1/documents/{doc['id']}/recipients/{doc['recipients'][0]['id']}/rotate-link")
    assert status == 200, recipient
    new = "/api/sign/" + recipient["signing_url"].rsplit("/s/", 1)[1]
    assert new != old
    assert lab.main.client().get(old)[0] == 404
    assert lab.main.client().get(new)[0] == 200


def test_ban_nhap_sua_roi_moi_gui(lab, api, pdf):
    doc = create_document(api, pdf, [], send=False, title="Nháp")
    assert doc["status"] == "draft"
    status, body = api.post(f"/v1/documents/{doc['id']}/send")
    assert status == 400 and body["code"] == "no_signers"

    status, body = api.put(f"/v1/documents/{doc['id']}/recipients", [SIGNER_A])
    assert status == 200, body
    status, body = api.patch(f"/v1/documents/{doc['id']}", {"title": "Hợp đồng chính thức"})
    assert status == 200 and body["title"] == "Hợp đồng chính thức"
    # Liên kết của bản nháp chưa mở được: người nhận chưa được mời.
    assert lab.main.client().get(invite_path(body, 0))[0] == 404

    status, body = api.post(f"/v1/documents/{doc['id']}/send")
    assert status == 200 and body["status"] == "in_progress"
    status, body = api.put(f"/v1/documents/{doc['id']}/recipients", [SIGNER_B])
    assert status == 409 and body["code"] == "not_draft"


def test_thanh_vien_khong_co_quyen_quan_tri(lab, owner):
    email = f"member-{uuid.uuid4().hex[:8]}@e2e.vn"
    status, invited = owner.post("/api/org/members", {"email": email, "name": "Nhân viên", "role": "member"})
    assert status == 201, invited
    token = invited["invite_url"].split("t=", 1)[1]

    member = lab.main.client()
    status, me = member.post("/api/auth/accept-invite", {"token": token, "name": "Nhân Viên", "password": PASSWORD})
    assert status == 200, me
    assert me["user"]["role"] == "member" and me["org"]["id"] == owner.me["org"]["id"]
    member.csrf = me["csrf_token"]

    assert member.get("/v1/documents")[0] == 200
    status, body = member.post("/api/org/api-keys", {"name": "khong duoc"})
    assert status == 403 and body["code"] == "forbidden"
    # Lời mời chỉ dùng được một lần.
    assert lab.main.client().post("/api/auth/accept-invite", {"token": token, "name": "X", "password": PASSWORD})[0] == 400

    again = lab.main.client()
    assert again.post("/api/auth/login", {"email": email, "password": PASSWORD})[0] == 200
    assert again.post("/api/auth/login", {"email": email, "password": "sai-mat-khau-roi"})[1]["code"] == "invalid_credentials"


def test_nhap_tai_lieu_tu_ban_luu_bang_tep(lab, api, pdf):
    """Bản cũ lưu tài liệu thành tệp và chủ là cookie ẩn danh; CLI đưa chúng vào một tổ chức."""
    source = create_document(api, pdf, [SIGNER_A])
    assert sign(lab.main.client(), invite_path(source, 0), "111111")[0] == 200
    signed = api.download(f"/v1/documents/{source['id']}/file")

    legacy_id = uuid.uuid4().hex[:16]
    legacy = lab.data / "documents" / legacy_id
    legacy.mkdir(parents=True)
    (legacy / "rev0.pdf").write_bytes(pdf)
    (legacy / "rev1.pdf").write_bytes(signed)
    (legacy / "meta.json").write_text(
        json.dumps(
            {
                "id": legacy_id,
                "name": "hop-dong-cu.pdf",
                "created_at": "2026-01-02T03:04:05+00:00",
                "owner_token": "cookie-an-danh",
                "revision": 1,
                "signers": [],
                "signatures": [
                    {"field_name": "Sig1", "signer": "NGUYEN VAN A", "tax_code": "0101234567",
                     "signed_at": "2026-01-02T03:05:00+00:00", "page": 1, "profile": "B-LT"}
                ],
            }
        ),
        encoding="utf-8",
    )
    org = register(lab.main, lab=lab)
    result = subprocess.run(
        [str(PYTHON), "-m", "app.admin", "import-legacy", org.me["org"]["id"]],
        cwd=ROOT / "backend",
        env={**os.environ, **lab.env()},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    try:
        status, doc = org.get(f"/v1/documents/doc_{legacy_id}")
        assert status == 200, doc
        assert doc["status"] == "completed" and doc["revision"] == 1
        assert doc["recipients"][0]["signature"]["signer"] == "NGUYEN VAN A"
        _, reports = org.get(f"/v1/documents/doc_{legacy_id}/verify")
        assert reports[0]["intact"] and reports[0]["trusted"]
        assert api.get(f"/v1/documents/doc_{legacy_id}")[0] == 404, "chỉ tổ chức được chọn mới thấy"
    finally:
        shutil.rmtree(legacy)


# --------------------------------------------------------------------------
# Thuật toán và hồ sơ khác
# --------------------------------------------------------------------------


@pytest.mark.skipif(softhsm_module() is None, reason="chưa cài softhsm2")
def test_ecdsa_qua_token_pkcs11(lab, api, pdf):
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

    doc = create_document(api, pdf, [{"name": "Lê Minh Cường", "tax_code": "0109999999"}])
    status, body = sign(lab.main.client(), invite_path(doc, 0), "444444")
    assert status == 200, body

    _, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert reports[0]["signer"] == "LE MINH CUONG"
    assert reports[0]["intact"] and reports[0]["trusted"] and reports[0]["ltv"]


@pytest.mark.skipif(softhsm_module() is None, reason="chưa cài softhsm2")
def test_nhieu_token_cung_luc_ky_dung_token(lab, api, pdf):
    """Người ký giữ token của nhiều công ty, cắm cùng lúc.

    Agent phải liệt kê chứng thư của mọi token và ký bằng đúng token giữ
    chứng thư được chọn — không phải token đầu tiên dò thấy.
    """
    env = make_softhsm_token(lab, "signer-a.pfx", "E2E-CTY-A")
    make_softhsm_token(lab, "signer-b.pfx", "E2E-CTY-B")
    # Không truyền --token-label: agent phải tự quét mọi token đang cắm.
    lab.start_agent("555555", "--pkcs11", softhsm_module(), "--pin", "123456", env=env)

    browser = lab.main.client()
    _, listed = browser.get("/api/agents/555555/certificates")
    subjects = {c["subject"] for c in listed["certificates"]}
    assert {"NGUYEN VAN A", "TRAN THI BICH"} <= subjects, subjects

    # Ký bằng chứng thư của công ty thứ hai, nằm trên token thứ hai.
    doc = create_document(api, pdf, [SIGNER_B])
    status, body = browser.post(
        f"{invite_path(doc, 0)}/sign",
        body={
            "agent_code": "555555",
            "cert_id": cert_for(browser, "555555", "TRAN THI BICH"),
            "page": 1,
            "box": BOX_RIGHT,
        },
    )
    assert status == 200, body

    _, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert reports[0]["signer"] == "TRAN THI BICH"
    assert reports[0]["tax_code"] == "0107654321"
    assert reports[0]["intact"] and reports[0]["trusted"]


def test_logo_va_mau_duoc_ve_vao_hinh_chu_ky(lab, api, pdf):
    """Hình chữ ký theo mẫu VN: logo bên trái, chữ song ngữ có màu bên phải."""
    import io as _io

    from PIL import Image, ImageDraw

    buf = _io.BytesIO()
    image = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
    ImageDraw.Draw(image).ellipse((4, 4, 124, 124), outline=(200, 20, 20, 255), width=8)
    image.save(buf, format="PNG")

    doc = create_document(api, pdf, [SIGNER_A])
    path = invite_path(doc, 0)
    browser = lab.main.client()
    status, info = browser.post(f"{path}/logo", upload=buf.getvalue(), filename="logo.png")
    assert status == 200, info
    assert info["format"] == "PNG"

    status, body = sign(browser, path, "111111", [65, 390, 330, 460], color="do", use_logo=True)
    assert status == 200, body

    signed = api.download(f"/v1/documents/{doc['id']}/file")
    assert _appearance_has_image(signed), "logo không được nhúng vào hình chữ ký"


def test_dau_tich_chim_bat_tat_theo_yeu_cau(lab, api, pdf):
    """Dấu tích chìm là tuỳ chọn: bật thì có, tắt thì hình chữ ký sạch."""
    doc = create_document(api, pdf, [SIGNER_A, SIGNER_A])
    for index, box, check_mark in ((0, [65, 390, 265, 445], True), (1, [300, 390, 500, 445], False)):
        status, body = sign(lab.main.client(), invite_path(doc, index), "111111", box, check_mark=check_mark)
        assert status == 200, body

    signed = api.download(f"/v1/documents/{doc['id']}/file")
    assert _appearance_check_marks(signed) == [True, False]


def test_cookie_thiet_bi_ky_duoc_ma_khong_can_ma_ghep_cap(lab, api, pdf):
    """Cài agent + kích hoạt một lần -> trình duyệt tự thấy token đang cắm.

    Đây là đường chính của trang ký: không gõ mã 6 số, không bấm "Kết nối".
    """
    token = json.loads((lab.data / "device-111111.json").read_text())["device_token"]
    browser = lab.main.client()

    # Trình duyệt mới: chưa gắn máy nào.
    status, info = browser.get("/api/agents")
    assert status == 200 and info["device"] is None, info

    # Agent mở liên kết kích hoạt trong trình duyệt mặc định.
    status, activation = browser.post("/api/devices/activation", body={"token": token})
    assert status == 200, activation
    ticket = activation["activate_url"].split("t=", 1)[1]
    assert browser.get(f"/activate?t={ticket}")[0] == 200  # 303 -> trang báo đã kích hoạt

    # Từ đây danh sách chứng thư tự hiện, không cần mã ghép cặp.
    status, info = browser.get("/api/agents")
    assert status == 200, info
    assert info["online"] is True
    assert info["device"]["platform"] == sys.platform
    assert info["certificates"][0]["subject"] == "NGUYEN VAN A"

    doc = create_document(api, pdf, [SIGNER_A])
    status, body = browser.post(
        f"{invite_path(doc, 0)}/sign",
        body={"cert_id": info["certificates"][0]["id"], "page": 1, "box": BOX_LEFT},
    )
    assert status == 200, body

    _, reports = api.get(f"/v1/documents/{doc['id']}/verify")
    assert reports[0]["signer"] == "NGUYEN VAN A"
    assert reports[0]["intact"] and reports[0]["trusted"]

    # Vé chỉ dùng một lần; và quên máy thì quay lại trạng thái chưa gắn.
    assert browser.get(f"/activate?t={ticket}")[0] == 400
    assert browser.delete("/api/devices/browser")[0] == 204
    assert browser.get("/api/agents")[1]["device"] is None


def test_khong_co_thiet_bi_lan_ma_thi_tu_choi_ky(lab, api, pdf):
    """Trình duyệt lạ không mượn được agent của người khác."""
    doc = create_document(api, pdf, [SIGNER_A])
    status, body = lab.main.client().post(
        f"{invite_path(doc, 0)}/sign",
        body={"cert_id": "bat-ky", "page": 1, "box": BOX_LEFT},
    )
    assert status == 404
    assert body["code"] == "agent_unavailable"
    assert "chưa gắn với máy nào" in body["detail"]


def test_agent_tu_noi_lai_khi_server_khoi_dong_lai(lab, api, pdf):
    """Deploy lại backend là chuyện thường; agent không được chết theo.

    Mã ghép cặp phải giữ nguyên để người ký không phải nhập lại trên web.
    """
    port = free_port()
    backend = lab.start_backend("backend-restart-1", port=port)
    lab.agent_with_pfx("121212", "signer-a.pfx", backend=backend)

    before = backend.client()
    assert before.get("/api/agents/121212/certificates")[0] == 200

    backend.process.stop()  # mô phỏng deploy: server biến mất
    restarted = lab.start_backend("backend-restart-2", port=port)
    client = restarted.client()

    wait_until(
        lambda: client.get("/api/agents/121212/certificates")[0] == 200,
        "agent nối lại sau khi server khởi động lại",
        timeout=60,
        interval=1.0,
    )

    # Nối lại thôi chưa đủ — phải ký được thật, trên dữ liệu còn nguyên trong DB.
    restarted_api = restarted.client(api_key=api.api_key)
    doc = create_document(restarted_api, pdf, [SIGNER_A])
    status, body = sign(client, invite_path(doc, 0), "121212")
    assert status == 200, body
    _, reports = restarted_api.get(f"/v1/documents/{doc['id']}/verify")
    assert reports[0]["intact"] and reports[0]["trusted"]


def test_rsa_pss_dung_salt_cua_server(lab, api, pdf):
    backend = lab.start_backend("backend-pss", WEBSIGNER_PREFER_PSS="1")
    lab.agent_with_pfx("777777", "signer-a.pfx", backend=backend)
    client = backend.client(api_key=api.api_key)

    doc = create_document(client, pdf, [SIGNER_A])
    status, body = sign(backend.client(), invite_path(doc, 0), "777777")
    assert status == 200, body

    _, reports = client.get(f"/v1/documents/{doc['id']}/verify")
    assert reports[0]["intact"] and reports[0]["trusted"]

    signed = client.download(f"/v1/documents/{doc['id']}/file")
    assert _signature_mechanism(signed) == "rsassa_pss"


def test_b_lta_co_dau_thoi_gian_tai_lieu(lab, api, pdf):
    backend = lab.start_backend("backend-lta", WEBSIGNER_PROFILE="B-LTA")
    lab.agent_with_pfx("888888", "signer-a.pfx", backend=backend)
    client = backend.client(api_key=api.api_key)

    doc = create_document(client, pdf, [SIGNER_A])
    assert sign(backend.client(), invite_path(doc, 0), "888888")[0] == 200

    _, reports = client.get(f"/v1/documents/{doc['id']}/verify")
    assert reports[0]["profile"] == "PAdES B-LTA"

    signed = client.download(f"/v1/documents/{doc['id']}/file")
    assert _has_document_timestamp(signed)


def test_khong_co_tsa_thi_chi_ky_duoc_b_b(lab, api, pdf):
    backend = lab.start_backend("backend-no-tsa", WEBSIGNER_TSA_URL="")
    lab.agent_with_pfx("666666", "signer-a.pfx", backend=backend)
    client = backend.client(api_key=api.api_key)

    _, config = backend.client().get("/api/config")
    assert config["profile"] == "B-B" and config["timestamping"] is False

    doc = create_document(client, pdf, [SIGNER_A])
    assert sign(backend.client(), invite_path(doc, 0), "666666")[0] == 200
    _, reports = client.get(f"/v1/documents/{doc['id']}/verify")
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


def _appearance_has_image(signed: bytes) -> bool:
    """Hình chữ ký có nhúng XObject ảnh (logo) hay không."""
    reader = _reader(signed)

    def deref(obj):
        return reader.get_object(obj.reference) if hasattr(obj, "reference") else obj

    def images_in(resources) -> bool:
        xobjects = deref(resources).get("/XObject")
        if xobjects is None:
            return False
        for entry in deref(xobjects).values():
            stream = deref(entry)
            if stream.get("/Subtype") == "/Image":
                return True
            nested = stream.get("/Resources")
            if nested is not None and images_in(nested):
                return True
        return False

    for embedded in reader.embedded_signatures:
        appearances = embedded.sig_field.get("/AP")
        if appearances is None:
            continue
        normal = deref(appearances).get("/N")
        if normal is None:
            continue
        resources = deref(normal).get("/Resources")
        if resources is not None and images_in(resources):
            return True
    return False


def _appearance_check_marks(signed: bytes) -> list[bool]:
    """Mỗi chữ ký: hình của nó có vẽ dấu tích chìm hay không."""
    reader = _reader(signed)

    def deref(obj):
        return reader.get_object(obj.reference) if hasattr(obj, "reference") else obj

    def has_mark(resources) -> bool:
        resources = deref(resources)
        # Dấu tích vẽ qua một ExtGState riêng để đặt độ mờ — có nó là có tích.
        if "/CheckMarkGS" in deref(resources.get("/ExtGState", {})):
            return True
        for entry in deref(resources.get("/XObject", {})).values():
            nested = deref(entry).get("/Resources")
            if nested is not None and has_mark(nested):
                return True
        return False

    marks = []
    for embedded in reader.embedded_signatures:
        appearances = embedded.sig_field.get("/AP")
        normal = deref(appearances).get("/N") if appearances is not None else None
        if normal is not None:
            marks.append(has_mark(deref(normal).get("/Resources", {})))
    return marks
