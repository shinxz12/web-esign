"""Kiểm thử vận hành đa tiến trình (multi-instance / horizontal scaling)
chạy 2 uvicorn processes trên cùng một PostgreSQL database:

1. Agent kết nối vào Instance A (dùng SoftHSM PKCS#11).
   Yêu cầu ký số phục vụ bởi Instance B thành công qua Postgres relay (LISTEN/NOTIFY).
2. Hai yêu cầu ký đồng thời vào 2 instances cho cùng 1 tài liệu -> một bên nhận 409 signing_in_progress.
3. Vé kích hoạt (activation ticket) cấp trên Instance A, đổi lấy cookie thiết bị trên Instance B.
4. Giới hạn tần suất (rate limit) được chia sẻ giữa các instances qua PostgreSQL.
"""

from __future__ import annotations

import concurrent.futures
import pathlib
import sys
import uuid

import pytest

from harness import (
    SIGNER_A,
    Client,
    Lab,
    api_client,
    create_document,
    free_port,
    invite_path,
    make_softhsm_token,
    postgres_available,
    register,
    sign,
    softhsm_module,
    wait_until,
)
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))



@pytest.fixture(scope="module")
def multi_lab(tmp_path_factory):
    if not postgres_available():
        pytest.skip("cần PostgreSQL (đặt WEBSIGNER_TEST_ADMIN_DSN)")
    lab = Lab(tmp_path_factory.mktemp("websigner-multi"))
    lab.setup()
    try:
        yield lab
    finally:
        lab.teardown()


@pytest.fixture(scope="module")
def cluster(multi_lab):
    be_a = multi_lab.start_backend("be-multi-a")
    be_b = multi_lab.start_backend("be-multi-b")
    owner = register(be_a, lab=multi_lab)
    api = api_client(owner)
    return {"a": be_a, "b": be_b, "owner": owner, "api": api}


@pytest.fixture(scope="module")
def pdf(multi_lab) -> bytes:
    return multi_lab.sample.read_bytes()


@pytest.mark.skipif(softhsm_module() is None, reason="chưa cài softhsm2")
def test_multi_instance_agent_relay_and_signing(multi_lab, cluster, pdf):
    """Agent cắm vào Instance A (SoftHSM PKCS#11), người ký gửi request HTTP sang Instance B."""
    be_a = cluster["a"]
    be_b = cluster["b"]
    api = cluster["api"]

    code = "789123"
    env = make_softhsm_token(multi_lab, "signer-a.pfx", "MULTI-HSM")
    multi_lab.start_agent(
        code,
        "--pkcs11",
        softhsm_module(),
        "--token-label",
        "MULTI-HSM",
        "--pin",
        "123456",
        backend=be_a,
        env=env,
    )

    # 1. Trình duyệt hỏi danh sách chứng thư của agent qua Instance B
    client_b = be_b.client()
    status, info = client_b.get(f"/api/agents/{code}/certificates")
    assert status == 200, info
    assert info["agent"]
    assert len(info["certificates"]) > 0

    # 2. Tạo tài liệu và ký qua Instance B
    api_b = be_b.client(api_key=api.api_key)
    doc = create_document(api_b, pdf, [SIGNER_A])
    link = invite_path(doc, 0)

    status, res = sign(client_b, link, code)
    assert status == 200, res

    # 3. Kiểm tra chữ ký PAdES qua API verify của Instance B
    status, reports = api_b.get(f"/v1/documents/{doc['id']}/verify")
    assert status == 200, reports
    assert len(reports) == 1
    assert reports[0]["intact"] and reports[0]["trusted"]
    assert reports[0]["signer"] == "NGUYEN VAN A"


def test_multi_instance_concurrent_signers_409(multi_lab, cluster, pdf):
    """Hai lượt ký song song trên 2 instances cho cùng tài liệu -> một bên nhận 409 signing_in_progress."""
    be_a = cluster["a"]
    be_b = cluster["b"]
    api = cluster["api"]

    api_a = be_a.client(api_key=api.api_key)
    doc = create_document(api_a, pdf, [SIGNER_A])
    doc_id = doc["id"]

    # Giữ advisory lock trên cơ sở dữ liệu mô phỏng Instance A đang trong quá trình prepare->sign->finalize
    import psycopg
    with psycopg.connect(multi_lab.db_url, autocommit=True) as lock_conn:
        cur = lock_conn.execute("SELECT pg_try_advisory_lock(hashtext('doc_lock'), hashtext(%s))", (doc_id,))
        locked = cur.fetchone()[0]
        assert locked is True

        # Lấy cert_id hợp lệ của agent
        code = "789123"
        _, info = be_b.client().get(f"/api/agents/{code}/certificates")
        cert_id = info["certificates"][0]["id"]

        # Khi lock đang bị giữ, request ký gửi sang Instance B phải nhận 409 ngay lập tức
        client_b = be_b.client()
        status, res = client_b.post(
            f"{invite_path(doc, 0)}/sign",
            {"agent_code": code, "cert_id": cert_id, "page": 0, "box": [50, 50, 200, 100]},
        )
        assert status == 409, res
        assert res["code"] == "signing_in_progress"

        # Tương tự gửi sang Instance A cũng bị chặn 409
        client_a = be_a.client()
        status_a, res_a = client_a.post(
            f"{invite_path(doc, 0)}/sign",
            {"agent_code": code, "cert_id": cert_id, "page": 0, "box": [50, 50, 200, 100]},
        )
        assert status_a == 409, res_a
        assert res_a["code"] == "signing_in_progress"
        # Giải phóng lock
        lock_conn.execute("SELECT pg_advisory_unlock(hashtext('doc_lock'), hashtext(%s))", (doc_id,))


def test_multi_instance_activation_ticket_a_to_b(cluster):
    """Vé kích hoạt cấp trên Instance A, đổi cookie thiết bị thành công trên Instance B."""
    be_a = cluster["a"]
    be_b = cluster["b"]

    token = f"tok-device-{uuid.uuid4().hex}"
    status, res = be_a.client().post(
        "/api/devices",
        {"token": token, "name": "Workstation-A", "platform": "Darwin"},
    )
    assert status == 201, res
    activate_url = res["activate_url"]
    ticket = activate_url.split("t=", 1)[1]

    # Đổi vé trên Instance B
    client_b = be_b.client()
    status_b, _ = client_b.get(f"/activate?t={ticket}")
    assert status_b == 200

    # Kiểm tra cookie thiết bị đã được nhận diện trên Instance B
    status_dev, dev_info = client_b.get("/api/agents")
    assert status_dev == 200
    assert dev_info["device"] is not None
    assert dev_info["device"]["id"] == res["device"]["id"]
    # Dùng lại vé đã đổi trên Instance A -> bị từ chối 400 invalid_ticket
    client_a = be_a.client()
    status_a, res_a = client_a.get(f"/activate?t={ticket}")
    assert status_a == 400
    assert res_a["code"] == "invalid_ticket"


def test_multi_instance_rate_limit_shared(cluster):
    """Giới hạn tần suất được chia sẻ giữa 2 instances qua PostgreSQL."""
    be_a = cluster["a"]
    be_b = cluster["b"]

    # Endpoint /auth/forgot có limit 5 req/min theo IP client
    # Gửi xen kẽ: 3 request tới A, 2 request tới B (tổng cộng 5 = hết quota)
    for i in range(3):
        status, _ = be_a.client().post("/api/auth/forgot", {"email": f"rate-{i}@demo.vn"})
        assert status == 202

    for i in range(2):
        status, _ = be_b.client().post("/api/auth/forgot", {"email": f"rate-b-{i}@demo.vn"})
        assert status == 202

    # Request thứ 6 tới Instance A -> 429 rate_limited
    status_6, res_6 = be_a.client().post("/api/auth/forgot", {"email": "rate-overflow-a@demo.vn"})
    assert status_6 == 429, res_6
    assert res_6["code"] == "rate_limited"

    # Request thứ 7 tới Instance B -> 429 rate_limited
    status_7, res_7 = be_b.client().post("/api/auth/forgot", {"email": "rate-overflow-b@demo.vn"})
    assert status_7 == 429, res_7
    assert res_7["code"] == "rate_limited"
