"""Quản trị nền tảng từ dòng lệnh — không mở thêm bề mặt tấn công trên web.

    cd backend
    python -m app.admin orgs
    python -m app.admin create-org "Công ty A" owner@a.vn "Nguyễn Văn A" --plan business
    python -m app.admin set-plan org_1234abcd business
    python -m app.admin import-legacy org_1234abcd
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys

from . import accounts, audit, config, db, documents, plans, security, storage


async def _orgs() -> None:
    rows = await db.fetchall(
        "SELECT o.id, o.name, o.plan, o.created_at, "
        "  (SELECT count(*) FROM users u WHERE u.org_id = o.id) AS members, "
        "  COALESCE(c.documents, 0) AS documents, COALESCE(c.signatures, 0) AS signatures "
        "FROM organizations o LEFT JOIN usage_counters c "
        "  ON c.org_id = o.id AND c.period = %s ORDER BY o.created_at",
        (plans.current_period(),),
    )
    print(f"{'ID':<22} {'GÓI':<11} {'TV':>3} {'TL/tháng':>8} {'CK/tháng':>8}  TÊN")
    for r in rows:
        print(f"{r['id']:<22} {r['plan']:<11} {r['members']:>3} {r['documents']:>8} {r['signatures']:>8}  {r['name']}")


async def _set_plan(org_id: str, plan: str) -> None:
    if plan not in plans.PLANS:
        sys.exit(f"Gói không tồn tại. Chọn một trong: {', '.join(plans.PLANS)}")
    if not await db.execute("UPDATE organizations SET plan = %s WHERE id = %s", (plan, org_id)):
        sys.exit(f"Không có tổ chức {org_id}")
    print(f"{org_id} -> {plan}")


async def _create_org(name: str, email: str, owner_name: str, plan: str, base_url: str) -> None:
    if plan not in plans.PLANS:
        sys.exit(f"Gói không tồn tại. Chọn một trong: {', '.join(plans.PLANS)}")
    email = accounts.normalize_email(email)
    org_id, user_id = security.new_id("org"), security.new_id("usr")
    async with db.transaction() as conn:
        await conn.execute(
            "INSERT INTO organizations (id, name, plan) VALUES (%s, %s, %s)", (org_id, name, plan)
        )
        await conn.execute(
            "INSERT INTO users (id, org_id, email, name, role) VALUES (%s, %s, %s, %s, 'owner')",
            (user_id, org_id, email, owner_name),
        )
        token = await accounts.issue_user_token(conn, user_id, "invite", accounts.INVITE_TTL)
    print(f"Tổ chức {org_id} ({plan}). Chủ tổ chức đặt mật khẩu tại (hạn 7 ngày):")
    print(f"  {base_url.rstrip('/')}/#/invite?t={token}")


def _legacy_recipients(meta: dict) -> list[dict]:
    """Bản cũ: luồng có thứ tự (signers) hoặc ký tự do (chỉ có signatures)."""
    signatures = meta.get("signatures") or []
    if meta.get("signers"):
        out = []
        for index, slot in enumerate(meta["signers"]):
            record = next((s for s in signatures if slot.get("signed_at") and s["signed_at"] == slot["signed_at"]), None)
            out.append({"name": slot["name"], "tax_code": slot.get("tax_code"), "order": index + 1,
                        "signed": bool(slot.get("signed_at")), "record": record, "position": index})
        return out
    return [
        {"name": s["signer"], "tax_code": s.get("tax_code"), "order": i + 1, "signed": True, "record": s, "position": i}
        for i, s in enumerate(signatures)
    ]


async def _import_legacy(org_id: str) -> None:
    """Đưa tài liệu của bản chạy bằng tệp (``documents/<16 hex>/meta.json``) vào một tổ chức.

    Bản cũ không có tài khoản — chủ tài liệu chỉ là cookie ẩn danh — nên người
    vận hành chọn tổ chức nhận. Liên kết mời cũ không còn dùng được; liên kết
    mới lấy từ API (``signing_url``).
    """
    await accounts.get_org(org_id)
    imported = 0
    for legacy_dir in sorted(config.DOCUMENTS_DIR.iterdir()):
        meta_path = legacy_dir / "meta.json"
        if not (legacy_dir.is_dir() and len(legacy_dir.name) == 16 and meta_path.is_file()):
            continue
        doc_id = f"doc_{legacy_dir.name}"
        if await db.fetchone("SELECT 1 FROM documents WHERE id = %s", (doc_id,)):
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        revisions = sorted(legacy_dir.glob("rev*.pdf"), key=lambda p: int(p.stem[3:]))
        if not revisions:
            continue
        page_count = documents.inspect_pdf_sync(revisions[0].read_bytes())
        recipients = _legacy_recipients(meta)
        if not recipients:
            status = "draft"
        elif all(r["signed"] for r in recipients):
            status = "completed"
        else:
            status = "in_progress"

        for path in revisions:  # lên R2 nếu đã cấu hình, nếu không thì sang thư mục mới
            storage.write_revision(doc_id, int(path.stem[3:]), path.read_bytes())

        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO documents (id, org_id, title, filename, status, revision, page_count, "
                "created_at, sent_at, completed_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    doc_id, org_id, meta["name"].removesuffix(".pdf"), meta["name"], status,
                    meta.get("revision", len(revisions) - 1), page_count, meta["created_at"],
                    meta["created_at"] if status != "draft" else None,
                    (recipients[-1]["record"] or {}).get("signed_at") if status == "completed" else None,
                ),
            )
            for path in revisions:
                data = path.read_bytes()
                await conn.execute(
                    "INSERT INTO revisions (document_id, revision, sha256, size) VALUES (%s, %s, %s, %s)",
                    (doc_id, int(path.stem[3:]), hashlib.sha256(data).digest(), len(data)),
                )
            for r in recipients:
                rid = security.new_id("rcp")
                record = r["record"] or {}
                await conn.execute(
                    "INSERT INTO recipients (id, document_id, position, routing_order, role, name, tax_code, "
                    "token_hash, status, acted_at, signed_by, signer_tax_code, sig_field, sig_page, sig_profile) "
                    "VALUES (%s, %s, %s, %s, 'signer', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        rid, doc_id, r["position"], r["order"], r["name"], r["tax_code"],
                        security.token_hash(security.recipient_token(rid, 1)),
                        "signed" if r["signed"] else "pending",
                        record.get("signed_at"), record.get("signer"), record.get("tax_code"),
                        record.get("field_name"), record.get("page"), record.get("profile"),
                    ),
                )
            await audit.append(
                conn, doc_id, "document.imported", "system",
                {"legacy_id": legacy_dir.name, "revisions": len(revisions), "status": status},
            )
        imported += 1
        print(f"  {legacy_dir.name} -> {doc_id} ({status})")
    print(f"Đã nhập {imported} tài liệu vào {org_id}. Thư mục cũ giữ nguyên, xoá tay khi đã kiểm tra.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.admin", description="Quản trị Web Signer")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("orgs", help="liệt kê tổ chức, gói và lượt dùng tháng này")
    p = sub.add_parser("set-plan", help="đổi gói dịch vụ")
    p.add_argument("org_id")
    p.add_argument("plan", choices=list(plans.PLANS))
    p = sub.add_parser("create-org", help="tạo tổ chức + liên kết đặt mật khẩu cho chủ")
    p.add_argument("name")
    p.add_argument("owner_email")
    p.add_argument("owner_name")
    p.add_argument("--plan", default="free", choices=list(plans.PLANS))
    p.add_argument("--base-url", default=config.public_url() or "http://127.0.0.1:8000")
    p = sub.add_parser("import-legacy", help="nhập tài liệu của bản lưu bằng tệp vào một tổ chức")
    p.add_argument("org_id")
    args = parser.parse_args(argv)

    async def run() -> None:
        await db.open_pool()
        try:
            if args.command == "orgs":
                await _orgs()
            elif args.command == "set-plan":
                await _set_plan(args.org_id, args.plan)
            elif args.command == "create-org":
                await _create_org(args.name, args.owner_email, args.owner_name, args.plan, args.base_url)
            elif args.command == "import-legacy":
                await _import_legacy(args.org_id)
        finally:
            await db.close_pool()

    asyncio.run(run())


if __name__ == "__main__":
    main()
