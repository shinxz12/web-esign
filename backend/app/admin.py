"""Quản trị nền tảng từ dòng lệnh — không mở thêm bề mặt tấn công trên web.

    cd backend
    python -m app.admin orgs
    python -m app.admin create-org "Công ty A" owner@a.vn "Nguyễn Văn A" --plan business
    python -m app.admin set-plan org_1234abcd business
    python -m app.admin import-legacy org_1234abcd
    python -m app.admin create-partner "Đối tác X"
    python -m app.admin list-partners
    python -m app.admin attach-partner org_1234abcd prt_5678efgh
    python -m app.admin rewrap-secrets
    python -m app.admin migrate-storage [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys

from . import accounts, audit, config, db, documents, plans, secrets_crypto, security, storage


async def _orgs() -> None:
    rows = await db.system_fetchall(
        "SELECT o.id, o.name, o.plan, o.created_at, "
        "  (SELECT count(*) FROM memberships m WHERE m.org_id = o.id) AS members, "
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
    if not await db.system_execute("UPDATE organizations SET plan = %s WHERE id = %s", (plan, org_id)):
        sys.exit(f"Không có tổ chức {org_id}")
    print(f"{org_id} -> {plan}")


async def _create_org(name: str, email: str, owner_name: str, plan: str, base_url: str) -> None:
    if plan not in plans.PLANS:
        sys.exit(f"Gói không tồn tại. Chọn một trong: {', '.join(plans.PLANS)}")
    email = accounts.normalize_email(email)
    org_id, user_id = security.new_id("org"), security.new_id("usr")

    signing_key = secrets_crypto.new_signing_key()
    key_ciphertext, kek_id = secrets_crypto.encrypt_secret(signing_key)

    async with db.system_transaction() as conn:
        await conn.execute(
            "INSERT INTO organizations (id, name, plan, signing_key_ciphertext, signing_key_kek_id, signing_key_scheme) "
            "VALUES (%s, %s, %s, %s, %s, 'kek')",
            (org_id, name, plan, key_ciphertext, kek_id),
        )
        cur_u = await conn.execute("SELECT * FROM users WHERE lower(email) = %s", (email,))
        existing_u = await cur_u.fetchone()
        if existing_u is None:
            await conn.execute(
                "INSERT INTO users (id, email, name, password_hash) VALUES (%s, %s, %s, NULL)",
                (user_id, email, owner_name),
            )
        else:
            user_id = existing_u["id"]

        await conn.execute(
            "INSERT INTO memberships (user_id, org_id, role) VALUES (%s, %s, 'owner')",
            (user_id, org_id),
        )
        token = await accounts.issue_user_token(conn, user_id, "invite", accounts.INVITE_TTL)
    print(f"Tổ chức {org_id} ({plan}). Chủ tổ chức đặt mật khẩu tại (hạn 7 ngày):")
    print(f"  {base_url.rstrip('/')}/#/invite?t={token}")


async def _create_partner(name: str) -> None:
    partner_id = security.new_id("prt")
    token = "wsp_live_" + security.random_token(32)
    prefix = token[: len("wsp_live_") + 6]
    key_hash = security.token_hash(token)

    await db.system_execute(
        "INSERT INTO partners (id, name, prefix, key_hash) VALUES (%s, %s, %s, %s)",
        (partner_id, name.strip(), prefix, key_hash),
    )
    print(f"Đã tạo đối tác {partner_id} ({name}):")
    print(f"  Khoá API đối tác (chỉ hiện một lần duy nhất): {token}")


async def _attach_partner(org_id: str, partner_id: str) -> None:
    p = await db.system_fetchone("SELECT * FROM partners WHERE id = %s", (partner_id,))
    if not p:
        sys.exit(f"Không tìm thấy đối tác {partner_id}")
    o = await db.system_fetchone("SELECT * FROM organizations WHERE id = %s", (org_id,))
    if not o:
        sys.exit(f"Không tìm thấy tổ chức {org_id}")

    await db.system_execute(
        "UPDATE organizations SET partner_id = %s WHERE id = %s",
        (partner_id, org_id),
    )
    print(f"Đã gắn tổ chức {org_id} ({o['name']}) vào đối tác {partner_id} ({p['name']})")


async def _list_partners() -> None:
    rows = await db.system_fetchall(
        "SELECT p.id, p.name, p.created_at, count(o.id) AS tenants "
        "FROM partners p LEFT JOIN organizations o ON o.partner_id = p.id "
        "GROUP BY p.id, p.name, p.created_at ORDER BY p.created_at"
    )
    print(f"{'ID':<22} {'TENANTS':>7}  TÊN")
    for r in rows:
        print(f"{r['id']:<22} {r['tenants']:>7}  {r['name']}")


async def _rewrap_secrets() -> None:
    target_kek_id = secrets_crypto.current_kek_id()
    endpoints = await db.system_fetchall(
        "SELECT id, secret_ciphertext, kek_id, prev_secret_ciphertext "
        "FROM webhook_endpoints WHERE secret_scheme = 'kek' AND secret_ciphertext IS NOT NULL AND kek_id <> %s",
        (target_kek_id,),
    )
    rewrapped_wh = 0
    for wh in endpoints:
        plain = secrets_crypto.decrypt_secret(wh["secret_ciphertext"], wh["kek_id"])
        new_ct, kid = secrets_crypto.encrypt_secret(plain, target_kek_id)
        new_prev_ct = None
        if wh.get("prev_secret_ciphertext"):
            try:
                plain_prev = secrets_crypto.decrypt_secret(wh["prev_secret_ciphertext"], wh["kek_id"])
                new_prev_ct, _ = secrets_crypto.encrypt_secret(plain_prev, target_kek_id)
            except Exception:
                pass
        await db.system_execute(
            "UPDATE webhook_endpoints SET secret_ciphertext = %s, kek_id = %s, prev_secret_ciphertext = %s WHERE id = %s",
            (new_ct, kid, new_prev_ct, wh["id"]),
        )
        rewrapped_wh += 1

    orgs = await db.system_fetchall(
        "SELECT id, signing_key_ciphertext, signing_key_kek_id "
        "FROM organizations WHERE signing_key_scheme = 'kek' AND signing_key_ciphertext IS NOT NULL AND signing_key_kek_id <> %s",
        (target_kek_id,),
    )
    rewrapped_org = 0
    for org in orgs:
        plain_key = secrets_crypto.decrypt_secret(org["signing_key_ciphertext"], org["signing_key_kek_id"])
        new_ct, kid = secrets_crypto.encrypt_secret(plain_key, target_kek_id)
        await db.system_execute(
            "UPDATE organizations SET signing_key_ciphertext = %s, signing_key_kek_id = %s WHERE id = %s",
            (new_ct, kid, org["id"]),
        )
        rewrapped_org += 1

    print(f"Đã rewrap bí mật sang KEK '{target_kek_id}': {rewrapped_wh} webhook endpoints, {rewrapped_org} organizations")


async def _migrate_storage(dry_run: bool) -> None:
    res = await storage.migrate_storage(dry_run=dry_run)
    prefix = "[DRY-RUN] " if dry_run else ""
    print(f"{prefix}Kết quả di chuyển lưu trữ:")
    print(f"  Tổng số revision kiểm tra: {res['examined']}")
    if dry_run:
        print(f"  Số tệp sẽ chuyển:        {res['would_migrate']}")
    else:
        print(f"  Số tệp đã chuyển:        {res['migrated']}")
    print(f"  Số tệp đã có ở layout mới: {res['already_migrated']}")
    print(f"  Số tệp không tìm thấy:     {res['missing']}")


def _legacy_recipients(meta: dict) -> list[dict]:
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
    org = await db.system_fetchone("SELECT * FROM organizations WHERE id = %s", (org_id,))
    if not org:
        sys.exit(f"Không tìm thấy tổ chức {org_id}")
    imported = 0
    for legacy_dir in sorted(config.DOCUMENTS_DIR.iterdir()):
        meta_path = legacy_dir / "meta.json"
        if not (legacy_dir.is_dir() and len(legacy_dir.name) == 16 and meta_path.is_file()):
            continue
        doc_id = f"doc_{legacy_dir.name}"
        if await db.system_fetchone("SELECT 1 FROM documents WHERE id = %s", (doc_id,)):
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

        for path in revisions:
            storage.write_revision(org_id, doc_id, int(path.stem[3:]), path.read_bytes())

        async with db.system_transaction() as conn:
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
                    "INSERT INTO revisions (org_id, document_id, revision, sha256, size) VALUES (%s, %s, %s, %s, %s)",
                    (org_id, doc_id, int(path.stem[3:]), hashlib.sha256(data).digest(), len(data)),
                )
            for r in recipients:
                rid = security.new_id("rcp")
                record = r["record"] or {}
                await conn.execute(
                    "INSERT INTO recipients (id, org_id, document_id, position, routing_order, role, name, tax_code, "
                    "token_hash, status, acted_at, signed_by, signer_tax_code, sig_field, sig_page, sig_profile) "
                    "VALUES (%s, %s, %s, %s, %s, 'signer', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        rid, org_id, doc_id, r["position"], r["order"], r["name"], r["tax_code"],
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

    p = sub.add_parser("create-partner", help="tạo đối tác mới và in khoá wsp_live_...")
    p.add_argument("name")

    p = sub.add_parser("attach-partner", help="gắn một tổ chức vào đối tác")
    p.add_argument("org_id")
    p.add_argument("partner_id")

    sub.add_parser("list-partners", help="danh sách đối tác")

    sub.add_parser("rewrap-secrets", help="rewrap các bí mật theo KEK mới nhất")

    p = sub.add_parser("migrate-storage", help="chuyển đổi tệp PDF sang layout t/<org_id>/...")
    p.add_argument("--dry-run", action="store_true", help="chỉ kiểm tra và đếm, không sao chép")

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
            elif args.command == "create-partner":
                await _create_partner(args.name)
            elif args.command == "attach-partner":
                await _attach_partner(args.org_id, args.partner_id)
            elif args.command == "list-partners":
                await _list_partners()
            elif args.command == "rewrap-secrets":
                await _rewrap_secrets()
            elif args.command == "migrate-storage":
                await _migrate_storage(dry_run=args.dry_run)
        finally:
            await db.close_pool()

    asyncio.run(run())


if __name__ == "__main__":
    main()
