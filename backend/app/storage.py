"""Tệp PDF theo revision: ``t/<org_id>/documents/<doc_id>/rev<N>.pdf`` (SPEC §4).

Hỗ trợ:
* Cloudflare R2 (S3) khi đặt ``CLOUDFLARE_R2_BUCKET``;
* đĩa cục bộ ``<data>/documents`` khi không đặt.

Đọc có fallback về định dạng cũ ``documents/<doc_id>/rev<N>.pdf`` để không gián đoạn
các tài liệu đã tồn tại trước khi nâng cấp.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
from typing import Any

from . import config
from .config import DOCUMENTS_DIR

DOC_ID_RE = re.compile(r"^doc_[0-9a-f]{16}$")

R2_BUCKET = os.environ.get("CLOUDFLARE_R2_BUCKET") or None
R2_ACCOUNT_ID = os.environ.get("CLOUDFLARE_R2_ACCOUNT_ID", "")
R2_PREFIX = os.environ.get("WEBSIGNER_R2_PREFIX", "web-signer/")


class StorageMissing(FileNotFoundError):
    pass


def _tenant_key(org_id: str, doc_id: str, revision: int | None = None) -> str:
    if not DOC_ID_RE.match(doc_id):
        raise ValueError(f"doc_id không hợp lệ: {doc_id!r}")
    base = f"t/{org_id}/documents/{doc_id}/"
    return base if revision is None else f"{base}rev{int(revision)}.pdf"


def _legacy_key(doc_id: str, revision: int | None = None) -> str:
    if not DOC_ID_RE.match(doc_id):
        raise ValueError(f"doc_id không hợp lệ: {doc_id!r}")
    base = f"documents/{doc_id}/"
    return base if revision is None else f"{base}rev{int(revision)}.pdf"


def backend_name() -> str:
    return f"R2 {R2_BUCKET}/{R2_PREFIX}" if R2_BUCKET else f"đĩa {DOCUMENTS_DIR}"


@functools.cache
def _s3():
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=os.environ["CLOUDFLARE_R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["CLOUDFLARE_R2_SECRET_ACCESS_KEY"],
        region_name="auto",
        config=Config(retries={"max_attempts": 4, "mode": "standard"}, max_pool_connections=20),
    )


def write_revision(
    org_id_or_doc_id: str,
    doc_id_or_rev: str | int,
    revision_or_data: int | bytes,
    data: bytes | None = None,
) -> None:
    """Ghi revision mới theo tiền tố t/<org_id>/documents/<doc_id>/rev<N>.pdf."""
    from . import db

    if data is not None:
        org_id = org_id_or_doc_id
        doc_id = str(doc_id_or_rev)
        revision = int(revision_or_data)
        content = data
    else:
        # Trường hợp gọi 3 tham số kiểu cũ: write_revision(doc_id, revision, data)
        doc_id = org_id_or_doc_id
        revision = int(doc_id_or_rev)
        content = revision_or_data  # type: ignore[assignment]
        org_id = db.current_tenant_id() or "legacy"

    key = _tenant_key(org_id, doc_id, revision)
    if R2_BUCKET:
        _s3().put_object(Bucket=R2_BUCKET, Key=R2_PREFIX + key, Body=content, ContentType="application/pdf")
        return
    target = config.DATA_DIR / key
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".pdf.tmp")
    with open(tmp, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(target)


def read_revision(
    org_id_or_doc_id: str,
    doc_id_or_rev: str | int,
    revision: int | None = None,
) -> bytes:
    """Đọc revision: tìm ở t/<org_id>/... trước, nếu không thấy fallback sang documents/..."""
    from . import db

    if revision is not None:
        org_id = org_id_or_doc_id
        doc_id = str(doc_id_or_rev)
        rev = int(revision)
    else:
        doc_id = org_id_or_doc_id
        rev = int(doc_id_or_rev)
        org_id = db.current_tenant_id() or ""

    # 1. Thử đọc khoá mới có org_id
    if org_id:
        tenant_k = _tenant_key(org_id, doc_id, rev)
        if R2_BUCKET:
            client = _s3()
            try:
                return client.get_object(Bucket=R2_BUCKET, Key=R2_PREFIX + tenant_k)["Body"].read()
            except client.exceptions.NoSuchKey:
                pass
        else:
            path = config.DATA_DIR / tenant_k
            if path.is_file():
                return path.read_bytes()

    # 2. Fallback sang đường dẫn cũ không có org_id
    legacy_k = _legacy_key(doc_id, rev)
    if R2_BUCKET:
        client = _s3()
        try:
            return client.get_object(Bucket=R2_BUCKET, Key=R2_PREFIX + legacy_k)["Body"].read()
        except client.exceptions.NoSuchKey:
            raise StorageMissing(legacy_k) from None
    path = config.DATA_DIR / legacy_k
    if not path.is_file():
        raise StorageMissing(legacy_k)
    return path.read_bytes()


def delete_document(org_id_or_doc_id: str, doc_id: str | None = None) -> None:
    """Xoá toàn bộ revision của tài liệu ở cả thư mục mới và cũ."""
    from . import db

    if doc_id is not None:
        target_doc_id = doc_id
        org_id = org_id_or_doc_id
    else:
        target_doc_id = org_id_or_doc_id
        org_id = db.current_tenant_id() or ""

    prefixes_to_delete = [_legacy_key(target_doc_id)]
    if org_id:
        prefixes_to_delete.append(_tenant_key(org_id, target_doc_id))

    if R2_BUCKET:
        client = _s3()
        for p in prefixes_to_delete:
            for page in client.get_paginator("list_objects_v2").paginate(Bucket=R2_BUCKET, Prefix=R2_PREFIX + p):
                objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objects:
                    client.delete_objects(Bucket=R2_BUCKET, Delete={"Objects": objects})
        return

    for p in prefixes_to_delete:
        shutil.rmtree(config.DATA_DIR / p, ignore_errors=True)


async def migrate_storage(dry_run: bool = False) -> dict[str, int]:
    """Sao chép tệp PDF từ layout cũ (documents/<doc_id>/rev<N>.pdf)

    sang layout mới (t/<org_id>/documents/<doc_id>/rev<N>.pdf) một cách idempotent.
    """
    from . import db

    rows = await db.system_fetchall("SELECT id, org_id, revision FROM documents")
    total_examined = 0
    migrated = 0
    would_migrate = 0
    already_migrated = 0
    missing = 0

    for row in rows:
        doc_id = row["id"]
        org_id = row["org_id"]
        max_rev = row["revision"]

        for rev in range(max_rev + 1):
            total_examined += 1
            new_key = _tenant_key(org_id, doc_id, rev)
            old_key = _legacy_key(doc_id, rev)

            if R2_BUCKET:
                client = _s3()
                # Kiểm tra xem new_key đã có chưa
                new_exists = False
                try:
                    client.head_object(Bucket=R2_BUCKET, Key=R2_PREFIX + new_key)
                    new_exists = True
                except Exception:
                    pass

                if new_exists:
                    already_migrated += 1
                    continue

                # Kiểm tra old_key
                old_exists = False
                try:
                    client.head_object(Bucket=R2_BUCKET, Key=R2_PREFIX + old_key)
                    old_exists = True
                except Exception:
                    pass

                if not old_exists:
                    missing += 1
                    continue

                if dry_run:
                    would_migrate += 1
                else:
                    client.copy_object(
                        Bucket=R2_BUCKET,
                        CopySource={"Bucket": R2_BUCKET, "Key": R2_PREFIX + old_key},
                        Key=R2_PREFIX + new_key,
                    )
                    migrated += 1
            else:
                new_path = config.DATA_DIR / new_key
                old_path = config.DATA_DIR / old_key

                if new_path.is_file():
                    already_migrated += 1
                    continue

                if not old_path.is_file():
                    missing += 1
                    continue

                if dry_run:
                    would_migrate += 1
                else:
                    new_path.parent.mkdir(parents=True, exist_ok=True)
                    tmp_target = new_path.with_suffix(".tmp")
                    data = old_path.read_bytes()
                    with open(tmp_target, "wb") as f:
                        f.write(data)
                        f.flush()
                        os.fsync(f.fileno())
                    tmp_target.replace(new_path)
                    migrated += 1
    return {
        "examined": total_examined,
        "migrated": migrated,
        "would_migrate": would_migrate,
        "already_migrated": already_migrated,
        "missing": missing,
    }
