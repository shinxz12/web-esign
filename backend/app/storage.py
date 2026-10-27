"""Tệp PDF theo revision: ``documents/<doc_id>/rev<N>.pdf``.

Hai nơi chứa, cùng một giao diện:

* Cloudflare R2 (S3) khi đặt ``CLOUDFLARE_R2_BUCKET`` — container không giữ
  trạng thái, deploy lại không mất tệp;
* đĩa cục bộ ``<data>/documents`` khi không đặt — chạy dev/test không cần mạng.

Siêu dữ liệu nằm trong PostgreSQL; ở đây chỉ có byte. Ghi trên đĩa đi qua tệp
tạm rồi ``rename``; trên R2 một PUT là nguyên tử sẵn.
"""

from __future__ import annotations

import functools
import os
import re
import shutil

from .config import DATA_DIR, DOCUMENTS_DIR

DOC_ID_RE = re.compile(r"^doc_[0-9a-f]{16}$")

R2_BUCKET = os.environ.get("CLOUDFLARE_R2_BUCKET") or None
R2_ACCOUNT_ID = os.environ.get("CLOUDFLARE_R2_ACCOUNT_ID", "")
# Bucket có thể dùng chung với dự án khác: mọi khoá nằm dưới tiền tố riêng.
R2_PREFIX = os.environ.get("WEBSIGNER_R2_PREFIX", "web-signer/")


class StorageMissing(FileNotFoundError):
    pass


def _key(doc_id: str, revision: int | None = None) -> str:
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


def write_revision(doc_id: str, revision: int, data: bytes) -> None:
    key = _key(doc_id, revision)
    if R2_BUCKET:
        _s3().put_object(Bucket=R2_BUCKET, Key=R2_PREFIX + key, Body=data, ContentType="application/pdf")
        return
    target = DATA_DIR / key  # = <data>/documents/<doc_id>/rev<N>.pdf
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".pdf.tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(target)


def read_revision(doc_id: str, revision: int) -> bytes:
    key = _key(doc_id, revision)
    if R2_BUCKET:
        client = _s3()
        try:
            return client.get_object(Bucket=R2_BUCKET, Key=R2_PREFIX + key)["Body"].read()
        except client.exceptions.NoSuchKey:
            raise StorageMissing(key) from None
    path = DATA_DIR / key
    if not path.is_file():
        raise StorageMissing(key)
    return path.read_bytes()


def delete_document(doc_id: str) -> None:
    prefix = _key(doc_id)
    if R2_BUCKET:
        client = _s3()
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=R2_BUCKET, Prefix=R2_PREFIX + prefix):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                client.delete_objects(Bucket=R2_BUCKET, Delete={"Objects": objects})
        return
    shutil.rmtree(DATA_DIR / prefix, ignore_errors=True)
