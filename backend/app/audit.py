"""Nhật ký kiểm toán của từng tài liệu, nối thành chuỗi băm.

Mỗi sự kiện băm ``SHA-256(hash_trước ‖ JSON chuẩn hoá)``. Sửa, xoá hay chèn
một dòng giữa chừng đều làm đứt chuỗi từ chỗ đó trở đi. Hệ thống tích hợp lưu
``head`` (băm cuối) ở phía mình thì phát hiện được cả việc viết lại toàn bộ.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from . import db


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def chain_hash(prev_hash: bytes | None, canonical: str) -> bytes:
    return hashlib.sha256((prev_hash or b"") + canonical.encode()).digest()


async def append(
    conn: db.Conn,
    document_id: str,
    type_: str,
    actor: str,
    data: dict[str, Any] | None = None,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Ghi một sự kiện trong transaction của người gọi.

    Khoá dòng tài liệu trước khi đọc mắt xích cuối: hai sự kiện song song của
    cùng tài liệu xếp hàng, không bao giờ cùng nối vào một mắt xích.
    """
    await conn.execute("SELECT 1 FROM documents WHERE id = %s FOR UPDATE", (document_id,))
    cur = await conn.execute(
        "SELECT seq, hash FROM events WHERE document_id = %s ORDER BY seq DESC LIMIT 1",
        (document_id,),
    )
    last = await cur.fetchone()
    seq = last["seq"] + 1 if last else 1
    prev_hash = last["hash"] if last else None
    at = datetime.now(timezone.utc)
    canonical = canonical_json(
        {
            "document_id": document_id,
            "seq": seq,
            "type": type_,
            "actor": actor,
            "at": at.isoformat(),
            "ip": ip,
            "user_agent": user_agent,
            "data": data or {},
        }
    )
    await conn.execute(
        "INSERT INTO events (document_id, seq, type, created_at, canonical, prev_hash, hash) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (document_id, seq, type_, at, canonical, prev_hash, chain_hash(prev_hash, canonical)),
    )


def verify_chain(rows: list[dict]) -> tuple[bool, int | None]:
    """-> (nguyên vẹn, seq đầu tiên bị đứt)."""
    prev: bytes | None = None
    for expected_seq, row in enumerate(rows, start=1):
        if (
            row["seq"] != expected_seq
            or row["prev_hash"] != prev
            or bytes(row["hash"]) != chain_hash(prev, row["canonical"])
        ):
            return False, row["seq"]
        prev = bytes(row["hash"])
    return True, None


async def trail(document_id: str) -> dict:
    rows = await db.fetchall(
        "SELECT seq, canonical, prev_hash, hash FROM events WHERE document_id = %s ORDER BY seq",
        (document_id,),
    )
    for row in rows:
        row["prev_hash"] = bytes(row["prev_hash"]) if row["prev_hash"] is not None else None
        row["hash"] = bytes(row["hash"])
    valid, broken_at = verify_chain(rows)
    events = []
    for row in rows:
        record = json.loads(row["canonical"])
        record["hash"] = row["hash"].hex()
        record.pop("document_id", None)
        events.append(record)
    return {
        "events": events,
        "chain_valid": valid,
        "broken_at": broken_at,
        "head": rows[-1]["hash"].hex() if rows else None,
    }
