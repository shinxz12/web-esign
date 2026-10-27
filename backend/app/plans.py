"""Gói dịch vụ, hạn mức và đếm lượt dùng theo tháng.

Hạn mức tài liệu được trừ **nguyên tử** ngay lúc tạo tài liệu: một câu
``INSERT … ON CONFLICT DO UPDATE … WHERE documents < hạn mức``. Hai request
song song ở sát hạn mức không thể cùng lọt qua.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from . import db
from .errors import ApiError

VN_TZ = timezone(timedelta(hours=7))


@dataclass(frozen=True)
class Plan:
    code: str
    name: str
    documents_per_month: int | None  # None = không giới hạn
    api_requests_per_minute: int
    max_file_mb: int
    max_recipients: int
    max_members: int | None
    max_api_keys: int
    max_webhooks: int

    def to_dict(self) -> dict:
        return asdict(self)


PLANS: dict[str, Plan] = {
    plan.code: plan
    for plan in (
        Plan("free", "Miễn phí", 20, 60, 10, 5, 3, 2, 1),
        Plan("business", "Doanh nghiệp", 1000, 600, 25, 20, 25, 10, 5),
        Plan("enterprise", "Enterprise", None, 3000, 50, 50, None, 50, 20),
    )
}


def get(code: str) -> Plan:
    return PLANS.get(code, PLANS["free"])


def current_period(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(VN_TZ).strftime("%Y-%m")


async def consume_document(conn: db.Conn, org_id: str, plan: Plan) -> None:
    period = current_period()
    if plan.documents_per_month is None:
        await conn.execute(
            "INSERT INTO usage_counters (org_id, period, documents) VALUES (%s, %s, 1) "
            "ON CONFLICT (org_id, period) DO UPDATE "
            "SET documents = usage_counters.documents + 1",
            (org_id, period),
        )
        return
    cur = await conn.execute(
        "INSERT INTO usage_counters (org_id, period, documents) VALUES (%s, %s, 1) "
        "ON CONFLICT (org_id, period) DO UPDATE "
        "SET documents = usage_counters.documents + 1 "
        "WHERE usage_counters.documents < %s "
        "RETURNING documents",
        (org_id, period, plan.documents_per_month),
    )
    if await cur.fetchone() is None:
        raise ApiError(
            402,
            "quota_exceeded",
            f"Đã dùng hết {plan.documents_per_month} tài liệu của gói "
            f"{plan.name} trong tháng {period}",
        )


async def count_signature(conn: db.Conn, org_id: str) -> None:
    await conn.execute(
        "INSERT INTO usage_counters (org_id, period, signatures) VALUES (%s, %s, 1) "
        "ON CONFLICT (org_id, period) DO UPDATE "
        "SET signatures = usage_counters.signatures + 1",
        (org_id, current_period()),
    )


async def usage(org_id: str, plan: Plan) -> dict:
    period = current_period()
    row = await db.fetchone(
        "SELECT documents, signatures FROM usage_counters WHERE org_id = %s AND period = %s",
        (org_id, period),
    )
    history = await db.fetchall(
        "SELECT period, documents, signatures FROM usage_counters "
        "WHERE org_id = %s ORDER BY period DESC LIMIT 12",
        (org_id,),
    )
    return {
        "period": period,
        "documents": row["documents"] if row else 0,
        "signatures": row["signatures"] if row else 0,
        "plan": plan.to_dict(),
        "history": history,
    }
