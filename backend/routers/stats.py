"""GET /api/v1/stats — aggregate counts from real database rows."""
from fastapi import APIRouter, Query
from typing import Optional

import aiosqlite
from backend.config import DB_PATH
from backend.models import StatsResponse

router = APIRouter()


@router.get("/stats", response_model=StatsResponse)
async def get_stats(tenant_id: Optional[str] = Query(default=None)):
    tenant_filter = "AND tenant_id = ?" if tenant_id else ""
    params = [tenant_id] if tenant_id else []

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute(
            f"""
            SELECT
                COUNT(*)                                                      AS total_events,
                SUM(CASE WHEN status = 'accepted'                THEN 1 ELSE 0 END) AS accepted,
                SUM(CASE WHEN status = 'rejected'                THEN 1 ELSE 0 END) AS rejected,
                SUM(CASE WHEN rejected_reason = 'duplicate_event' THEN 1 ELSE 0 END) AS duplicate_rejections,
                SUM(CASE WHEN rejected_reason = 'hash_mismatch'   THEN 1 ELSE 0 END) AS hash_failures,
                SUM(CASE WHEN rejected_reason IN ('invalid_signature','untrusted_key') THEN 1 ELSE 0 END) AS signature_failures,
                MAX(ingested_at) AS last_event_at
            FROM events
            WHERE 1=1 {tenant_filter}
            """,
            params,
        ) as cur:
            row = await cur.fetchone()

        async with db.execute(
            f"SELECT COUNT(DISTINCT tenant_id) FROM events WHERE 1=1 {tenant_filter}",
            params,
        ) as cur:
            tenants_active = (await cur.fetchone())[0]

    return StatsResponse(
        total_events=row["total_events"] or 0,
        accepted=row["accepted"] or 0,
        rejected=row["rejected"] or 0,
        duplicate_rejections=row["duplicate_rejections"] or 0,
        hash_failures=row["hash_failures"] or 0,
        signature_failures=row["signature_failures"] or 0,
        tenants_active=tenants_active or 0,
        last_event_at=row["last_event_at"],
    )
