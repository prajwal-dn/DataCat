"""
GET /api/v1/stats — aggregate telemetry counts from database tables.
Tenant isolation rule: tenant_id is strictly required. Never returns cross-tenant data.
"""
import aiosqlite
from fastapi import APIRouter, Query

from backend.config import DB_PATH
from backend.models import StatsResponse

router = APIRouter()


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    tenant_id: str = Query(..., min_length=1, description="Tenant ID is required for isolation")
):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Accepted count from events
        async with db.execute(
            """
            SELECT COUNT(*) AS accepted_count, MAX(ingested_at) AS last_accepted
            FROM events
            WHERE tenant_id = ?
            """,
            (tenant_id,),
        ) as cur:
            acc_row = await cur.fetchone()
            accepted = acc_row["accepted_count"] or 0
            last_accepted = acc_row["last_accepted"]

        # Rejection metrics from rejection_audit
        async with db.execute(
            """
            SELECT
                COUNT(*) AS rejected_count,
                SUM(CASE WHEN rejected_reason = 'duplicate_event' THEN 1 ELSE 0 END) AS duplicate_rejections,
                SUM(CASE WHEN rejected_reason = 'hash_mismatch' THEN 1 ELSE 0 END) AS hash_failures,
                SUM(CASE WHEN rejected_reason IN ('invalid_signature', 'untrusted_key', 'unknown_collector', 'tenant_mismatch') THEN 1 ELSE 0 END) AS signature_failures,
                MAX(rejected_at) AS last_rejected
            FROM rejection_audit
            WHERE tenant_id = ?
            """,
            (tenant_id,),
        ) as cur:
            rej_row = await cur.fetchone()
            rejected = rej_row["rejected_count"] or 0
            duplicates = rej_row["duplicate_rejections"] or 0
            hash_fails = rej_row["hash_failures"] or 0
            sig_fails = rej_row["signature_failures"] or 0
            last_rejected = rej_row["last_rejected"]

    last_event_candidates = [ts for ts in (last_accepted, last_rejected) if ts]
    last_event_at = max(last_event_candidates) if last_event_candidates else None

    return StatsResponse(
        total_events=accepted + rejected,
        accepted=accepted,
        rejected=rejected,
        duplicate_rejections=duplicates,
        hash_failures=hash_fails,
        signature_failures=sig_fails,
        tenants_active=1 if (accepted + rejected) > 0 else 0,
        last_event_at=last_event_at,
    )
