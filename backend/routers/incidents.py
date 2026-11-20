"""
GET /api/v1/incidents — audit of rejected events from rejection_audit.
Tenant isolation rule: tenant_id is strictly required. Never returns cross-tenant data.
"""
import aiosqlite
from fastapi import APIRouter, Query

from backend.config import DB_PATH
from backend.models import IncidentRecord, IncidentsResponse

router = APIRouter()

_REASON_TO_TYPE = {
    "hash_mismatch": "hash_mismatch",
    "invalid_signature": "signature_failure",
    "untrusted_key": "untrusted_key",
    "unknown_collector": "unknown_collector",
    "duplicate_event": "duplicate",
    "tenant_mismatch": "tenant_mismatch",
}


@router.get("/incidents", response_model=IncidentsResponse)
async def get_incidents(
    tenant_id: str = Query(..., min_length=1, description="Tenant ID is required for isolation"),
    limit: int = Query(default=100, ge=1, le=500),
):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT event_id, tenant_id, timestamp, source_host,
                   event_type, rejected_reason, rejected_at
            FROM rejection_audit
            WHERE tenant_id = ?
            ORDER BY rejected_at DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        ) as cur:
            rows = await cur.fetchall()

    incidents = [
        IncidentRecord(
            event_id=r["event_id"],
            tenant_id=r["tenant_id"],
            incident_type=_REASON_TO_TYPE.get(r["rejected_reason"], "unknown"),
            timestamp=r["timestamp"] or r["rejected_at"],
            source_host=r["source_host"] or "unknown",
            detail=r["rejected_reason"],
        )
        for r in rows
    ]

    return IncidentsResponse(incidents=incidents)
