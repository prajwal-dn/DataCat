"""GET /api/v1/incidents — rejected events as incident records."""
from fastapi import APIRouter, Query
from typing import Optional

import aiosqlite
from backend.config import DB_PATH
from backend.models import IncidentRecord, IncidentsResponse

router = APIRouter()

# Map stored rejected_reason values to incident_type labels
_REASON_TO_TYPE = {
    "hash_mismatch": "hash_mismatch",
    "invalid_signature": "signature_failure",
    "untrusted_key": "signature_failure",
    "unknown_collector": "signature_failure",
    "duplicate_event": "duplicate",
    "tenant_mismatch": "signature_failure",
}


@router.get("/incidents", response_model=IncidentsResponse)
async def get_incidents(
    tenant_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    filters = ["status = 'rejected'"]
    params: list = []

    if tenant_id:
        filters.append("tenant_id = ?")
        params.append(tenant_id)

    where = "WHERE " + " AND ".join(filters)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"""
            SELECT event_id, tenant_id, timestamp, source_host,
                   event_type, rejected_reason, ingested_at
            FROM events {where}
            ORDER BY ingested_at DESC
            LIMIT ?
            """,
            params + [limit],
        ) as cur:
            rows = await cur.fetchall()

    incidents = [
        IncidentRecord(
            event_id=r["event_id"],
            tenant_id=r["tenant_id"],
            incident_type=_REASON_TO_TYPE.get(r["rejected_reason"], "unknown"),
            timestamp=r["timestamp"],
            source_host=r["source_host"],
            detail=r["rejected_reason"] or "unknown rejection",
        )
        for r in rows
    ]

    return IncidentsResponse(incidents=incidents)
