"""GET /api/v1/events — paginated event list from the database."""
from fastapi import APIRouter, Query
from typing import Optional

import aiosqlite
from backend.config import DB_PATH, EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT
from backend.models import EventRecord, EventsResponse

router = APIRouter()


@router.get("/events", response_model=EventsResponse)
async def get_events(
    tenant_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None, pattern="^(accepted|rejected|all)$"),
    limit: int = Query(default=EVENTS_DEFAULT_LIMIT, ge=1, le=EVENTS_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    filters = []
    params: list = []

    if tenant_id:
        filters.append("tenant_id = ?")
        params.append(tenant_id)
    if status and status != "all":
        filters.append("status = ?")
        params.append(status)

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Total count
        async with db.execute(
            f"SELECT COUNT(*) FROM events {where}", params
        ) as cur:
            total = (await cur.fetchone())[0]

        # Paginated rows
        async with db.execute(
            f"""
            SELECT event_id, tenant_id, timestamp, source_host, event_type,
                   status, hash_verified, sig_verified, rejected_reason, ingested_at
            FROM events {where}
            ORDER BY ingested_at DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ) as cur:
            rows = await cur.fetchall()

    events = [
        EventRecord(
            event_id=r["event_id"],
            tenant_id=r["tenant_id"],
            timestamp=r["timestamp"],
            source_host=r["source_host"],
            event_type=r["event_type"],
            status=r["status"],
            hash_verified=bool(r["hash_verified"]),
            signature_verified=bool(r["sig_verified"]),
            rejected_reason=r["rejected_reason"],
            ingested_at=r["ingested_at"],
        )
        for r in rows
    ]

    return EventsResponse(total=total, events=events)
