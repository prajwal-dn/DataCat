"""
GET /api/v1/events — paginated event list from the database.
Enforces tenant authentication and isolation.
"""
from typing import Optional
import aiosqlite
from fastapi import APIRouter, Query, Depends

from backend.config import DB_PATH, EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT
from backend.models import EventRecord, EventsResponse
from backend.auth import require_tenant_auth

router = APIRouter()


@router.get("/events", response_model=EventsResponse)
async def get_events(
    tenant_id: str = Depends(require_tenant_auth),
    limit: int = Query(default=EVENTS_DEFAULT_LIMIT, ge=1, le=EVENTS_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute(
            "SELECT COUNT(*) FROM events WHERE tenant_id = ?",
            (tenant_id,),
        ) as cur:
            total = (await cur.fetchone())[0]

        async with db.execute(
            """
            SELECT event_id, tenant_id, timestamp, source_host, event_type,
                   hash_verified, sig_verified, ingested_at
            FROM events
            WHERE tenant_id = ?
            ORDER BY ingested_at DESC
            LIMIT ? OFFSET ?
            """,
            (tenant_id, limit, offset),
        ) as cur:
            rows = await cur.fetchall()

    events = [
        EventRecord(
            event_id=r["event_id"],
            tenant_id=r["tenant_id"],
            timestamp=r["timestamp"],
            source_host=r["source_host"],
            event_type=r["event_type"],
            status="accepted",
            hash_verified=bool(r["hash_verified"]),
            signature_verified=bool(r["sig_verified"]),
            rejected_reason=None,
            ingested_at=r["ingested_at"],
        )
        for r in rows
    ]

    return EventsResponse(total=total, events=events)
