"""
Duplicate event detection.

Enforces check for (tenant_id, event_id) against accepted events.
DB-level UNIQUE(tenant_id, event_id) constraint in events table handles races.
"""
import aiosqlite
from backend.config import DB_PATH


async def is_duplicate(tenant_id: str, event_id: str, db_path: str = DB_PATH) -> bool:
    """
    Return True if (tenant_id, event_id) already exists in events table.
    """
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT 1 FROM events WHERE tenant_id = ? AND event_id = ? LIMIT 1",
            (tenant_id, event_id),
        ) as cursor:
            row = await cursor.fetchone()
            return row is not None
