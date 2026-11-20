"""
Duplicate event detection.

Belt-and-suspenders approach:
1. Pre-check: SELECT query before INSERT (fast reject path, readable logs).
2. DB-level UNIQUE(event_id) constraint catches concurrent duplicates that
   race past the pre-check.

The INSERT in ingest.py uses a transaction and catches aiosqlite.IntegrityError
as the definitive duplicate signal.
"""
import aiosqlite
from backend.config import DB_PATH


async def is_duplicate(event_id: str, db_path: str = DB_PATH) -> bool:
    """
    Return True if event_id already exists in the events table.
    This is a soft pre-check; the UNIQUE constraint is the hard guarantee.
    """
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT 1 FROM events WHERE event_id = ? LIMIT 1", (event_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return row is not None
