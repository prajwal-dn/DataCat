"""
Tests for Phase 1 database layer, schema integrity, and isolation constraints.
"""
import uuid
import aiosqlite
import pytest
from backend.config import DB_PATH
from backend.database import init_db

pytestmark = pytest.mark.asyncio


async def test_database_tables_exist():
    """Verify events, rejection_audit, and trusted_keys tables exist."""
    await init_db()
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ) as cur:
            tables = {row[0] for row in await cur.fetchall()}

    assert "events" in tables
    assert "rejection_audit" in tables
    assert "trusted_keys" in tables


async def test_events_composite_unique_constraint():
    """Verify events enforces UNIQUE(tenant_id, event_id)."""
    tenant_1 = str(uuid.uuid4())
    event_id = str(uuid.uuid4())

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO events
                (tenant_id, event_id, timestamp, source_host, event_type, payload, privacy_tags, hash_verified, sig_verified)
            VALUES (?, ?, '2026-11-20T12:00:00Z', 'host1', 'metrics', '{"val":1}', '[]', 1, 1)
            """,
            (tenant_1, event_id),
        )
        await db.commit()

        # Second insert with same tenant and event_id must fail IntegrityError
        with pytest.raises(aiosqlite.IntegrityError):
            await db.execute(
                """
                INSERT INTO events
                    (tenant_id, event_id, timestamp, source_host, event_type, payload, privacy_tags, hash_verified, sig_verified)
                VALUES (?, ?, '2026-11-20T12:01:00Z', 'host1', 'metrics', '{"val":2}', '[]', 1, 1)
                """,
                (tenant_1, event_id),
            )
            await db.commit()


async def test_events_tenant_isolation_allows_same_event_id_for_different_tenants():
    """Two different tenants can have the same event_id without collision."""
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    shared_event_id = str(uuid.uuid4())

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO events
                (tenant_id, event_id, timestamp, source_host, event_type, payload, privacy_tags, hash_verified, sig_verified)
            VALUES (?, ?, '2026-11-20T12:00:00Z', 'hostA', 'metrics', '{"v":1}', '[]', 1, 1)
            """,
            (tenant_a, shared_event_id),
        )
        await db.execute(
            """
            INSERT INTO events
                (tenant_id, event_id, timestamp, source_host, event_type, payload, privacy_tags, hash_verified, sig_verified)
            VALUES (?, ?, '2026-11-20T12:00:00Z', 'hostB', 'metrics', '{"v":2}', '[]', 1, 1)
            """,
            (tenant_b, shared_event_id),
        )
        await db.commit()

        async with db.execute(
            "SELECT COUNT(*) FROM events WHERE event_id = ?", (shared_event_id,)
        ) as cur:
            count = (await cur.fetchone())[0]
            assert count == 2


async def test_rejection_audit_schema_no_sensitive_columns():
    """Verify rejection_audit does not contain columns for raw payload, signature, or key."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("PRAGMA table_info(rejection_audit)") as cur:
            columns = {row[1] for row in await cur.fetchall()}

    assert "payload" not in columns
    assert "signature" not in columns
    assert "public_key" not in columns
    assert "rejected_reason" in columns
    assert "event_id" in columns
    assert "tenant_id" in columns
