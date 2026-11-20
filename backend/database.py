"""
Database layer — aiosqlite connection pool, schema creation, and helpers.

Schema design decisions:
- events.payload is NULL for rejected events (privacy rule: never store
  rejected sensitive payloads on SaaS).
- events.event_id has a UNIQUE constraint enforced at DB level for concurrent
  duplicate protection.
- trusted_keys table holds the pre-registered collector public keys.
  The backend NEVER trusts a key supplied in the ingest request body.
"""
import aiosqlite
import asyncio
from pathlib import Path
from backend.config import DB_PATH

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS trusted_keys (
    tenant_id       TEXT NOT NULL,
    public_key_b64  TEXT NOT NULL,
    collector_name  TEXT,
    registered_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    source_host      TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    -- payload is NULL for rejected events (privacy rule)
    payload          TEXT,
    privacy_tags     TEXT,
    status           TEXT NOT NULL CHECK(status IN ('accepted','rejected')),
    hash_verified    INTEGER NOT NULL DEFAULT 0,
    sig_verified     INTEGER NOT NULL DEFAULT 0,
    rejected_reason  TEXT,
    ingested_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE(event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_tenant   ON events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_status   ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_ingested ON events(ingested_at);
"""


async def init_db() -> None:
    """Create tables if they do not exist. Called at application startup."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_DDL)
        await db.commit()


def get_db_path() -> str:
    return DB_PATH
